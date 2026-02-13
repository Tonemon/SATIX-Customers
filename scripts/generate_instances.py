#!/usr/bin/env python3
"""
generate_instances.py

Generates a randomized `instances.json` describing hosts to create on Proxmox,
allocates IPs from a given CIDR, picks services for Ubuntu 22.04/24.04 containers,
and produces Ansible inventory files under `ansible/inventory/` and
`ansible/host_vars/` for each host.

Usage: python3 scripts/generate_instances.py --network 5.0.0.0/8
"""
import argparse
import ipaddress
import json
import os
import random
from pathlib import Path
import sys

TOP20_SERVICES = [
    "nginx",
    "apache2",
    "mysql-server",
    "postgresql",
    "redis-server",
    "docker.io",
    "memcached",
    "rabbitmq-server",
    "openjdk-17-jre-headless",
    "prometheus",
    "grafana",
    "elasticsearch",
    "kibana",
    "haproxy",
    "bind9",
    "vsftpd",
    "samba",
    "openvpn",
    "fail2ban",
    "chrony",
]

def random_services(min_services=3, max_services=8, seed=None):
    n = random.randint(min_services, max_services)
    return random.sample(TOP20_SERVICES, n)


def allocate_ips(network_cidr, count: int, small_net_for_vms: bool = False):
    """
    Allocates IP addresses from the given network CIDR. If `small_net_for_vms` is True,
    it will attempt to find a small /30 subnet within the network and allocate from that.
    """

    net = ipaddress.ip_network(network_cidr)
    hosts = list(net.hosts())
    if small_net_for_vms:
        # choose a small /30 subnetwork chunk for VMs
        # find a /30 within network
        for prefix in range(30, net.max_prefixlen + 1):
            try:
                subnets = list(net.subnets(new_prefix=30))
                if subnets:
                    chosen = subnets[0]
                    return [str(ip) for ip in chosen.hosts()][:count]
            except Exception:
                break
    # default: random unique hosts
    return [str(h) for h in random.sample(hosts, count)]


def build_instances(args, vm_subnet_prefix: int = 24):
    """
    Generates a list of instance dicts with randomized properties based on the provided arguments.
    """

    random.seed(args.seed)
    instances = []

    # Derive hypervisors from provided networks: one hypervisor per network
    hv_networks = list(args.network)
    # If hypervisors were provided, they should already match networks length
    if getattr(args, "hypervisors", None):
        hypervisors = list(args.hypervisors)
    else:
        hypervisors = [f"hv{i+1}" for i in range(len(hv_networks))]
    hv_map = {hv: hv_networks[i] for i, hv in enumerate(hypervisors)}

    # Decide counts per hypervisor
    hv_counts = {hv: random.randint(args.min_per_hv, args.max_per_hv) for hv in hypervisors}

    if args.verbose:
        print("\n Using the following Hypervisor -> Network mapping:")
        for hv, net in hv_map.items():
            print(f"    {hv}: {net}     (will create {hv_counts[hv]} hosts)")


    # Allocate IPs per hypervisor network and build instances
    idx = 1
    hv_instances = {hv: [] for hv in hypervisors}
    for hv in hypervisors:
        net_cidr = hv_map[hv]
        count = hv_counts[hv]
        try:
            ips = allocate_ips(net_cidr, count)
        except Exception as e:
            if args.verbose:
                print(f"Failed to allocate IPs for {net_cidr}: {e}")
            ips = []

        if args.verbose:
            print(f"\nAllocated {len(ips)} IPs for {hv} from range {net_cidr}.")
        # Determine how many VMs (Ubuntu 20.04) are allowed on this hypervisor
        pct = max(0, min(100, getattr(args, "subnetworks_percentage", 20)))
        max_vms = int(count * pct / 100)
        if args.verbose:
            print(f"  Hypervisor {hv}: allowed maximum VMs (20.04) = {max_vms} of {count} hosts ({pct}%)")

        # Choose which indices will be VMs
        indices = list(range(len(ips)))
        vm_indices = set()
        if max_vms > 0 and indices:
            vm_indices = set(random.sample(indices, min(max_vms, len(indices))))

        for pos, ip in enumerate(ips):
            is_vm = pos in vm_indices
            if is_vm:
                distro = "20.04"
                services = []
            else:
                # pick between 22.04 and 24.04 (preserve relative weights)
                distro = random.choices(["22.04", "24.04"], weights=[0.45, 0.3])[0]
                services = random_services()

            name = f"ix-host-{idx:03d}"
            inst = {
                "name": name,
                "hypervisor": hv,
                "distro": distro,
                "is_vm": is_vm,
                "ip": ip,
                "ssh_user": "root",
                "ssh_pubkey": args.ssh_pubkey,
                "services": services,
            }
            instances.append(inst)
            hv_instances[hv].append(inst)
            idx += 1

    if args.verbose:
        print("\n")

    # For 20.04 VMs: ensure they each get a subnet allocation (e.g. /24)
    # We'll allocate sequential subnets from the provided network using the
    # `vm_subnet_prefix` parameter. If there are fewer subnets than VMs,
    # cycle through the available subnets.
    # Assign VM subnets per hypervisor: split each hypervisor network into
    # subnets of size `vm_subnet_prefix` and assign one per VM (cycle if needed).
    try:
        for hv, net_cidr in hv_map.items():
            try:
                net = ipaddress.ip_network(net_cidr)
                subnets = list(net.subnets(new_prefix=vm_subnet_prefix))
            except Exception as e:
                if args.verbose:
                    print(f"Failed to compute subnets for {net_cidr}: {e}")
                subnets = []

            vm_list = [i for i in hv_instances.get(hv, []) if i.get("is_vm")]
            if not subnets:
                if args.verbose and vm_list:
                    print(f"No subnets available for hypervisor {hv} ({net_cidr}), skipping vm_subnet assignment")
                continue
            nsub = len(subnets)
            for i, inst in enumerate(vm_list):
                inst["vm_subnet"] = str(subnets[i % nsub])
            if args.verbose:
                print(f"Assigned {len(vm_list)} VM subnets for {hv} using /{vm_subnet_prefix} subnets (available IPs for that subnet: {nsub})")
    except Exception:
        pass

    if args.verbose:
        print("\n")

    return instances


def write_outputs(instances):
    """
    Writes the generated instances to `instances.json` and prepares Ansible inventory files.
    """

    root = Path(__file__).resolve().parents[1]
    out_json = root / "instances.json"
    with open(out_json, "w") as f:
        json.dump(instances, f, indent=2)

    # prepare Ansible inventory and host_vars
    ansible_inv_dir = root / "ansible" / "inventory"
    host_vars_dir = root / "ansible" / "host_vars"
    ansible_inv_dir.mkdir(parents=True, exist_ok=True)
    host_vars_dir.mkdir(parents=True, exist_ok=True)

    groups = {"vms_20": [], "containers": []}
    for inst in instances:
        if inst["is_vm"]:
            groups["vms_20"].append(inst)
        else:
            groups["containers"].append(inst)

    hosts_yml = {"all": {"hosts": {}, "children": {}}}
    # fill hosts
    for inst in instances:
        hosts_yml["all"]["hosts"][inst["name"]] = {"ansible_host": inst["ip"], "ansible_user": inst["ssh_user"]}
        # write host_vars
        hv = host_vars_dir / f"{inst['name']}.yml"
        with open(hv, "w") as f:
            json.dump({"services": inst.get("services", []), "distro": inst["distro"], "vm_subnet": inst.get("vm_subnet")}, f, indent=2)

    # groups
    for gname, members in groups.items():
        hosts_yml["all"]["children"][gname] = {"hosts": {m["name"]: {} for m in members}}

    # write hosts.yml
    import yaml

    with open(ansible_inv_dir / "hosts.yml", "w") as f:
        yaml.safe_dump(hosts_yml, f)

    print(f"Wrote '{out_json}' and Ansible inventory to '{ansible_inv_dir}'.\n")


def validate_networks(networks):
    """
    Validates that each entry in `networks` is a valid CIDR and returns a list of normalized CIDR strings.
    """

    validated = []
    for n in networks:
        try:
            net = ipaddress.ip_network(n)
            validated.append(str(net))
        except Exception as e:
            print(f"Invalid network provided: {n} -> {e}")
            sys.exit(1)

    return validated


def validate_hypervisors(hypervisors, networks):
    """
    Validates that the number of hypervisors matches the number of networks and returns a list of hypervisor names.
    If `hypervisors` is None, it will auto-generate names based on the number of networks.
    """

    if hypervisors:
        if len(hypervisors) != len(networks):
            print("Error: number of --hypervisors entries must match number of --network entries. Exiting...")
            sys.exit(1)
        return list(hypervisors)
    else:
        # auto-generate hypervisor names
        return [f"hv{i+1}" for i in range(len(networks))]


def parse_args():
    """
    Parses command-line arguments for the script.
    """

    p = argparse.ArgumentParser()
    p.add_argument("--hypervisors", nargs="*", default=None, help="List of hypervisor node names. If provided, must match number of networks.")
    p.add_argument("--network", nargs="*", default=["5.0.0.0/8"], required=True, help="Network CIDR(s) to allocate from. Provide one per hypervisor.")
    p.add_argument("--min-per-hv", type=int, default=8)
    p.add_argument("--max-per-hv", type=int, default=12)
    p.add_argument("--vm-subnet-prefix", type=int, default=24, help="Prefix length for VM subnet allocations (e.g. 24 for /24)")
    p.add_argument("--subnetworks-percentage", type=int, default=20, help="Percent of hosts per hypervisor that may be Ubuntu 20.04 VMs (0-100)")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--ssh-pubkey", default="ssh-rsa AAAAB3Nza... user@example", help="Public key to set for all hosts")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging")
    return p.parse_args()


def main():
    args = parse_args()

    # Validate networks and hypervisors
    args.network = validate_networks(args.network)
    args.hypervisors = validate_hypervisors(args.hypervisors, args.network)

    instances = build_instances(args, vm_subnet_prefix=args.vm_subnet_prefix)
    write_outputs(instances)


if __name__ == "__main__":
    main()
