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


def build_instances(args):
    random.seed(args.seed)
    instances = []
    # Decide counts per hypervisor
    hv_counts = {}
    for hv in args.hypervisors:
        hv_counts[hv] = random.randint(args.min_per_hv, args.max_per_hv)

    # allocate IPs globally
    total = sum(hv_counts.values())
    global_ips = allocate_ips(args.network, total)
    ip_iter = iter(global_ips)

    idx = 1
    for hv in args.hypervisors:
        for _ in range(hv_counts[hv]):
            # pick distro
            distro = random.choices(["20.04", "22.04", "24.04"], weights=[0.25, 0.45, 0.3])[0]
            is_vm = distro == "20.04"
            ip = next(ip_iter)
            services = []
            if not is_vm:
                services = random_services()

            name = f"ix-host-{idx:03d}"
            instances.append({
                "name": name,
                "hypervisor": hv,
                "distro": distro,
                "is_vm": is_vm,
                "ip": ip,
                "ssh_user": "root",
                "ssh_pubkey": args.ssh_pubkey,
                "services": services,
            })
            idx += 1

    # For 20.04 VMs: ensure they each get small subnet allocation ( /30 )
    # We'll allocate a tiny network per VM from the remaining address space if possible.
    # For simplicity, assign sequential /30s from a derived subnet.
    # If can't compute, skip this step.
    try:
        net = ipaddress.ip_network(args.network)
        subnets = list(net.subnets(new_prefix=30))
        vm_subnet_iter = iter(subnets)
        for inst in instances:
            if inst["is_vm"]:
                sub = next(vm_subnet_iter)
                inst["vm_subnet"] = str(sub)
    except Exception:
        pass

    return instances


def write_outputs(instances):
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

    print(f"Wrote {out_json} and Ansible inventory to {ansible_inv_dir}")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--network", default="5.0.0.0/8", help="Network CIDR to allocate from")
    p.add_argument("--hypervisors", nargs="*", default=["hv1", "hv2"], help="List of hypervisor node names")
    p.add_argument("--min-per-hv", type=int, default=8)
    p.add_argument("--max-per-hv", type=int, default=12)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--ssh-pubkey", default="ssh-rsa AAAAB3Nza... user@example", help="Public key to set for all hosts")
    return p.parse_args()


def main():
    args = parse_args()
    instances = build_instances(args)
    write_outputs(instances)


if __name__ == "__main__":
    main()
