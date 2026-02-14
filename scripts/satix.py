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

def random_services(min_services=3, max_services=8, exclude_services=None, seed=None):
    """
    Selects random services from TOP20_SERVICES, excluding those in exclude_services.
    """
    exclude_services = exclude_services or []
    available_services = [s for s in TOP20_SERVICES if s not in exclude_services]
    
    if len(available_services) < min_services:
        # If not enough services available, use what we have
        return available_services
    
    n = random.randint(min_services, min(max_services, len(available_services)))
    return random.sample(available_services, n)


def allocate_ips(network_cidr, count: int, small_net_for_vms: bool = False):
    """
    Allocates IP addresses from the given network CIDR. If `small_net_for_vms` is True,
    it will attempt to find a small /30 subnet within the network and allocate from that.
    Uses efficient math-based IP selection instead of materializing all hosts.
    """

    net = ipaddress.ip_network(network_cidr)
    first_host = net.network_address + 1
    last_host = net.broadcast_address - 1
    num_hosts = net.num_addresses - 2  # exclude network and broadcast
    
    if small_net_for_vms:
        # For /30, there are only 2 usable hosts, so just return those
        if net.prefixlen >= 30:
            return [str(first_host), str(first_host + 1)]
        # Otherwise, try using first /30 subnet
        try:
            subnet = net.subnets(new_prefix=30).__next__()
            hosts = list(subnet.hosts())
            return [str(h) for h in hosts][:count]
        except StopIteration:
            pass
    
    # default: select IPs mathematically without materializing entire list
    if count > num_hosts:
        count = num_hosts
    
    ips = []
    if count <= 0:
        return ips
    
    # Use random offsets within the range instead of sampling from materialized list
    offsets = set()
    while len(offsets) < count and len(offsets) < num_hosts:
        offsets.add(random.randint(0, num_hosts - 1))
    
    return [str(first_host + offset) for offset in sorted(offsets)]


def build_instances(args, vm_subnet_prefix: int = 24, exclude_services=None):
    """
    Generates a list of instance dicts with randomized properties based on the provided arguments.
    """
    exclude_services = exclude_services or []

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

    print("\nUsing the following Hypervisor -> Network mapping:")
    for hv, net in hv_map.items():
        print(f"  {hv}: {net}     (will create {hv_counts[hv]} hosts)")


    # Allocate IPs per hypervisor network and build instances
    idx = 1
    hv_instances = {hv: [] for hv in hypervisors}

    # track globally used ips and subnets to avoid duplicates
    global_used_ips = set()
    global_used_subnets = set()
    for hv in hypervisors:
        net_cidr = hv_map[hv]
        count = hv_counts[hv]
        ips = []
        try:
            hv_net = ipaddress.ip_network(net_cidr)
            first_host = hv_net.network_address + 1
            last_host = hv_net.broadcast_address - 1
            num_hosts = hv_net.num_addresses - 2
            
            # Efficiently select random IPs without materializing entire list
            if count > num_hosts:
                count = num_hosts
            
            attempts = 0
            max_attempts = count * 10  # allow some retries for collision avoidance
            while len(ips) < count and attempts < max_attempts:
                offset = random.randint(0, num_hosts - 1)
                candidate_ip = first_host + offset
                s = str(candidate_ip)
                
                if s not in global_used_ips and not any(candidate_ip in ipaddress.ip_network(r) for r in global_used_subnets):
                    ips.append(s)
                    global_used_ips.add(s)
                attempts += 1

        except Exception as e:
            if args.verbose:
                print(f"Failed to allocate IPs for {net_cidr}: {e}")
            ips = []

        print(f"\nAllocated {len(ips)} random IPs for {hv} from range {net_cidr}.")


        # Determine how many VMs (Ubuntu 20.04) are allowed on this hypervisor
        pct = max(0, min(100, getattr(args, "subnetworks_percentage", 20)))
        max_vms = int(count * pct / 100)
        print(f"  Hypervisor {hv}: {max_vms} of {count} hosts ({pct}%) will be VMs with their own subnets.")

        # Choose which indices will be VMs
        indices = list(range(len(ips)))
        vm_indices = set()
        if max_vms > 0 and indices:
            vm_indices = set(random.sample(indices, min(max_vms, len(indices))))

        # Determine how many hosts will have multiple IPs (exclude VMs)
        multi_ip_pct = max(0, min(100, getattr(args, "multiple_ip_percentage", 40)))
        max_multi_ip = int(count * multi_ip_pct / 100)
        # Select from non-VM indices only
        non_vm_indices = [i for i in indices if i not in vm_indices]
        multi_ip_indices = set()
        if max_multi_ip > 0 and non_vm_indices:
            multi_ip_indices = set(random.sample(non_vm_indices, min(max_multi_ip, len(non_vm_indices))))
        
        if args.verbose:
            print(f"  Hypervisor {hv}: {len(multi_ip_indices)} of {count} hosts ({multi_ip_pct}%) will have multiple IPs.")


        # Keep a local pool of remaining hv hosts for resolving conflicts (if needed)
        # Use math-based approach instead of materializing all hosts
        hv_net = ipaddress.ip_network(net_cidr)
        hv_pool = []
        try:
            first_host = hv_net.network_address + 1
            num_hosts = hv_net.num_addresses - 2
            # Sample some candidate IPs from the range without materializing all
            for _ in range(min(1000, num_hosts)):
                offset = random.randint(0, num_hosts - 1)
                candidate = first_host + offset
                s = str(candidate)
                if s not in global_used_ips:
                    hv_pool.append(s)
            random.shuffle(hv_pool)
        except Exception:
            hv_pool = []

        for pos, ip in enumerate(ips):
            is_vnetmgr = pos in vm_indices
            has_multi_ip = pos in multi_ip_indices
            services = []
            primary_ip = ip
            additional_ips = []
            
            # Allocate additional IPs if this host has multiple IPs
            if has_multi_ip:
                num_additional = random.randint(1, 4)  # 2-5 total IPs (1 primary + 1-4 additional)
                
                if args.multiple_ip_random:
                    # Random unique /32 addresses from hv_pool
                    for _ in range(num_additional):
                        if hv_pool:
                            additional_ip = hv_pool.pop()
                            additional_ips.append(additional_ip)
                            global_used_ips.add(additional_ip)
                        else:
                            break
                else:
                    # Sequential IPs incremented from the primary IP
                    try:
                        current_ip = ipaddress.ip_address(ip)
                        for offset in range(1, num_additional + 1):
                            next_ip = current_ip + offset
                            next_ip_str = str(next_ip)
                            if next_ip_str not in global_used_ips:
                                additional_ips.append(next_ip_str)
                                global_used_ips.add(next_ip_str)
                            else:
                                # Try to find a free sequential IP from the pool
                                if hv_pool:
                                    additional_ips.append(hv_pool.pop())
                    except Exception:
                        pass
            
            if is_vnetmgr:
                # Compute subnet derived from this ip
                try:
                    net = ipaddress.ip_network(f"{ip}/{vm_subnet_prefix}", strict=False)
                    net_s = str(net)
                except Exception:
                    net = None
                    net_s = None

                # If this subnet already used, try to find another ip from hv_pool that yields a free subnet
                if net_s and net_s in global_used_subnets:
                    found = False
                    while hv_pool and not found:
                        cand = hv_pool.pop()
                        try:
                            cand_net = ipaddress.ip_network(f"{cand}/{vm_subnet_prefix}", strict=False)
                            if str(cand_net) not in global_used_subnets and cand not in global_used_ips:
                                # use cand
                                ip = cand
                                net = cand_net
                                net_s = str(cand_net)
                                global_used_ips.add(ip)
                                found = True
                                break
                        except Exception:
                            continue

                    if not found:
                        # fallback: try to pick a free subnet mathematically
                        # instead of enumerating all subnets (which is slow for large networks)
                        try:
                            first_host = hv_net.network_address + 1
                            num_hosts = hv_net.num_addresses - 2
                            # compute how many /24 subnets fit in the network
                            subnet_size = 2 ** (32 - vm_subnet_prefix)
                            max_subnets = num_hosts // subnet_size
                            
                            # try random subnets until we find a free one
                            for _ in range(min(100, max_subnets)):
                                subnet_idx = random.randint(0, max_subnets - 1)
                                candidate_net = ipaddress.ip_network(
                                    (hv_net.network_address + subnet_idx * subnet_size, vm_subnet_prefix),
                                    strict=False
                                )
                                if str(candidate_net) not in global_used_subnets:
                                    net = candidate_net
                                    net_s = str(candidate_net)
                                    break
                        except Exception:
                            pass

                # finally assign and record
                if net_s:
                    global_used_subnets.add(net_s)
                    global_used_ips.add(ip)
                distro = "20.04"
            else:
                # pick between 22.04 and 24.04 (preserve relative weights)
                distro = random.choices(["22.04", "24.04"], weights=[0.45, 0.3])[0]
                services = random_services(exclude_services=exclude_services)

            name = f"ix-host-{idx:03d}"
            # Merge primary IP and additional IPs into a single list
            all_ips = [ip] + additional_ips
            inst = {
                "name": name,
                "hypervisor": hv,
                "distro": distro,
                "is_vm": is_vnetmgr,
                "ip": all_ips,
                "ssh_user": "root",
                "ssh_pubkey": args.ssh_pubkey,
                "services": services,
            }
            instances.append(inst)
            hv_instances[hv].append(inst)
            idx += 1


    # For 20.04 VMs: compute and store the subnet network address as `vm_subnet`.
    # The VM's IP is kept as randomly selected within that subnet range.
    print("\nComputing VM subnets for Ubuntu 20.04 hosts:")

    try:
        for inst in instances:
            if inst.get("is_vm"):
                try:
                    primary_ip = inst['ip'][0]  # Use first IP from the list
                    net = ipaddress.ip_network(f"{primary_ip}/{vm_subnet_prefix}", strict=False)
                    inst["vm_subnet"] = str(net)
                    print(f"  VM {inst['name']}: computed subnet {inst['vm_subnet']}, IP {primary_ip}")

                except Exception as e:
                    if args.verbose:
                        print(f"  Failed to compute vm subnet for {inst['name']} ({inst.get('ip')}): {e}")

    except Exception:
        pass

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
    ansible_inv_file = ansible_inv_dir / "hosts.yml"
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
        primary_ip = inst["ip"][0]  # Use first IP from the list for Ansible host
        hosts_yml["all"]["hosts"][inst["name"]] = {"ansible_host": primary_ip, "ansible_user": inst["ssh_user"]}
        # write host_vars
        hv = host_vars_dir / f"{inst['name']}.yml"
        with open(hv, "w") as f:
            json.dump({"services": inst.get("services", []), "distro": inst["distro"], "vm_subnet": inst.get("vm_subnet")}, f, indent=2)

    # groups
    for gname, members in groups.items():
        hosts_yml["all"]["children"][gname] = {"hosts": {m["name"]: {} for m in members}}

    # write hosts.yml
    import yaml

    with open(ansible_inv_file, "w") as f:
        yaml.safe_dump(hosts_yml, f)

    print(f"\n\nGeneration finished. Wrote the:")
    print(f"  - Overall network to '{out_json}'.")
    print(f"  - Ansible inventory to '{ansible_inv_file}'.")
    print(f"  - Host variables to '{host_vars_dir}/' (one file per host).\n")


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


def list_services():
    """
    Lists all available services from TOP20_SERVICES.
    """
    print("\nAvailable Services (Top 20):")
    print("-" * 40)
    for i, service in enumerate(TOP20_SERVICES, 1):
        print(f"{i:2d}. {service}")
    print()


def parse_args():
    """
    Parses command-line arguments for the script using subparsers.
    """
    main_parser = argparse.ArgumentParser(
        description="Generate instances or list available services."
    )
    
    subparsers = main_parser.add_subparsers(dest="command", help="Commands")
    
    # 'generate' subcommand
    generate_parser = subparsers.add_parser("generate", help="Generate instances configuration")
    generate_parser.add_argument("--hypervisors", nargs="*", default=None, help="List of hypervisor node names. If provided, must match number of networks.")
    generate_parser.add_argument("--network", nargs="*", default=["5.0.0.0/8"], required=True, help="Network CIDR(s) to allocate from. Provide one per hypervisor.")
    generate_parser.add_argument("--min-per-hv", type=int, default=8)
    generate_parser.add_argument("--max-per-hv", type=int, default=12)
    generate_parser.add_argument("--vm-subnet-prefix", type=int, default=24, help="Prefix length for VM subnet allocations (e.g. 24 for /24).")
    generate_parser.add_argument("--subnetworks-percentage", type=int, default=20, help="Percent of hosts per hypervisor that may be Ubuntu 20.04 VMs (0-100).")
    generate_parser.add_argument("--multiple-ip-percentage", type=int, default=40, help="Percent of hosts per hypervisor that has multiple IPs assigned to them.")
    generate_parser.add_argument("--multiple-ip-random", action="store_true", help="If the IPs of hosts with multiple IPs should be random. By default they are incremented.")
    generate_parser.add_argument("--exclude-service", nargs="*", default=[], help="Services to exclude from the available services list.")
    generate_parser.add_argument("--seed", type=int, default=None)
    generate_parser.add_argument("--ssh-pubkey", default="ssh-rsa AAAAB3Nza... user@example", help="Public key to set for all hosts")
    generate_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging")
    
    # 'list' subcommand
    list_parser = subparsers.add_parser("list", help="List available resources")
    list_subparsers = list_parser.add_subparsers(dest="list_type", help="What to list")
    list_subparsers.add_parser("services", help="List available services")
    
    args = main_parser.parse_args()
    
    # If no command specified, show help
    if not args.command:
        main_parser.print_help()
        sys.exit(0)
    
    return args


def main():
    """
    Main entry point for the script. Parses arguments and executes the appropriate command.
    """
    print("\n  ================================================")
    print("=== SATIX Customer Simulation Instance Generator ===")
    print("  ================================================\n")
    args = parse_args()
    
    if args.command == "list":
        if args.list_type == "services":
            list_services()
        else:
            print("Please specify what to list: services")
            sys.exit(1)
    
    elif args.command == "generate":
        # Validate networks and hypervisors
        args.network = validate_networks(args.network)
        args.hypervisors = validate_hypervisors(args.hypervisors, args.network)
        
        instances = build_instances(
            args, 
            vm_subnet_prefix=args.vm_subnet_prefix,
            exclude_services=args.exclude_service
        )
        write_outputs(instances)


if __name__ == "__main__":
    main()
