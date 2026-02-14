# SATIX Customers Simulation

> Suit-and-Tie (SAT) Internet eXchange (IX) customers simulation.


## About
This repository scaffolds a university-level simulation of an Internet Exchange using a variable amount of hypervisors running Proxmox. It provides:
- A Python based network generation script that randomly decides how many Proxmox Container / VM instances will be in the whole network.
    - It assigns Ubuntu versions (20.04, 22.04, 24.04), selects services to run on 22.04/24.04 containers, and prepares vnet-manager for 20.04 VMs.
- Terraform templates that read the generated `instances.json` and (optionally) create Proxmox LXC containers or QEMU VMs using the Proxmox provider.
- Ansible playbooks and roles to configure instances: install services on 22.04/24.04 and install/configure `vnet-manager` on 20.04 VMs.


## Features

This project (will) contain the following features:
- [x] Generating the Proxmox Container / VM network layout configuration using one command.
- [ ] Deployment of these Containers and VMs directly to the hypervisors via Terraform.
- [ ] Configuring various services on these Containers and VMs using Ansible.
- [ ] 2 main hosts simulating tech giants: one catchall web server and one root DNS server.
- [ ] One script to start generating traffic from all hosts.


## Requirements

These are the (minimal) requirements for this project:
- One (or more) Proxmox Hypervisors. All hypervisors should have the following OS images ready:
    - Cloudinit ready VM template of Ubuntu Server 20.04.
    - Ubuntu Server 22.04 LXC container image.
    - Ubuntu Server 24.04 LXC container image.

- A big IP address range assigned to each of the Proxmox Hypervisors.


## Usage
You first use the `scripts/generate_instances.py` to produce `instances.json`, `ansible/inventory/hosts.yml`, and `ansible/host_vars/*.yml`:

```bash
python3 scripts/generate_instances.py -h
python3 scripts/generate_instances.py generate -h
```


### Single hypervisor

Custom ranges
```bash
python3 scripts/generate_instances.py generate --hypervisors hv1.lan --network 5.0.0.0/8 -v
```

Using a private `10.0.0.0/8` range on one hypervisor:
```bash
python3 scripts/generate_instances.py generate --hypervisors hv1.lan --network 10.0.0.0/8 -v
```

### Multiple hypervisors

Custom ranges
```bash
python3 scripts/generate_instances.py generate --hypervisors hv1.lan hv2.lan --network 5.0.0.0/8 6.0.0.0/8 -v
```

Using one private `10.0.0.0/8` range on multiple hypervisors:
```bash
python3 scripts/generate_instances.py generate --hypervisors hv1.lan hv2.lan --network 10.1.0.0/16 10.2.0.0/16 -v
```

2. Then inspect `terraform/instances.json` (copied from root `instances.json`) and customize `terraform/terraform.tfvars` (Proxmox credentials and storage/node mapping).
3. Run `terraform init` and `terraform apply` in `terraform/` to create containers/VMs (requires Proxmox provider and credentials).
4. Run `ansible-playbook -i ansible/inventory/hosts.yml ansible/site.yml` to configure services.

Notes
- The Terraform Proxmox provider configuration is left as placeholders: fill in endpoint, user, and password or token.
- The Python generator implements the randomization and prepares Ansible inventory and `host_vars` so Ansible can perform deterministic configuration.


## Sources

- This project uses https://github.com/Erik-Lamers1/vnet-manager to create various smaller networks on Ubuntu 20.04 hosts. The motivation behind using this (slightly outdated) project was that various networks had to be created during lab assignments and it would help to simulate smaller ISPs using protocols and technologies such as BGP, RIPNG, STP, VLANs, bridging and more.

