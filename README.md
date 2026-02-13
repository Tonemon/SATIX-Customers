# SAT-IX-Customers Simulation

> Suit-and-Tie (SAT) Internet eXchange (IX) customers simulation.


## About
This repository scaffolds a university-level simulation of an Internet Exchange using two hypervisors running Proxmox. It provides:

- A Python generator that randomly decides how many Proxmox instances to create, assigns Ubuntu versions (20.04, 22.04, 24.04), selects services to run on 22.04/24.04 containers, and prepares vnet-manager VMs for 20.04 hosts.
- Terraform templates that read the generated `instances.json` and (optionally) create Proxmox LXC containers or QEMU VMs using the Proxmox provider.
- Ansible playbooks and roles to configure instances: install services on 22.04/24.04 and install/configure `vnet-manager` on 20.04 VMs.


## Usage


1. You can use `scripts/generate_instances.py` to produce `instances.json`, `ansible/inventory/hosts.yml`, and `ansible/host_vars/*.yml`:
```bash
python3 scripts/generate_instances.py -h
python3 scripts/generate_instances.py --network 5.0.0.0/8 --hypervisors hv1
```

2. Then inspect `terraform/instances.json` (copied from root `instances.json`) and customize `terraform/terraform.tfvars` (Proxmox credentials and storage/node mapping).
3. Run `terraform init` and `terraform apply` in `terraform/` to create containers/VMs (requires Proxmox provider and credentials).
4. Run `ansible-playbook -i ansible/inventory/hosts.yml ansible/site.yml` to configure services.

Notes
- The Terraform Proxmox provider configuration is left as placeholders: fill in endpoint, user, and password or token.
- The Python generator implements the randomization and prepares Ansible inventory and `host_vars` so Ansible can perform deterministic configuration.


## Sources

- This project uses https://github.com/Erik-Lamers1/vnet-manager to create various smaller networks on Ubuntu 20.04 hosts.
