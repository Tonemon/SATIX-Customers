# SAT-IX-Customers Simulation

> Suit-and-Tie (SAT) Internet eXchange (IX) customers simulation.


## About
This repository scaffolds a university-level simulation of an Internet Exchange using two hypervisors running Proxmox. It provides:

- A Python generator that randomly decides how many Proxmox instances to create, assigns Ubuntu versions (20.04, 22.04, 24.04), selects services to run on 22.04/24.04 containers, and prepares vnet-manager VMs for 20.04 hosts.
- Terraform templates that read the generated `instances.json` and (optionally) create Proxmox LXC containers or QEMU VMs using the Proxmox provider.
- Ansible playbooks and roles to configure instances: install services on 22.04/24.04 and install/configure `vnet-manager` on 20.04 VMs.


## Usage

```bash
python3 scripts/generate_instances.py --network 5.0.0.0/8 --hypervisors hv1 --min-per-hv 8 --max-per-hv 10
```


## Sources

- This project uses https://github.com/Erik-Lamers1/vnet-manager to create various smaller networks on Ubuntu 20.04 hosts.
