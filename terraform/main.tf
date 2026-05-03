terraform {
  required_providers {
    proxmox = {
      source  = "Telmate/proxmox"
      version = "~> 2.9"
    }
  }
}

provider "proxmox" {
  # Fill these values in terraform/terraform.tfvars
  pm_api_url = var.proxmox_api_url
  pm_user    = var.proxmox_user
  pm_password = var.proxmox_password
  # or use pm_tls_insecure, pm_token_id, pm_token_secret per provider docs
}

locals {
  instances = jsondecode(file("${path.module}/../instances.json"))
  lxc_instances = { for inst in local.instances : inst.name => inst if inst.is_vm == false }
  vm_instances  = { for inst in local.instances : inst.name => inst if inst.is_vm == true }
}

resource "proxmox_lxc" "containers" {
  for_each = local.lxc_instances

  # Mapping values (these depend on your Proxmox templates/storage names)
  hostname = each.key
  ostemplate = var.lxc_template
  cores = 1
  memory = 512
  rootfs = "local-zfs:1"
  net {
    name = "eth0"
    ip   = "${each.value.ip}/24"
    gw   = var.gateway
  }
  # adjust node mapping: use each.value.hypervisor
  node = each.value.hypervisor
}

resource "proxmox_vm_qemu" "vms20" {
  for_each = local.vm_instances

  name = each.key
  target_node = each.value.hypervisor
  cores = 2
  memory = 1024
  scsihw = "virtio-scsi-pci"
  boot = "cdn"
  iso = var.vm_iso_path

  network {
    model = "virtio"
    bridge = var.vm_bridge
    tag = 0
    firewall = false
  }
  # cloud-init or other provisioning may be required
}

output "instances" {
  value = local.instances
}
