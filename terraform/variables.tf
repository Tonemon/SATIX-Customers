variable "proxmox_api_url" { type = string }
variable "proxmox_user" { type = string }
variable "proxmox_password" { type = string }

variable "lxc_template" { type = string, default = "local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.gz" }
variable "vm_iso_path" { type = string, default = "/var/lib/vz/template/iso/ubuntu-20.04.iso" }
variable "vm_bridge" { type = string, default = "vmbr0" }
variable "gateway" { type = string, default = "5.0.0.1" }
