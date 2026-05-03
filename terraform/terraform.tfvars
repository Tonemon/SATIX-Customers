proxmox_api_url = "https://proxmox.example:8006/api2/json"
proxmox_user = "root@pam"
proxmox_password = "REPLACE_ME"

# adjust as appropriate
lxc_template = "local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.gz"
vm_iso_path = "/var/lib/vz/template/iso/ubuntu-20.04.iso"
vm_bridge = "vmbr0"
gateway = "5.0.0.1"
