variable "do_token" {}

variable "do_region" {
  type    = string
  default = "sfo2"
}

variable "do_min_nodes" {
  type    = number
  default = 1
}

variable "do_max_nodes" {
  type    = number
  default = 3
}

variable "do_node_size" {
  type    = string
  default = "s-2vcpu-4gb"
}

variable "write_kubeconfig" {
  type    = bool
  default = true
}

provider "digitalocean" {
  token = var.do_token
}

data "digitalocean_kubernetes_versions" "k8s_version" {}

resource "digitalocean_kubernetes_cluster" "upterm" {
  name         = "upterm"
  region       = var.do_region
  auto_upgrade = true
  version      = data.digitalocean_kubernetes_versions.k8s_version.latest_version

  node_pool {
    name       = "autoscale-worker-pool"
    size       = var.do_node_size
    auto_scale = true
    min_nodes  = var.do_min_nodes
    max_nodes  = var.do_max_nodes
    tags       = ["upterm"]
    labels     = { "app" = "upterm" }
  }
}

resource "local_file" "kubeconfig" {
  count                = var.write_kubeconfig ? 1 : 0
  content              = digitalocean_kubernetes_cluster.upterm.kube_config[0].raw_config
  filename             = "./kubeconfig_upterm"
  file_permission      = "0644"
  directory_permission = "0755"
}

output "kubeconfig" {
  depends_on = [digitalocean_kubernetes_cluster.upterm]
  value      = digitalocean_kubernetes_cluster.upterm.kube_config[0].raw_config
}
