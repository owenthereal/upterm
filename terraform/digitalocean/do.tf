data "digitalocean_kubernetes_versions" "k8s_version" {}

resource "digitalocean_kubernetes_cluster" "upterm" {
  name         = var.do_k8s_name
  region       = var.do_region
  auto_upgrade = false
  version      = data.digitalocean_kubernetes_versions.k8s_version.latest_version

  node_pool {
    name       = "autoscale-worker-pool"
    size       = var.do_node_size
    auto_scale = true
    min_nodes  = var.do_min_nodes
    max_nodes  = var.do_max_nodes
    tags       = [var.do_k8s_name]
    labels     = { "app" = var.do_k8s_name }
  }
}

resource "local_file" "kubeconfig" {
  count                = var.write_kubeconfig ? 1 : 0
  content              = digitalocean_kubernetes_cluster.upterm.kube_config[0].raw_config
  filename             = var.kubeconfig_path
  file_permission      = "0644"
  directory_permission = "0755"
}
