output "kubeconfig" {
  depends_on = [digitalocean_kubernetes_cluster.upterm]
  value      = digitalocean_kubernetes_cluster.upterm.kube_config[0].raw_config
  sensitive  = true
}
