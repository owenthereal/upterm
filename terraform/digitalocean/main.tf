variable "wait_for_k8s_resources" {
  default = false
}

variable "uptermd_host" {
}

variable "uptermd_acme_email" {
}

data "digitalocean_kubernetes_versions" "k8s_version" {}

resource "digitalocean_vpc" "upterm" {
  name        = "upterm-vpc"
  region      = "sfo2"
  description = "Upterm VPC"
}

resource "digitalocean_kubernetes_cluster" "upterm" {
  name         = "upterm"
  region       = "sfo2"
  auto_upgrade = true
  version      = data.digitalocean_kubernetes_versions.k8s_version.latest_version
  vpc_uuid     = digitalocean_vpc.upterm.id

  node_pool {
    name       = "autoscale-worker-pool"
    size       = "s-2vcpu-4gb"
    auto_scale = true
    min_nodes  = 1
    max_nodes  = 3
    tags       = [ "upterm", "production" ]
    labels     = { "app" = "upterm" }
  }
}

provider "helm" {
  kubernetes {
    host                   = digitalocean_kubernetes_cluster.upterm.endpoint
    token                  = digitalocean_kubernetes_cluster.upterm.kube_config[0].token
    cluster_ca_certificate = base64decode(digitalocean_kubernetes_cluster.upterm.kube_config[0].cluster_ca_certificate)
  }
}

resource "helm_release" "ingress_nginx" {
  name             = "ingress-nginx"
  chart            = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  version          = "3.4.0"
  namespace        = "upterm-ingress-nginx"
  wait             = var.wait_for_k8s_resources
  create_namespace = true
  values           = [ file("values/ingress_nginx_values.yml") ]
}

resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  chart            = "cert-manager"
  repository       = "https://charts.jetstack.io"
  version          = "1.0.2"
  namespace        = "cert-manager"
  wait             = var.wait_for_k8s_resources
  create_namespace = true
  values           = [ file("values/cert_manager_values.yml") ]
}

resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  chart      = "metrics-server"
  repository = "https://kubernetes-charts.storage.googleapis.com"
  version    = "2.11.2"
  namespace  = "kube-system"
  wait       = var.wait_for_k8s_resources
  values     = [ file("values/metrics_server_values.yml") ]
}

resource "helm_release" "uptermd" {
  name             = "uptermd"
  chart            = "uptermd"
  repository       = "https://upterm.dev"
  namespace        = "uptermd"
  create_namespace = true
  wait             = var.wait_for_k8s_resources
  values           = [ file("values/uptermd_values.yml") ]

  set_string {
    name = "websocket.host"
    value = var.uptermd_host
  }

  set_string {
    name = "websocket.cert_manager_acme_email"
    value = var.uptermd_acme_email
  }
}
