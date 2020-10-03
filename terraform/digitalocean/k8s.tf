variable "wait_for_k8s_resources" {
  type    = bool
  default = false
}

variable "uptermd_host" {
  type = string
}

variable "uptermd_acme_email" {
  type = string
}

variable "uptermd_host_keys" {
  type = list(string)
}

variable "uptermd_helm_repo" {
  type        = string
  default     = "https://upterm.dev"
  description = "Configurable for testing purpose"
}

locals {
  ingress_nginx_values = {
    controller = {
      ingressClass = "upterm-nginx"
      service = {
        annotations = {
          "service.beta.kubernetes.io/do-loadbalancer-name"     = "uptermd-lb"
          "service.beta.kubernetes.io/do-loadbalancer-protocol" = "tcp"
        }
      }
    }

    tcp = {
      22 = "uptermd/uptermd:22"
    }
  }

  cert_manager_values = {
    installCRDs = true
  }

  metrics_server_values = {
    args = ["--kubelet-preferred-address-types=InternalIP"]
  }

  uptermd_values = {
    autoscaling = {
      minReplicas = 2
      maxReplicas = 5
    }
    websocket = {
      enabled                     = true
      ingress_nginx_ingress_class = "upterm-nginx"
      host                        = var.uptermd_host
      cert_manager_acme_email     = var.uptermd_acme_email
    }
    host_keys = {
      for f in var.uptermd_host_keys :
      basename(f) => base64encode(file(f))
    }
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
  values           = [yamlencode(local.ingress_nginx_values)]
}

resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  chart            = "cert-manager"
  repository       = "https://charts.jetstack.io"
  version          = "1.0.2"
  namespace        = "cert-manager"
  wait             = var.wait_for_k8s_resources
  create_namespace = true
  values           = [yamlencode(local.cert_manager_values)]
}

resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  chart      = "metrics-server"
  repository = "https://kubernetes-charts.storage.googleapis.com"
  version    = "2.11.2"
  namespace  = "kube-system"
  wait       = var.wait_for_k8s_resources
  values     = [yamlencode(local.metrics_server_values)]
}

resource "helm_release" "uptermd" {
  depends_on       = [helm_release.ingress_nginx, helm_release.cert_manager, helm_release.metrics_server]
  name             = "uptermd"
  chart            = "uptermd"
  repository       = var.uptermd_helm_repo
  namespace        = "uptermd"
  create_namespace = true
  wait             = var.wait_for_k8s_resources
  values           = [yamlencode(local.uptermd_values)]
}
