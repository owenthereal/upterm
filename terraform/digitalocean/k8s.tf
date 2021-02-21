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
  type        = map(string) # { filename=content }
  description = "Host keys in the format of {\"rsa_key.pub\"=\"...\", \"rsa_key\"=\"...\"}"
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
          "service.beta.kubernetes.io/do-loadbalancer-name"     = "${var.do_k8s_name}-lb"
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
    extraArgs = {
      "kubelet-preferred-address-types" = "InternalIP"
    }
  }

  uptermd_values = {
    autoscaling = {
      minReplicas = 2
      maxReplicas = 5
    }
    hostname = var.uptermd_host
    websocket = {
      enabled                     = true
      ingress_nginx_ingress_class = "upterm-nginx"
      cert_manager_acme_email     = var.uptermd_acme_email
    }
    host_keys = {
      for k, v in var.uptermd_host_keys :
      k => v
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
  depends_on       = [digitalocean_kubernetes_cluster.upterm, local_file.kubeconfig]
  name             = "ingress-nginx"
  chart            = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  version          = "3.23.0"
  namespace        = "upterm-ingress-nginx"
  wait             = var.wait_for_k8s_resources
  create_namespace = true
  values           = [yamlencode(local.ingress_nginx_values)]
}

resource "helm_release" "cert_manager" {
  depends_on       = [digitalocean_kubernetes_cluster.upterm, local_file.kubeconfig]
  name             = "cert-manager"
  chart            = "cert-manager"
  repository       = "https://charts.jetstack.io"
  version          = "1.2.0"
  namespace        = "cert-manager"
  wait             = var.wait_for_k8s_resources
  create_namespace = true
  values           = [yamlencode(local.cert_manager_values)]
}

resource "helm_release" "metrics_server" {
  depends_on = [digitalocean_kubernetes_cluster.upterm, local_file.kubeconfig]
  name       = "metrics-server"
  chart      = "metrics-server"
  repository = "https://charts.bitnami.com/bitnami"
  version    = "5.5.1"
  namespace  = "metrics-server"
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
