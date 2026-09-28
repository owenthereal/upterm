### Digital Ocean ###
variable "do_token" {}

variable "do_region" {
  type    = string
  default = "sfo2"
}

variable "do_k8s_name" {
  type    = string
  default = "upterm-cluster"
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
  default = false
}

variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}
### Digital Ocean ###

### Charts ###
variable "wait_for_k8s_resources" {
  type    = bool
  default = true
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
### Charts ###
