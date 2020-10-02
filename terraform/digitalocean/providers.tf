variable "do_token" {}

provider "digitalocean" {
  token = var.do_token
}
