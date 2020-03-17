variable "app_name" {
  description = "Name of the Heroku app"
}

variable "github_release" {
  description = "GitHub release tag"
  default = "master"
}

variable "region" {
  description = "Heroku region"
  default = ""
}

variable "space" {
  description = "Name of the Heroku space"
  default = null
}

variable "organization" {
  description = "Heroku team"
  default = ""
}

resource "heroku_app" "uptermd" {
  name   = var.app_name
  region = var.region
  buildpacks = [ "heroku/go" ]
  space = var.space

  sensitive_config_vars = {
    PRIVATE_KEY = "${tls_private_key.private_key.private_key_pem}"
  }

  organization {
    name = var.organization
  }
}

resource "tls_private_key" "private_key" {
  algorithm   = "RSA"
  rsa_bits    = "4096"
}

resource "heroku_app_feature" "spaces-dns-discovery" {
  app = heroku_app.uptermd.id
  name = "spaces-dns-discovery"
  enabled = var.space == null ? false : true
}

resource "heroku_build" "uptermd" {
  app        = heroku_app.uptermd.id

  source = {
    url     = "https://github.com/jingweno/upterm/archive/${var.github_release}.tar.gz"
    version = var.github_release
  }
}

resource "heroku_formation" "uptermd" {
  app        = heroku_app.uptermd.id
  type       = "web"
  quantity   = var.space == null ? 1 : 2
  size       = var.space == null ? "standard-1x" : "private-s"
  depends_on = [ "heroku_build.uptermd" ]
}

output "app_url" {
  value = "https://${heroku_app.uptermd.name}.herokuapp.com"
}
