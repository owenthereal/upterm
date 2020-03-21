variable "heroku_app_name" {
  description = "Heroku app name"
}

variable "heroku_region" {
  description = "Heroku region"
  default = "us"
}

variable "heroku_space" {
  description = "Name of the Heroku space"
  default = ""
}

variable "git_commit_sha" {
  description = "Git commit sha on GitHub"
  default = "master"
}

variable "heroku_team" {
  description = "Heroku team"
  default = ""
}

resource "heroku_app" "uptermd" {
  name   = var.heroku_app_name
  region = var.heroku_region
  buildpacks = [ "heroku/go" ]
  space = var.heroku_space
  acm = true

  sensitive_config_vars = {
    PRIVATE_KEY = "${tls_private_key.private_key.private_key_pem}"
  }

  organization {
    name = var.heroku_team
  }
}

resource "tls_private_key" "private_key" {
  algorithm   = "RSA"
  rsa_bits    = "4096"
}

resource "heroku_app_feature" "spaces-dns-discovery" {
  app = heroku_app.uptermd.id
  name = "spaces-dns-discovery"
  enabled = var.heroku_space == "" ? false : true
}

resource "heroku_build" "uptermd" {
  app        = heroku_app.uptermd.id

  source = {
    url     = "https://github.com/jingweno/upterm/archive/${var.git_commit_sha}.tar.gz"
    version = var.git_commit_sha
  }
}

resource "heroku_formation" "uptermd" {
  app        = heroku_app.uptermd.id
  type       = "web"
  quantity   = var.heroku_space == "" ? 1 : 2
  size       = var.heroku_space == "" ? "standard-1x" : "private-s"
  depends_on = [ heroku_build.uptermd ]
}

output "app_url" {
  value = "https://${heroku_app.uptermd.name}.herokuapp.com"
}
