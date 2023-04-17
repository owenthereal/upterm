variable "heroku_app_name" {
  description = "Heroku app name"
}

variable "heroku_region" {
  description = "Heroku region"
  default     = "us"
}

variable "heroku_space" {
  description = "Name of the Heroku space"
  default     = ""
}

variable "git_commit_sha" {
  description = "Git commit sha on GitHub"
  default     = "master"
}

variable "heroku_team" {
  description = "Heroku team"
  default     = ""
}

locals {
  app_id   = var.heroku_space == "" ? heroku_app.uptermd_common_runtime.*.id[0] : heroku_app.uptermd_private_spaces.*.id[0]
  app_name = var.heroku_space == "" ? heroku_app.uptermd_common_runtime.*.name[0] : heroku_app.uptermd_private_spaces.*.name[0]
}

resource "heroku_app" "uptermd_common_runtime" {
  count = var.heroku_team == "" ? 1 : 0

  name       = var.heroku_app_name
  region     = var.heroku_region
  buildpacks = ["heroku/go"]
  space      = var.heroku_space
  acm        = false

  sensitive_config_vars = {
    PRIVATE_KEY = "${tls_private_key.private_key.private_key_pem}"
  }
}

resource "heroku_app" "uptermd_private_spaces" {
  count = var.heroku_team == "" ? 0 : 1

  name       = var.heroku_app_name
  region     = var.heroku_region
  buildpacks = ["heroku/go"]
  space      = var.heroku_space
  acm        = false

  sensitive_config_vars = {
    PRIVATE_KEY = "${tls_private_key.private_key.private_key_pem}"
  }

  organization {
    name = var.heroku_team
  }
}

resource "tls_private_key" "private_key" {
  algorithm = "RSA"
  rsa_bits  = "4096"
}

resource "heroku_app_feature" "spaces-dns-discovery" {
  app_id  = local.app_id
  name    = "spaces-dns-discovery"
  enabled = var.heroku_space == "" ? false : true
}

resource "heroku_build" "uptermd" {
  app_id = local.app_id

  source {
    url     = "https://github.com/owenthereal/upterm/archive/${var.git_commit_sha}.tar.gz"
    version = var.git_commit_sha
  }
}

resource "heroku_formation" "uptermd" {
  app_id     = local.app_id
  type       = "web"
  quantity   = var.heroku_space == "" ? 1 : 2
  size       = var.heroku_space == "" ? "eco" : "private-s"
  depends_on = [heroku_build.uptermd]
}

output "step_1_share_session" {
  value = "upterm host --server wss://${local.app_name}.herokuapp.com -- YOUR_COMMAND"
}

output "step_2_join_session" {
  value = "ssh -o ProxyCommand='upterm proxy wss://TOKEN@${local.app_name}.herokuapp.com' TOKEN@${local.app_name}.herokuapp.com:443"
}
