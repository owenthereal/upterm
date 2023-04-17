terraform {
  required_providers {
    heroku = {
      source  = "heroku/heroku"
      version = "5.2.1"
    }
  }
}

provider "heroku" {
}

provider "tls" {
}
