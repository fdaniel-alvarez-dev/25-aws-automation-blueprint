terraform {
  required_version = ">= 1.5.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "null" {}
provider "random" {}

variable "owner" {
  type        = string
  description = "Owner tag used for accountability and cost attribution."
  default     = "freddy-alvarez"
}

resource "random_id" "suffix" {
  byte_length = 2
}

resource "null_resource" "example" {
  triggers = {
    owner  = var.owner
    build  = "portfolio"
    suffix = random_id.suffix.hex
  }
}

output "example_triggers" {
  value = null_resource.example.triggers
}
