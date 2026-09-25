terraform {
  required_version = "~> 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # Local state. Single operator, no concurrent applies, and the alternative
  # (S3 + DynamoDB) would add billable resources that complicate teardown --
  # which matters here, because teardown between run blocks is the project's
  # main cost control (risk R12). State is gitignored.
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project   = "ddos-eval"
      managedby = "terraform"
      component = "00-core"
    }
  }
}
