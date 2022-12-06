# Input variable definitions

variable "aws_region" {
  description = "AWS region for all resources."
  type    = string
  default = "us-east-1"
}

variable "client_id_list" {
  default = [
    "sts.amazonaws.com"
  ]
}

variable "repo_name" {
  type    = string
  # Example: Jareechang/astro-aws-starter
  default = "Jareechang/static-site-astro-aws-ci-cd"
}

variable "cf_price_class" {
  default = "PriceClass_100"
}
