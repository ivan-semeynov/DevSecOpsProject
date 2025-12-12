terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Это НЕ реальный AWS, а MinIO (S3-совместимый endpoint)
provider "aws" {
  region                      = "us-east-1"
  access_key                  = var.minio_access_key
  secret_key                  = var.minio_secret_key

  skip_credentials_validation = true
  skip_requesting_account_id  = true

  endpoints {
    # ВАЖНО: для Terraform в Docker MinIO доступен по host.docker.internal
    s3 = var.minio_endpoint
  }
}

variable "minio_access_key" {
  type      = string
  sensitive = true
}

variable "minio_secret_key" {
  type      = string
  sensitive = true
}

variable "minio_endpoint" {
  type    = string
  default = "http://host.docker.internal:9000"
}

# Безопасный бакет (после добавления public_access_block будет реально ок)
resource "aws_s3_bucket" "safe_logs" {
  bucket = "safe-logs-bucket"
  acl    = "private"

  # ниже блок добавим позже, когда будем показывать "зелёный" сценарий
}

# Опасный бакет (для демонстрации сценария 1)
resource "aws_s3_bucket" "dangerous_logs" {
  bucket = "dangerous-logs-bucket"
  acl    = "public-read"  # <-- должен ломать пайплайн
}
