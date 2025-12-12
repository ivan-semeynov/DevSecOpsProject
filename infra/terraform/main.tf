terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Провайдер AWS, работающий с MinIO (S3-совместимое хранилище)
provider "aws" {
  region                      = "us-east-1"
  access_key                  = var.minio_access_key
  secret_key                  = var.minio_secret_key

  skip_credentials_validation = true
  skip_requesting_account_id  = true

  endpoints {
    s3 = var.minio_endpoint
  }
}

# -------------------------
# Переменные
# -------------------------

variable "minio_access_key" {
  type      = string
  sensitive = true
}

variable "minio_secret_key" {
  type      = string
  sensitive = true
}

variable "minio_endpoint" {
  type = string
}

# -------------------------
# Безопасный S3-бакет
# -------------------------

resource "aws_s3_bucket" "safe_logs" {
  bucket = "safe-logs-bucket"
  acl    = "private"

  tags = {
    Name        = "safe-logs-bucket"
    Environment = "demo"
    ManagedBy   = "terraform"
  }
}

# Явная блокировка любого публичного доступа
resource "aws_s3_bucket_public_access_block" "safe_logs" {
  bucket                  = aws_s3_bucket.safe_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# (Опционально) Шифрование на стороне сервера
resource "aws_s3_bucket_server_side_encryption_configuration" "safe_logs" {
  bucket = aws_s3_bucket.safe_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# (Опционально) Версионирование — плюс к безопасности
resource "aws_s3_bucket_versioning" "safe_logs" {
  bucket = aws_s3_bucket.safe_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}
