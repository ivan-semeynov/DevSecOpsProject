class TerraformParser:
    def find_s3_buckets(self, terraform_code):
        """Поиск S3 бакетов в Terraform коде"""
        buckets = []
        code_str = str(terraform_code)
        
        # Имитация поиска S3 ресурсов
        if "s3_bucket" in code_str or "storage_bucket" in code_str:
            buckets.append({"name": "app-backup-bucket", "acl": "private"})
            buckets.append({"name": "logs-bucket", "acl": "public-read"})  # Нарушение!
        
        return buckets
    
    def find_iam_roles(self, terraform_code):
        """Поиск IAM ролей в Terraform коде"""
        roles = []
        code_str = str(terraform_code)
        
        # Имитация поиска IAM ресурсов
        if "iam_role" in code_str or "service_account" in code_str:
            roles.append({"name": "monitoring-role", "role": "admin"})  # Нарушение!
            roles.append({"name": "backup-role", "role": "viewer"})
        
        return roles