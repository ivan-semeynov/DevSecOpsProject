class TerraformParser:
    def find_s3_buckets(self, terraform_code):
        """Поиск S3 бакетов в Terraform коде"""
        buckets = []
        
        # Парсим реальный terraform_code вместо тестовых данных
        if isinstance(terraform_code, dict):
            resources = terraform_code.get("resource", {})
            s3_buckets = resources.get("yandex_storage_bucket", {})
            
            for bucket_name, bucket_config in s3_buckets.items():
                buckets.append({
                    "name": bucket_name,
                    "acl": bucket_config.get("acl", "private")
                })
        
        return buckets
    
    def find_iam_roles(self, terraform_code):
        """Поиск IAM ролей в Terraform коде"""
        roles = []
        
        if isinstance(terraform_code, dict):
            resources = terraform_code.get("resource", {})
            
            # Ищем IAM роли
            iam_roles = resources.get("yandex_iam_service_account", {})
            for role_name, role_config in iam_roles.items():
                roles.append({
                    "name": role_name,
                    "role": "admin" if "admin" in role_name else "viewer"  # Упрощенная логика
                })
            
            # Ищем IAM binding
            iam_bindings = resources.get("yandex_resourcemanager_folder_iam_binding", {})
            for binding_name, binding_config in iam_bindings.items():
                role = binding_config.get("role", "viewer")
                roles.append({
                    "name": binding_name,
                    "role": role
                })
        
        return roles