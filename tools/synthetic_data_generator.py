#!/usr/bin/env python3
"""
Synthetic Data Generator for S3 Demo Buckets
Generates realistic fake sensitive data for security testing
"""
import json
import random
import string
import base64
from datetime import datetime, timedelta
import csv
import io


class SyntheticDataGenerator:
    """Generate various types of synthetic sensitive data"""
    
    def __init__(self):
        self.fake_names = [
            "John Smith", "Jane Doe", "Alice Johnson", "Bob Williams", "Carol Davis",
            "David Brown", "Emma Wilson", "Frank Miller", "Grace Lee", "Henry Martin"
        ]
        self.fake_companies = [
            "Acme Corp", "TechStart Inc", "Global Systems", "DataFlow LLC", "CloudNet Solutions"
        ]
        self.fake_departments = ["Sales", "Engineering", "HR", "Finance", "Marketing", "IT"]
        
    def generate_financial_data(self):
        """Generate synthetic financial transaction data"""
        transactions = []
        for i in range(100):
            date = (datetime.now() - timedelta(days=random.randint(1, 365))).strftime('%Y-%m-%d')
            transactions.append({
                "transaction_id": f"TXN{random.randint(100000, 999999)}",
                "date": date,
                "amount": round(random.uniform(10.0, 10000.0), 2),
                "currency": "USD",
                "account_number": f"ACC{random.randint(1000000, 9999999)}",
                "merchant": random.choice(self.fake_companies),
                "category": random.choice(["Purchase", "Transfer", "Withdrawal", "Deposit"]),
                "status": random.choice(["Completed", "Pending", "Failed"])
            })
        
        # Quarterly report data
        quarterly_report = {
            "quarter": "Q1-2025",
            "revenue": 15750000,
            "expenses": 12300000,
            "profit": 3450000,
            "growth_rate": "12.5%",
            "departments": {dept: random.randint(100000, 5000000) for dept in self.fake_departments}
        }
        
        # Revenue forecast
        forecast = {
            "year": 2025,
            "projections": {
                "Q1": 15750000,
                "Q2": 17325000,
                "Q3": 19057500,
                "Q4": 20963250
            },
            "confidence": "85%",
            "assumptions": ["10% quarterly growth", "No major market disruptions", "Successful product launch"]
        }
        
        return {
            "transactions-2025.json": json.dumps(transactions, indent=2),
            "quarterly-report-Q1.json": json.dumps(quarterly_report, indent=2),
            "revenue-forecast.json": json.dumps(forecast, indent=2)
        }
    
    def generate_customer_data(self):
        """Generate synthetic PII customer data"""
        customers = []
        for i in range(50):
            customers.append({
                "customer_id": f"CUST{random.randint(10000, 99999)}",
                "name": random.choice(self.fake_names),
                "email": f"user{random.randint(100, 999)}@example.com",
                "phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
                "address": f"{random.randint(100, 9999)} Main St, City, ST {random.randint(10000, 99999)}",
                "ssn": f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}",
                "date_of_birth": f"{random.randint(1950, 2000)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
                "credit_score": random.randint(300, 850),
                "account_status": random.choice(["Active", "Inactive", "Suspended"])
            })
        
        # User profiles
        profiles = []
        for i in range(30):
            profiles.append({
                "user_id": f"USER{random.randint(1000, 9999)}",
                "username": f"user{random.randint(100, 999)}",
                "password_hash": base64.b64encode(f"hash_{random.randint(100000, 999999)}".encode()).decode(),
                "last_login": datetime.now().isoformat(),
                "preferences": {
                    "theme": random.choice(["dark", "light"]),
                    "notifications": random.choice([True, False]),
                    "language": random.choice(["en", "es", "fr", "de"])
                }
            })
        
        return {
            "customer-list.json": json.dumps(customers, indent=2),
            "user-profiles.json": json.dumps(profiles, indent=2),
            "contact-database.csv": self._generate_csv(customers[:20])
        }
    
    def generate_audit_logs(self):
        """Generate synthetic CloudTrail and security logs"""
        cloudtrail_events = []
        for i in range(200):
            timestamp = (datetime.now() - timedelta(minutes=random.randint(1, 10000))).isoformat()
            cloudtrail_events.append({
                "eventTime": timestamp,
                "eventName": random.choice(["CreateBucket", "GetObject", "PutObject", "DeleteObject", "CreateUser", "AssumeRole"]),
                "eventSource": random.choice(["s3.amazonaws.com", "iam.amazonaws.com", "sts.amazonaws.com"]),
                "userIdentity": {
                    "type": random.choice(["IAMUser", "AssumedRole", "Root"]),
                    "principalId": f"AIDA{random.randint(100000, 999999)}",
                    "arn": f"arn:aws:iam::343059098826:user/user{random.randint(1, 100)}"
                },
                "sourceIPAddress": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "userAgent": "aws-cli/2.0.0"
            })
        
        # Security events
        security_events = []
        for i in range(50):
            security_events.append({
                "timestamp": datetime.now().isoformat(),
                "event_type": random.choice(["LOGIN_ATTEMPT", "PRIVILEGE_ESCALATION", "UNAUTHORIZED_ACCESS", "POLICY_VIOLATION"]),
                "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                "user": random.choice(self.fake_names),
                "ip_address": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "action_taken": random.choice(["BLOCKED", "ALLOWED", "LOGGED", "ALERTED"])
            })
        
        # Access logs
        access_log_lines = []
        for i in range(100):
            timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')
            access_log_lines.append(
                f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)} - - [{timestamp}] "GET /api/v1/resource HTTP/1.1" {random.choice([200, 401, 403, 404, 500])} {random.randint(100, 10000)}'
            )
        
        return {
            "cloudtrail-logs.json": json.dumps({"Records": cloudtrail_events}, indent=2),
            "security-events.json": json.dumps(security_events, indent=2),
            "access-logs.txt": "\n".join(access_log_lines)
        }
    
    def generate_secrets(self):
        """Generate synthetic API keys, passwords, and certificates"""
        # API Keys
        api_keys = {
            "production": {
                "aws_access_key": f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}",
                "aws_secret_key": base64.b64encode(''.join(random.choices(string.ascii_letters + string.digits, k=40)).encode()).decode()[:40],
                "github_token": f"ghp_{''.join(random.choices(string.ascii_letters + string.digits, k=36))}",
                "stripe_key": f"sk_live_{''.join(random.choices(string.ascii_letters + string.digits, k=32))}"
            },
            "staging": {
                "api_endpoint": "https://api.staging.example.com",
                "api_key": ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
                "webhook_secret": base64.b64encode(''.join(random.choices(string.ascii_letters, k=24)).encode()).decode()
            }
        }
        
        # Database passwords
        db_passwords = {
            "databases": {
                "production": {
                    "host": "prod-db.example.com",
                    "port": 5432,
                    "username": "admin",
                    "password": ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=16)),
                    "database": "production_db"
                },
                "analytics": {
                    "host": "analytics-db.example.com",
                    "port": 3306,
                    "username": "analytics_user",
                    "password": ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=16)),
                    "database": "analytics"
                }
            }
        }
        
        # Fake SSL certificate
        ssl_cert = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKLdQVPy90WjMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjUwMTAxMDAwMDAwWhcNMjYwMTAxMDAwMDAwWjBF
[SYNTHETIC CERTIFICATE DATA - NOT REAL]
-----END CERTIFICATE-----"""
        
        return {
            "api-keys.json": json.dumps(api_keys, indent=2),
            "database-passwords.json": json.dumps(db_passwords, indent=2),
            "ssl-certificates.pem": ssl_cert
        }
    
    def generate_backups(self):
        """Generate synthetic backup data"""
        # Database dump (SQL format)
        sql_dump = """-- Synthetic Database Dump
-- Generated: """ + datetime.now().isoformat() + """
-- Database: production_db

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    password_hash VARCHAR(255),
    created_at TIMESTAMP
);

INSERT INTO users VALUES
"""
        for i in range(10):
            sql_dump += f"({i+1}, 'user{i+1}', 'user{i+1}@example.com', 'hash_{random.randint(100000, 999999)}', '2025-01-01 00:00:00'),\n"
        sql_dump = sql_dump.rstrip(',\n') + ";\n"
        
        # Config backup
        config_data = {
            "application": {
                "name": "lambda-testing-toolkit-app",
                "version": "2.5.0",
                "environment": "production",
                "debug": False,
                "secret_key": base64.b64encode(''.join(random.choices(string.ascii_letters, k=32)).encode()).decode()
            },
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "app_db"
            },
            "cache": {
                "type": "redis",
                "host": "cache.example.com",
                "port": 6379
            }
        }
        
        # System snapshot info
        snapshot_info = {
            "snapshot_id": f"snap-{random.randint(100000, 999999)}",
            "timestamp": datetime.now().isoformat(),
            "system": "Ubuntu 20.04 LTS",
            "size_gb": 50,
            "encrypted": True,
            "volumes": [
                {"mount": "/", "size_gb": 20, "used_gb": 12},
                {"mount": "/var", "size_gb": 30, "used_gb": 18}
            ]
        }
        
        return {
            "database-dump-2025.sql": sql_dump,
            "config-backup.json": json.dumps(config_data, indent=2),
            "system-snapshot.json": json.dumps(snapshot_info, indent=2)
        }
    
    def _generate_csv(self, data):
        """Helper to generate CSV from list of dicts"""
        if not data:
            return ""
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()
    
    def generate_all_data(self):
        """Generate all synthetic data for buckets (aligned with new structure)"""
        return {
            "data": self.generate_mixed_data(),  # Primary data bucket
            "logs": self.generate_audit_logs(),   # Logs bucket
            "config": self.generate_secrets()     # Config/secrets bucket
        }
        
    def generate_mixed_data(self):
        """Generate mixed data combining financial and customer data"""
        financial_data = self.generate_financial_data()
        customer_data = self.generate_customer_data()
        backup_data = self.generate_backups()
        
        # Combine all data types for the primary data bucket
        mixed_data = {}
        mixed_data.update(financial_data)
        mixed_data.update(customer_data) 
        mixed_data.update(backup_data)
        
        return mixed_data


# Lambda handler for CloudFormation custom resource
def lambda_handler(event, context):
    """CloudFormation custom resource handler to populate S3 buckets"""
    import boto3
    import cfnresponse
    
    s3 = boto3.client('s3')
    
    try:
        request_type = event['RequestType']
        bucket_prefix = event['ResourceProperties'].get('BucketPrefix', 'lambdalabs')
        random_suffix = event['ResourceProperties'].get('RandomSuffix', '')
        
        if request_type == 'Create' or request_type == 'Update':
            generator = SyntheticDataGenerator()
            all_data = generator.generate_all_data()
            
            bucket_mapping = {
                f"{bucket_prefix}-finance-data-{random_suffix}": all_data['finance'],
                f"{bucket_prefix}-customer-data-{random_suffix}": all_data['customer'],
                f"{bucket_prefix}-audit-logs-{random_suffix}": all_data['audit'],
                f"{bucket_prefix}-secrets-{random_suffix}": all_data['secrets'],
                f"{bucket_prefix}-backups-{random_suffix}": all_data['backups']
            }
            
            for bucket_name, files in bucket_mapping.items():
                for file_name, content in files.items():
                    s3.put_object(
                        Bucket=bucket_name,
                        Key=file_name,
                        Body=content.encode('utf-8') if isinstance(content, str) else content,
                        ServerSideEncryption='AES256'
                    )
                    print(f"Created {file_name} in {bucket_name}")
            
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {
                'Message': 'Synthetic data created successfully'
            })
        
        elif request_type == 'Delete':
            # Cleanup is handled by bucket deletion
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {
                'Message': 'Cleanup not required'
            })
            
    except Exception as e:
        print(f"Error: {str(e)}")
        cfnresponse.send(event, context, cfnresponse.FAILED, {
            'Message': str(e)
        })
    
    return {'statusCode': 200}


# For local testing
if __name__ == "__main__":
    generator = SyntheticDataGenerator()
    all_data = generator.generate_all_data()
    
    print("Generated synthetic data for all buckets:")
    for category, files in all_data.items():
        print(f"\n{category.upper()} bucket:")
        for filename in files.keys():
            print(f"  - {filename}")
