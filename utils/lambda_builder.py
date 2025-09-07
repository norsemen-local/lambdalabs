#!/usr/bin/env python3
"""
Lambda Package Builder for AWS Lambda Testing Toolkit
Handles creation and management of Lambda deployment packages
"""
import os
import sys
import zipfile
import shutil
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
import json


class LambdaPackageBuilder:
    """Builds and manages Lambda deployment packages"""
    
    def __init__(self, project_root=None):
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.build_dir = self.project_root / 'build'
        self.lambda_packages_dir = self.project_root / 'payloads' / 'lambda' / 'packages'
        
        # Ensure directories exist
        self.build_dir.mkdir(exist_ok=True)
        self.lambda_packages_dir.mkdir(exist_ok=True)
        
    def create_basic_lambda_package(self, output_name="lambda_function"):
        """
        Create a basic Lambda package with the main lambda function
        Returns: Path to the created zip file
        """
        print(f"[INFO] Creating Lambda package: {output_name}")
        
        # Create temporary build directory
        temp_dir = self.build_dir / f"temp_{output_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Copy lambda function
            lambda_source = self.project_root / "payloads" / "lambda" / "lambda_function.py"
            if not lambda_source.exists():
                raise FileNotFoundError(f"Lambda source file not found: {lambda_source}")
                
            shutil.copy2(lambda_source, temp_dir / "lambda_function.py")
            
            # Create deployment package
            zip_path = self.lambda_packages_dir / f"{output_name}.zip"
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add lambda function
                zipf.write(temp_dir / "lambda_function.py", "lambda_function.py")
                
                # Add any additional Python files if needed
                for py_file in temp_dir.glob("*.py"):
                    if py_file.name != "lambda_function.py":
                        zipf.write(py_file, py_file.name)
                        
            print(f"[SUCCESS] Lambda package created: {zip_path}")
            print(f"[INFO] Package size: {zip_path.stat().st_size / 1024:.1f} KB")
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir)
            
            return str(zip_path)
            
        except Exception as e:
            # Cleanup on error
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            raise Exception(f"Failed to create Lambda package: {str(e)}")
            
    def create_enhanced_lambda_package(self, output_name="enhanced_lambda_function", include_dependencies=False):
        """
        Create an enhanced Lambda package with additional utilities
        Returns: Path to the created zip file
        """
        print(f"[INFO] Creating enhanced Lambda package: {output_name}")
        
        # Create temporary build directory
        temp_dir = self.build_dir / f"temp_{output_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Copy main lambda function
            lambda_source = self.project_root / "payloads" / "lambda" / "lambda_function.py"
            if not lambda_source.exists():
                raise FileNotFoundError(f"Lambda source file not found: {lambda_source}")
                
            shutil.copy2(lambda_source, temp_dir / "lambda_function.py")
            
            # Create enhanced version with additional capabilities
            enhanced_lambda = self._create_enhanced_lambda_function()
            with open(temp_dir / "lambda_function.py", 'w') as f:
                f.write(enhanced_lambda)
                
            # Install dependencies if requested
            if include_dependencies:
                self._install_lambda_dependencies(temp_dir)
                
            # Create deployment package
            zip_path = self.lambda_packages_dir / f"{output_name}.zip"
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add all files from temp directory
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = Path(root) / file
                        archive_name = file_path.relative_to(temp_dir)
                        zipf.write(file_path, archive_name)
                        
            print(f"[SUCCESS] Enhanced Lambda package created: {zip_path}")
            print(f"[INFO] Package size: {zip_path.stat().st_size / 1024:.1f} KB")
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir)
            
            return str(zip_path)
            
        except Exception as e:
            # Cleanup on error
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            raise Exception(f"Failed to create enhanced Lambda package: {str(e)}")
            
    def _create_enhanced_lambda_function(self):
        """Create enhanced Lambda function with additional security testing capabilities"""
        enhanced_code = '''import boto3
import json
import os
from datetime import datetime
import base64
import subprocess
import sys

# Initialize AWS clients
sts_client = boto3.client("sts")
iam_client = boto3.client("iam")
s3_client = boto3.client("s3")
ec2_client = boto3.client("ec2")
lambda_client = boto3.client("lambda")

def lambda_handler(event, context):
    """
    Enhanced Lambda function for security testing with expanded capabilities
    """
    try:
        # Parse input parameters
        action = event.get("action", "sts_get_identity").lower()
        
        print(f"[INFO] Lambda invoked with action: {action}")
        print(f"[INFO] Execution context: {context.function_name} v{context.function_version}")
        
        # Route to appropriate function
        if action == "sts_get_identity":
            return get_caller_identity()
        elif action == "sts_get_session_token":
            return get_session_token()
        elif action == "list_roles":
            return list_iam_roles()
        elif action == "list_users":
            return list_iam_users()
        elif action == "list_s3_buckets":
            return list_s3_buckets()
        elif action == "list_s3_objects":
            bucket_name = event.get("bucket_name")
            return list_s3_objects(bucket_name) if bucket_name else response_template(400, "Missing bucket_name")
        elif action == "s3_enum":
            return s3_enum()
        elif action == "list_ec2_instances":
            return list_ec2_instances()
        elif action == "environment_recon":
            return environment_reconnaissance()
        elif action == "privilege_check":
            return check_privileges()
        elif action == "network_discovery":
            return network_discovery()
        else:
            return response_template(400, f"Invalid action: {action}")
            
    except Exception as e:
        error_msg = f"Lambda execution error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        return response_template(500, error_msg)

# -------------------- Core Functions --------------------
def get_caller_identity():
    """Returns the AWS identity executing the function"""
    try:
        identity = sts_client.get_caller_identity()
        
        # Enhanced identity information
        enhanced_identity = {
            "account": identity["Account"],
            "userId": identity["UserId"],
            "arn": identity["Arn"],
            "execution_time": datetime.utcnow().isoformat(),
            "lambda_context": {
                "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown"),
                "function_version": os.environ.get("AWS_LAMBDA_FUNCTION_VERSION", "unknown"),
                "region": os.environ.get("AWS_REGION", "unknown")
            }
        }
        
        return response_template(200, enhanced_identity)
    except Exception as e:
        return response_template(500, f"Failed to retrieve identity: {str(e)}")

def get_session_token():
    """Returns temporary AWS session token"""
    try:
        token = sts_client.get_session_token()
        return response_template(200, token["Credentials"])
    except Exception as e:
        return response_template(500, f"Failed to retrieve session token: {str(e)}")

def list_iam_roles():
    """Lists IAM roles with enhanced information"""
    try:
        roles = iam_client.list_roles()
        
        enhanced_roles = []
        for role in roles["Roles"][:10]:  # Limit to first 10 for performance
            enhanced_roles.append({
                "role_name": role["RoleName"],
                "arn": role["Arn"],
                "created": role["CreateDate"].isoformat() if "CreateDate" in role else None,
                "path": role.get("Path", "/"),
                "max_session_duration": role.get("MaxSessionDuration", 3600)
            })
            
        return response_template(200, enhanced_roles)
    except Exception as e:
        return response_template(500, f"Failed to list IAM roles: {str(e)}")

def list_iam_users():
    """Lists IAM users with enhanced information"""
    try:
        users = iam_client.list_users()
        
        enhanced_users = []
        for user in users["Users"][:10]:  # Limit to first 10
            enhanced_users.append({
                "user_name": user["UserName"],
                "arn": user["Arn"],
                "created": user["CreateDate"].isoformat() if "CreateDate" in user else None,
                "path": user.get("Path", "/")
            })
            
        return response_template(200, enhanced_users)
    except Exception as e:
        return response_template(500, f"Failed to list IAM users: {str(e)}")

def list_s3_buckets():
    """Lists all S3 buckets with enhanced information"""
    try:
        buckets_response = s3_client.list_buckets()
        
        enhanced_buckets = []
        for bucket in buckets_response.get("Buckets", []):
            bucket_info = {
                "name": bucket["Name"],
                "created": bucket["CreationDate"].isoformat()
            }
            
            # Try to get bucket region and additional info
            try:
                location = s3_client.get_bucket_location(Bucket=bucket["Name"])
                bucket_info["region"] = location.get("LocationConstraint") or "us-east-1"
            except:
                bucket_info["region"] = "unknown"
                
            enhanced_buckets.append(bucket_info)
            
        return response_template(200, enhanced_buckets)
    except Exception as e:
        return response_template(500, f"Failed to list S3 buckets: {str(e)}")

def list_s3_objects(bucket_name):
    """Lists objects in a specific S3 bucket"""
    try:
        objects_response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
        
        if "Contents" not in objects_response:
            return response_template(200, f"No objects found in bucket '{bucket_name}'")
            
        objects = []
        for obj in objects_response["Contents"]:
            objects.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "modified": obj["LastModified"].isoformat(),
                "storage_class": obj.get("StorageClass", "STANDARD")
            })
            
        return response_template(200, objects)
    except Exception as e:
        return response_template(500, f"Failed to list objects in bucket '{bucket_name}': {str(e)}")

def s3_enum():
    """Enhanced S3 enumeration with detailed analysis"""
    try:
        print("[INFO] Starting enhanced S3 enumeration...")
        buckets_response = s3_client.list_buckets()
        
        if not buckets_response.get("Buckets"):
            return response_template(200, "No S3 buckets found")
            
        enumeration_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_buckets": len(buckets_response["Buckets"]),
            "buckets": []
        }
        
        for bucket in buckets_response["Buckets"]:
            bucket_name = bucket["Name"]
            bucket_info = {
                "name": bucket_name,
                "created": bucket["CreationDate"].isoformat(),
                "objects": [],
                "total_objects": 0,
                "total_size": 0,
                "errors": []
            }
            
            try:
                # Get bucket objects
                objects_response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=50)
                
                if "Contents" in objects_response:
                    bucket_info["total_objects"] = objects_response.get("KeyCount", 0)
                    
                    for obj in objects_response["Contents"]:
                        bucket_info["objects"].append({
                            "key": obj["Key"],
                            "size": obj["Size"],
                            "modified": obj["LastModified"].isoformat()
                        })
                        bucket_info["total_size"] += obj["Size"]
                        
            except Exception as e:
                bucket_info["errors"].append(f"Failed to enumerate objects: {str(e)}")
                
            enumeration_results["buckets"].append(bucket_info)
            
        return response_template(200, enumeration_results)
    except Exception as e:
        return response_template(500, f"Enhanced S3 enumeration failed: {str(e)}")

def list_ec2_instances():
    """Lists EC2 instances with enhanced information"""
    try:
        instances = ec2_client.describe_instances()
        
        enhanced_instances = []
        for reservation in instances["Reservations"]:
            for instance in reservation["Instances"]:
                enhanced_instances.append({
                    "instance_id": instance["InstanceId"],
                    "state": instance["State"]["Name"],
                    "instance_type": instance["InstanceType"],
                    "public_dns": instance.get("PublicDnsName", "N/A"),
                    "public_ip": instance.get("PublicIpAddress", "N/A"),
                    "private_ip": instance.get("PrivateIpAddress", "N/A"),
                    "launch_time": instance["LaunchTime"].isoformat(),
                    "availability_zone": instance["Placement"]["AvailabilityZone"]
                })
                
        return response_template(200, enhanced_instances)
    except Exception as e:
        return response_template(500, f"Failed to list EC2 instances: {str(e)}")

def environment_reconnaissance():
    """Perform environment reconnaissance"""
    try:
        recon_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "lambda_environment": {
                "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME"),
                "function_version": os.environ.get("AWS_LAMBDA_FUNCTION_VERSION"),
                "region": os.environ.get("AWS_REGION"),
                "runtime": os.environ.get("AWS_EXECUTION_ENV"),
                "memory_limit": os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE"),
                "timeout": os.environ.get("AWS_LAMBDA_FUNCTION_TIMEOUT")
            },
            "system_info": {
                "python_version": sys.version,
                "platform": sys.platform
            }
        }
        
        # Get current identity
        try:
            identity = sts_client.get_caller_identity()
            recon_data["identity"] = identity
        except Exception as e:
            recon_data["identity_error"] = str(e)
            
        return response_template(200, recon_data)
    except Exception as e:
        return response_template(500, f"Environment reconnaissance failed: {str(e)}")

def check_privileges():
    """Check current privileges and permissions"""
    try:
        privilege_check = {
            "timestamp": datetime.utcnow().isoformat(),
            "tests": []
        }
        
        # Test various AWS services
        services_to_test = [
            ("S3", lambda: s3_client.list_buckets()),
            ("IAM", lambda: iam_client.list_roles(MaxItems=1)),
            ("EC2", lambda: ec2_client.describe_instances(MaxResults=1)),
            ("Lambda", lambda: lambda_client.list_functions(MaxItems=1))
        ]
        
        for service_name, test_func in services_to_test:
            try:
                test_func()
                privilege_check["tests"].append({
                    "service": service_name,
                    "access": "ALLOWED",
                    "error": None
                })
            except Exception as e:
                privilege_check["tests"].append({
                    "service": service_name,
                    "access": "DENIED",
                    "error": str(e)
                })
                
        return response_template(200, privilege_check)
    except Exception as e:
        return response_template(500, f"Privilege check failed: {str(e)}")

def network_discovery():
    """Perform basic network discovery"""
    try:
        network_info = {
            "timestamp": datetime.utcnow().isoformat(),
            "lambda_network": {
                "region": os.environ.get("AWS_REGION"),
                "availability_zone": "lambda-managed"
            }
        }
        
        # Try to determine VPC information if available
        try:
            # This would only work in VPC-enabled Lambda
            vpc_info = {}  # Placeholder for VPC discovery
            network_info["vpc_info"] = vpc_info
        except:
            network_info["vpc_info"] = "Lambda not in VPC or no VPC access"
            
        return response_template(200, network_info)
    except Exception as e:
        return response_template(500, f"Network discovery failed: {str(e)}")

def response_template(status_code, data):
    """Standardized JSON response format"""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "X-Lambda-Function": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown"),
            "X-Request-Id": os.environ.get("AWS_REQUEST_ID", "unknown")
        },
        "body": json.dumps(data, indent=2, default=str)
    }
'''
        return enhanced_code
        
    def _install_lambda_dependencies(self, temp_dir):
        """Install Python dependencies for Lambda package"""
        print("[INFO] Installing Lambda dependencies...")
        
        # Create requirements.txt for Lambda-specific dependencies
        lambda_requirements = [
            "boto3>=1.28.0",
            "botocore>=1.31.0"
        ]
        
        requirements_file = temp_dir / "requirements.txt"
        with open(requirements_file, 'w') as f:
            f.write('\n'.join(lambda_requirements))
            
        # Install dependencies
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install",
                "-r", str(requirements_file),
                "-t", str(temp_dir),
                "--no-deps"  # Don't install dependencies of dependencies
            ], check=True, capture_output=True)
            
            print("[SUCCESS] Dependencies installed")
            
        except subprocess.CalledProcessError as e:
            print(f"[WARNING] Failed to install dependencies: {e.stderr.decode()}")
            
    def list_existing_packages(self):
        """List existing Lambda packages"""
        packages = []
        
        for zip_file in self.lambda_packages_dir.glob("*.zip"):
            stat = zip_file.stat()
            packages.append({
                'name': zip_file.name,
                'path': str(zip_file),
                'size_kb': stat.st_size / 1024,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
            
        return sorted(packages, key=lambda x: x['modified'], reverse=True)
        
    def cleanup_old_packages(self, keep_count=5):
        """Remove old Lambda packages, keeping only the most recent ones"""
        packages = self.list_existing_packages()
        
        if len(packages) > keep_count:
            to_remove = packages[keep_count:]
            
            print(f"[INFO] Removing {len(to_remove)} old Lambda packages:")
            
            for package in to_remove:
                try:
                    Path(package['path']).unlink()
                    print(f"  - Removed: {package['name']}")
                except Exception as e:
                    print(f"  - Failed to remove {package['name']}: {e}")
                    
    def build_s3_enumeration_lambda(self):
        """Build S3 enumeration Lambda function as ZIP package"""
        try:
            import zipfile
            import io
            
            # Create S3-focused Lambda function code
            s3_lambda_code = '''
import boto3
import json

def lambda_handler(event, context):
    """Lambda function for S3 enumeration and data extraction"""
    try:
        s3_client = boto3.client('s3')
        
        action = event.get('action', 'list_buckets')
        target_buckets = event.get('target_buckets', [])
        
        if action == 'list_buckets':
            response = s3_client.list_buckets()
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'buckets': buckets,
                    'target_buckets': [b for b in buckets if 'lambda-testing-toolkit' in b]
                })
            }
            
        elif action == 'enumerate_bucket':
            bucket_name = event.get('bucket_name')
            if not bucket_name:
                return {'statusCode': 400, 'body': json.dumps({'error': 'bucket_name required'})}
                
            bucket_data = {
                'name': bucket_name,
                'objects': [],
                'metadata': {}
            }
            
            try:
                # Get bucket tags
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    bucket_data['metadata']['tags'] = tags_response.get('TagSet', [])
                except:
                    bucket_data['metadata']['tags'] = []
                    
                # Get encryption status
                try:
                    enc_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    bucket_data['metadata']['encryption'] = 'Enabled'
                except:
                    bucket_data['metadata']['encryption'] = 'Disabled'
                    
                # List objects
                objects_response = s3_client.list_objects_v2(Bucket=bucket_name)
                objects = objects_response.get('Contents', [])
                
                for obj in objects:
                    object_info = {
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat(),
                        'content': None
                    }
                    
                    # Download small objects (< 1MB)
                    if obj['Size'] < 1024 * 1024:
                        try:
                            content_response = s3_client.get_object(Bucket=bucket_name, Key=obj['Key'])
                            content = content_response['Body'].read().decode('utf-8', errors='ignore')
                            object_info['content'] = content[:5000]  # First 5KB
                        except:
                            object_info['content'] = 'Error reading content'
                            
                    bucket_data['objects'].append(object_info)
                    
                return {
                    'statusCode': 200,
                    'body': json.dumps(bucket_data, default=str)
                }
                
            except Exception as e:
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': f'Failed to enumerate bucket: {str(e)}'})
                }
                
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'Unknown action: {action}'})
            }
            
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
'''
            
            # Create ZIP file in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr('lambda_function.py', s3_lambda_code)
                
            zip_buffer.seek(0)
            return zip_buffer.read()
            
        except Exception as e:
            from utils.enhanced_logging import get_logger
            logger = get_logger(__name__)
            logger.error(
                f"Failed to build S3 enumeration Lambda: {str(e)}",
                suggestion="Check Lambda function code syntax and ensure required dependencies are available"
            )
            return None
            
    def build_all_packages(self):
        """Build all available Lambda package variants"""
        packages_built = []
        
        try:
            # Build basic package
            basic_package = self.create_basic_lambda_package("basic_lambda")
            packages_built.append(basic_package)
            
            # Build enhanced package
            enhanced_package = self.create_enhanced_lambda_package("enhanced_lambda")
            packages_built.append(enhanced_package)
            
            # Build enhanced package with dependencies
            enhanced_deps_package = self.create_enhanced_lambda_package(
                "enhanced_lambda_with_deps", 
                include_dependencies=True
            )
            packages_built.append(enhanced_deps_package)
            
            print(f"\n[SUCCESS] Built {len(packages_built)} Lambda packages:")
            for package in packages_built:
                package_path = Path(package)
                size_kb = package_path.stat().st_size / 1024
                print(f"  - {package_path.name} ({size_kb:.1f} KB)")
                
            return packages_built
            
        except Exception as e:
            from utils.enhanced_logging import get_logger
            logger = get_logger(__name__)
            logger.error(
                f"Failed to build Lambda packages: {str(e)}",
                suggestion="Check that the payloads/lambda directory exists and contains required Lambda source files"
            )
            return packages_built


def main():
    """Command-line interface for Lambda package builder"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Build Lambda deployment packages")
    parser.add_argument("--action", choices=["build", "list", "cleanup", "build-all"], 
                       default="build-all", help="Action to perform")
    parser.add_argument("--name", default="lambda_function", help="Package name")
    parser.add_argument("--enhanced", action="store_true", help="Build enhanced package")
    parser.add_argument("--deps", action="store_true", help="Include dependencies")
    
    args = parser.parse_args()
    
    builder = LambdaPackageBuilder()
    
    if args.action == "build":
        if args.enhanced:
            package = builder.create_enhanced_lambda_package(args.name, args.deps)
        else:
            package = builder.create_basic_lambda_package(args.name)
        print(f"Package created: {package}")
        
    elif args.action == "list":
        packages = builder.list_existing_packages()
        print(f"\nFound {len(packages)} Lambda packages:")
        for package in packages:
            print(f"  - {package['name']} ({package['size_kb']:.1f} KB) - {package['modified']}")
            
    elif args.action == "cleanup":
        builder.cleanup_old_packages()
        
    elif args.action == "build-all":
        builder.build_all_packages()
        

if __name__ == "__main__":
    main()
