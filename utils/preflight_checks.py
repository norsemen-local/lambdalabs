#!/usr/bin/env python3
"""
Pre-flight verification system for AWS Lambda Testing Toolkit
Validates environment before deployment to prevent common issues
"""
import boto3
import subprocess
import sys
import json
import os
import requests
from pathlib import Path
from typing import List, Dict, Tuple
import logging

logger = logging.getLogger(__name__)

class PreflightChecker:
    """Comprehensive environment validation before deployment"""
    
    def __init__(self, aws_manager=None):
        self.aws_manager = aws_manager
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
        
    def run_all_checks(self) -> bool:
        """Run all pre-flight checks and return overall status"""
        print("\n🔍 AWS Lambda Testing Toolkit - Pre-flight Verification")
        print("=" * 60)
        
        checks = [
            ("Python Environment", self._check_python_environment),
            ("AWS Credentials", self._check_aws_credentials),
            ("AWS Permissions", self._check_aws_permissions),
            ("Project Files", self._check_project_files),
            ("Network Connectivity", self._check_network_connectivity),
            ("Existing Resources", self._check_existing_resources),
            ("Cost Estimation", self._check_cost_estimation),
            ("Required Tools", self._check_required_tools)
        ]
        
        for check_name, check_func in checks:
            print(f"Checking {check_name:.<25}", end=" ")
            try:
                if check_func():
                    print("✅ PASS")
                else:
                    print("❌ FAIL")
            except Exception as e:
                print(f"⚠️  ERROR: {e}")
                self.errors.append(f"{check_name}: {e}")
        
        print("=" * 60)
        
        # Display results
        self._display_results()
        
        # Return overall status
        return len(self.errors) == 0
    
    def _check_python_environment(self) -> bool:
        """Validate Python version and required packages"""
        # Check Python version
        if sys.version_info < (3, 7):
            self.errors.append(f"Python 3.7+ required, found {sys.version}")
            return False
        
        # Check required packages
        required_packages = ['boto3', 'requests', 'pathlib']
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            self.errors.append(f"Missing packages: {', '.join(missing_packages)}")
            self.info.append("Run: pip install -r requirements.txt")
            return False
            
        return True
    
    def _check_aws_credentials(self) -> bool:
        """Verify AWS credentials are properly configured"""
        try:
            if self.aws_manager:
                sts = self.aws_manager.session.client('sts')
            else:
                # Fallback to default session
                sts = boto3.client('sts')
            
            identity = sts.get_caller_identity()
            
            account_id = identity.get('Account')
            user_arn = identity.get('Arn')
            
            if account_id:
                self.info.append(f"AWS Account: {account_id}")
                self.info.append(f"Identity: {user_arn}")
                return True
            else:
                self.errors.append("Could not retrieve AWS identity")
                return False
                
        except Exception as e:
            self.errors.append(f"AWS credentials not configured: {e}")
            self.info.append("Run: aws configure")
            return False
    
    def _check_aws_permissions(self) -> bool:
        """Check for critical AWS permissions"""
        required_services = {
            'cloudformation': ['ListStacks', 'CreateStack', 'DeleteStack'],
            'iam': ['ListRoles', 'CreateRole', 'PassRole'],
            'ec2': ['DescribeInstances', 'RunInstances', 'CreateSecurityGroup'],
            'lambda': ['CreateFunction', 'InvokeFunction'],
            's3': ['ListAllMyBuckets', 'CreateBucket']
        }
        
        permission_issues = []
        
        for service, actions in required_services.items():
            try:
                if self.aws_manager:
                    client = self.aws_manager.session.client(service)
                else:
                    client = boto3.client(service)
                
                # Test basic describe/list operations
                if service == 'cloudformation':
                    client.list_stacks(StackStatusFilter=['CREATE_COMPLETE'])
                elif service == 'iam':
                    client.list_roles(MaxItems=1)
                elif service == 'ec2':
                    client.describe_instances(MaxResults=5)
                elif service == 'lambda':
                    client.list_functions(MaxItems=1)
                elif service == 's3':
                    client.list_buckets()
                    
            except Exception as e:
                permission_issues.append(f"{service}: {e}")
        
        if permission_issues:
            self.warnings.extend(permission_issues)
            self.info.append("Some permissions could not be verified - deployment may fail")
        
        return True  # Warnings only, not blocking
    
    def _check_project_files(self) -> bool:
        """Verify required project files exist"""
        required_files = [
            'lambdalabs.py',  # Current main file (updated from main_refactored.py)
            'requirements.txt',
            'utils/aws_utils.py',
            'utils/ssh_utils.py'
        ]
        
        # Check for CloudFormation template (updated locations)
        cf_templates = [
            'templates/lambdalabs_infrastructure.yaml',  # Primary template
            'templates/infra_deploy_parameterized.yaml', # Legacy
            'infra_deploy_unified.yaml',                # Legacy
            'infra_deploy.yaml'                         # Alternative
        ]
        
        cf_found = False
        for template in cf_templates:
            if Path(template).exists():
                cf_found = True
                break
        
        if not cf_found:
            self.errors.append("No CloudFormation template found")
        
        # Check other required files
        missing_files = []
        for file_path in required_files:
            if not Path(file_path).exists():
                missing_files.append(file_path)
        
        if missing_files:
            self.errors.extend([f"Missing file: {f}" for f in missing_files])
            return False
            
        return True
    
    def _check_network_connectivity(self) -> bool:
        """Test network connectivity to required services"""
        test_urls = [
            'https://aws.amazon.com',
            'https://api.ipify.org',
            'https://github.com'
        ]
        
        failed_connections = []
        for url in test_urls:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code != 200:
                    failed_connections.append(f"{url} (HTTP {response.status_code})")
            except Exception as e:
                failed_connections.append(f"{url} ({e})")
        
        if failed_connections:
            self.warnings.extend([f"Network issue: {f}" for f in failed_connections])
        
        return True  # Warnings only
    
    def _check_existing_resources(self) -> bool:
        """Check for existing LambdaLabs resources that might conflict"""
        try:
            # Check CloudFormation stacks
            if self.aws_manager:
                cf = self.aws_manager.session.client('cloudformation')
            else:
                cf = boto3.client('cloudformation')
            
            response = cf.list_stacks(
                StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'CREATE_IN_PROGRESS']
            )
            
            existing_stacks = []
            for stack in response['StackSummaries']:
                stack_name = stack['StackName']
                if 'lambdalabs' in stack_name.lower() or 'lambda-testing' in stack_name.lower():
                    existing_stacks.append(stack_name)
            
            if existing_stacks:
                self.warnings.append(f"Found existing stacks: {', '.join(existing_stacks)}")
                self.info.append("Use cleanup option to remove before deploying new infrastructure")
            
            # Check S3 buckets
            if self.aws_manager:
                s3 = self.aws_manager.session.client('s3')
            else:
                s3 = boto3.client('s3')
            
            buckets = s3.list_buckets()
            
            existing_buckets = []
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                if 'lambdalabs' in bucket_name or 'lambda-testing' in bucket_name:
                    existing_buckets.append(bucket_name)
            
            if existing_buckets:
                self.warnings.append(f"Found existing buckets: {', '.join(existing_buckets[:3])}{'...' if len(existing_buckets) > 3 else ''}")
            
            return True
            
        except Exception as e:
            self.warnings.append(f"Could not check existing resources: {e}")
            return True
    
    def _check_cost_estimation(self) -> bool:
        """Display cost estimation for deployment"""
        try:
            # Simple cost estimation based on known resources
            daily_cost = 0.28
            monthly_cost = daily_cost * 30
            
            self.info.append(f"Estimated daily cost: ${daily_cost:.2f}")
            self.info.append(f"Estimated monthly cost: ${monthly_cost:.2f}")
            self.info.append("Resources: EC2 t2.micro + S3 storage + Lambda executions")
            return True
        except Exception as e:
            self.warnings.append(f"Could not estimate costs: {e}")
            return True
    
    def _check_required_tools(self) -> bool:
        """Check for required command-line tools"""
        required_tools = {
            'curl': 'Required for web shell testing',
            'ssh': 'Required for EC2 instance access',
            'aws': 'AWS CLI for resource management'
        }
        
        missing_tools = []
        for tool, description in required_tools.items():
            try:
                result = subprocess.run(['which', tool], capture_output=True, text=True)
                if result.returncode != 0:
                    missing_tools.append(f"{tool} ({description})")
            except Exception:
                missing_tools.append(f"{tool} ({description})")
        
        if missing_tools:
            self.warnings.extend([f"Missing tool: {tool}" for tool in missing_tools])
        
        return True  # Warnings only
    
    def _display_results(self):
        """Display formatted results of all checks"""
        if self.errors:
            print(f"\n❌ CRITICAL ISSUES ({len(self.errors)}):")
            for error in self.errors:
                print(f"   • {error}")
            print("\n🛠️  Fix these issues before proceeding with deployment")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   • {warning}")
        
        if self.info:
            print(f"\n📋 INFORMATION:")
            for info in self.info:
                print(f"   • {info}")
        
        if not self.errors and not self.warnings:
            print("\n✅ All pre-flight checks passed! Ready for deployment.")
        elif not self.errors:
            print("\n⚠️  Pre-flight checks passed with warnings. Deployment can proceed.")
