#!/usr/bin/env python3
"""
AWS Utilities for Lambda Testing Toolkit
Handles AMI detection, region management, and AWS service interactions
"""
import boto3
import json
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, NoCredentialsError


class AWSManager:
    """Manages AWS operations and service interactions"""
    
    def __init__(self):
        self.session = None
        self.current_region = None
        self.account_id = None
        self._validate_aws_credentials()
        
    def _validate_aws_credentials(self):
        """Validate AWS credentials and get session info"""
        try:
            self.session = boto3.Session()
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            
            self.account_id = identity['Account']
            self.current_region = self.session.region_name or 'us-east-1'
            
            print(f"[INFO] AWS Session initialized")
            print(f"[INFO] Account ID: {self.account_id}")
            print(f"[INFO] Region: {self.current_region}")
            print(f"[INFO] User/Role ARN: {identity['Arn']}")
            
        except NoCredentialsError:
            raise Exception(
                "AWS credentials not found. Please configure AWS CLI:\n"
                "  aws configure\n"
                "Or set environment variables:\n"
                "  export AWS_ACCESS_KEY_ID=your_key\n"
                "  export AWS_SECRET_ACCESS_KEY=your_secret\n"
                "  export AWS_DEFAULT_REGION=us-east-1"
            )
        except Exception as e:
            raise Exception(f"Failed to validate AWS credentials: {str(e)}")
            
    def get_latest_amazon_linux_ami(self, region=None):
        """
        Get the latest Amazon Linux 2 AMI ID for the specified region
        Returns: (ami_id, ami_name, architecture)
        """
        if not region:
            region = self.current_region
            
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            
            # Search for Amazon Linux 2 AMIs
            response = ec2_client.describe_images(
                Owners=['amazon'],
                Filters=[
                    {
                        'Name': 'name',
                        'Values': ['amzn2-ami-hvm-*-x86_64-gp2']
                    },
                    {
                        'Name': 'state',
                        'Values': ['available']
                    },
                    {
                        'Name': 'architecture',
                        'Values': ['x86_64']
                    },
                    {
                        'Name': 'virtualization-type',
                        'Values': ['hvm']
                    }
                ]
            )
            
            if not response['Images']:
                raise Exception(f"No Amazon Linux 2 AMIs found in region {region}")
                
            # Sort by creation date (newest first)
            images = sorted(
                response['Images'],
                key=lambda x: x['CreationDate'],
                reverse=True
            )
            
            latest_ami = images[0]
            ami_id = latest_ami['ImageId']
            ami_name = latest_ami['Name']
            architecture = latest_ami['Architecture']
            
            print(f"[SUCCESS] Latest Amazon Linux 2 AMI in {region}:")
            print(f"[INFO] AMI ID: {ami_id}")
            print(f"[INFO] Name: {ami_name}")
            print(f"[INFO] Architecture: {architecture}")
            print(f"[INFO] Creation Date: {latest_ami['CreationDate']}")
            
            return ami_id, ami_name, architecture
            
        except ClientError as e:
            if 'UnauthorizedOperation' in str(e):
                raise Exception(f"Insufficient permissions to describe images in {region}")
            else:
                raise Exception(f"Failed to get AMI for region {region}: {str(e)}")
        except Exception as e:
            raise Exception(f"Error getting latest AMI: {str(e)}")
            
    def get_available_regions(self):
        """Get list of available AWS regions"""
        try:
            ec2_client = self.session.client('ec2')
            response = ec2_client.describe_regions()
            
            regions = []
            for region in response['Regions']:
                regions.append({
                    'name': region['RegionName'],
                    'endpoint': region['Endpoint'],
                    'opt_in_status': region.get('OptInStatus', 'opt-in-not-required')
                })
                
            return sorted(regions, key=lambda x: x['name'])
            
        except Exception as e:
            raise Exception(f"Failed to get available regions: {str(e)}")
            
    def validate_region(self, region):
        """Validate if a region is available"""
        try:
            available_regions = self.get_available_regions()
            region_names = [r['name'] for r in available_regions]
            
            if region not in region_names:
                from utils.enhanced_logging import get_logger
                logger = get_logger(__name__)
                logger.error(
                    f"Invalid AWS region: {region}",
                    suggestion=f"Choose from available regions: {', '.join(region_names[:10])}"
                )
                return False
                
            return True
            
        except Exception as e:
            print(f"[WARNING] Could not validate region {region}: {str(e)}")
            return True  # Assume valid if we can't check
            
    def estimate_deployment_cost(self):
        """Provide cost estimates for the lab deployment"""
        cost_info = {
            't2.micro': {
                'hourly': 0.0116,
                'daily': 0.2784,
                'monthly': 8.64
            },
            'data_transfer': {
                'gb_out': 0.09,
                'estimated_gb': 1.0
            },
            'ebs_storage': {
                'gb_per_month': 0.10,
                'estimated_gb': 8
            }
        }
        
        print("\n" + "="*60)
        print("💰 ESTIMATED AWS COSTS FOR LAB DEPLOYMENT")
        print("="*60)
        print(f"EC2 t2.micro (per hour): ${cost_info['t2.micro']['hourly']:.4f}")
        print(f"EC2 t2.micro (per day):  ${cost_info['t2.micro']['daily']:.4f}")
        print(f"EC2 t2.micro (30 days):  ${cost_info['t2.micro']['monthly']:.2f}")
        print(f"EBS Storage (8GB/month): ${cost_info['ebs_storage']['gb_per_month'] * cost_info['ebs_storage']['estimated_gb']:.2f}")
        print(f"Data Transfer (~1GB):    ${cost_info['data_transfer']['gb_out'] * cost_info['data_transfer']['estimated_gb']:.2f}")
        print("-" * 50)
        
        total_daily = cost_info['t2.micro']['daily']
        total_monthly = cost_info['t2.micro']['monthly'] + \
                       (cost_info['ebs_storage']['gb_per_month'] * cost_info['ebs_storage']['estimated_gb']) + \
                       (cost_info['data_transfer']['gb_out'] * cost_info['data_transfer']['estimated_gb'])
                       
        print(f"Estimated daily cost:    ${total_daily:.4f}")
        print(f"Estimated monthly cost:  ${total_monthly:.2f}")
        print("=" * 50)
        print("⚠️  Remember to delete resources when testing is complete!")
        print("💡 Use the cleanup option in the main menu to remove all resources")
        
        return {
            'daily': total_daily,
            'monthly': total_monthly,
            'components': cost_info
        }
        
    def check_service_quotas(self):
        """Check relevant AWS service quotas"""
        quotas = {}
        warnings = []
        
        try:
            # Check EC2 quotas
            ec2_client = self.session.client('ec2')
            
            # Get current instance count
            instances = ec2_client.describe_instances()
            current_instances = 0
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] in ['running', 'pending']:
                        current_instances += 1
                        
            quotas['current_instances'] = current_instances
            
            # Get VPC count
            vpcs = ec2_client.describe_vpcs()
            quotas['current_vpcs'] = len(vpcs['Vpcs'])
            
            # Get Security Groups
            sgs = ec2_client.describe_security_groups()
            quotas['current_security_groups'] = len(sgs['SecurityGroups'])
            
            print(f"\n📊 Current AWS Resource Usage:")
            print(f"Running/Pending EC2 Instances: {quotas['current_instances']}")
            print(f"VPCs: {quotas['current_vpcs']}")
            print(f"Security Groups: {quotas['current_security_groups']}")
            
            # Check for potential issues
            if quotas['current_instances'] > 15:
                warnings.append(f"High instance count: {quotas['current_instances']}")
                
            if quotas['current_vpcs'] > 4:
                warnings.append(f"High VPC count: {quotas['current_vpcs']}")
                
        except Exception as e:
            warnings.append(f"Could not check service quotas: {str(e)}")
            
        return quotas, warnings


def test_ami_detection():
    """Test AMI detection functionality"""
    try:
        manager = AWSManager()
        
        # Test current region
        ami_id, ami_name, arch = manager.get_latest_amazon_linux_ami()
        print(f"\nCurrent region AMI: {ami_id}")
        
        # Test different region
        if manager.current_region != 'us-west-2':
            try:
                west_ami_id, west_ami_name, west_arch = manager.get_latest_amazon_linux_ami('us-west-2')
                print(f"us-west-2 AMI: {west_ami_id}")
            except Exception as e:
                print(f"Could not get us-west-2 AMI: {e}")
                
        # Show cost estimates
        manager.estimate_deployment_cost()
        
    except Exception as e:
        print(f"Test failed: {e}")


if __name__ == "__main__":
    test_ami_detection()
