#!/bin/bash

# Validate AWS credentials are configured
if [ -z "$AWS_ACCESS_KEY_ID" ] && [ -z "$AWS_PROFILE" ]; then
    echo "❌ ERROR: AWS credentials not configured"
    echo "📋 Please run one of the following:"
    echo "   aws configure"
    echo "   export AWS_PROFILE=your-profile"
    echo "   export AWS_ACCESS_KEY_ID=... && export AWS_SECRET_ACCESS_KEY=..."
    exit 1
fi

echo "✅ AWS credentials detected, proceeding with cleanup..."

# Test credentials
aws sts get-caller-identity > /dev/null
if [ $? -ne 0 ]; then
    echo "❌ ERROR: Invalid AWS credentials"
    exit 1
fi

# Set default region if not specified
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}

echo "Starting comprehensive cleanup of all resources..."

# 1. Delete failed CloudFormation stacks
echo "Deleting CloudFormation stacks..."
aws cloudformation delete-stack --stack-name LambdaTestingSimple 2>/dev/null || true
aws cloudformation delete-stack --stack-name LambdaTestingDemo 2>/dev/null || true
aws cloudformation delete-stack --stack-name LambdaTestingToolkit-S3 2>/dev/null || true
aws cloudformation delete-stack --stack-name LambdaTestingToolkit-S3Demo 2>/dev/null || true

# 2. Delete EC2 KeyPair
echo "Deleting EC2 KeyPair: dev-team-key-pair..."
aws ec2 delete-key-pair --key-name dev-team-key-pair 2>/dev/null || true

# 3. Delete IAM UserToGroupAddition (handled by removing user from group)
echo "Removing users from groups..."
aws iam remove-user-from-group --user-name DevTeamDeveloper --group-name DevTeamIAMGroup 2>/dev/null || true

# 4. Delete IAM User
echo "Deleting IAM User: DevTeamDeveloper..."
aws iam delete-user --user-name DevTeamDeveloper 2>/dev/null || true

# 5. Delete IAM Group  
echo "Deleting IAM Group: DevTeamIAMGroup..."
aws iam delete-group --group-name DevTeamIAMGroup 2>/dev/null || true

# 6. Delete IAM Role policies first, then roles
echo "Deleting IAM Role: DevTeam_Group_Role..."
aws iam delete-role-policy --role-name DevTeam_Group_Role --policy-name DevTeamLambdaPolicy 2>/dev/null || true
aws iam delete-role --role-name DevTeam_Group_Role 2>/dev/null || true

echo "Deleting IAM Role: DevTeam_EC2_Role..."
aws iam delete-role-policy --role-name DevTeam_EC2_Role --policy-name DevTeam_EC2_Policy 2>/dev/null || true

# 7. Delete Instance Profile (must remove role first)
echo "Deleting Instance Profile: DevTeamInstanceProfile..."
aws iam remove-role-from-instance-profile --instance-profile-name DevTeamInstanceProfile --role-name DevTeam_EC2_Role 2>/dev/null || true
aws iam delete-instance-profile --instance-profile-name DevTeamInstanceProfile 2>/dev/null || true

# Now delete the EC2 role
aws iam delete-role --role-name DevTeam_EC2_Role 2>/dev/null || true

# 8. Delete Security Group (find and delete)
echo "Deleting Security Group: DevTeamSecurityGroup..."
SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=DevTeamSecurityGroup" --query "SecurityGroups[0].GroupId" --output text 2>/dev/null)
if [ "$SG_ID" != "None" ] && [ ! -z "$SG_ID" ]; then
    aws ec2 delete-security-group --group-id $SG_ID 2>/dev/null || true
fi

# 9. Terminate any EC2 instances with our tags
echo "Terminating EC2 instances with tag owner=dev-team..."
INSTANCE_IDS=$(aws ec2 describe-instances --filters "Name=tag:owner,Values=dev-team" "Name=instance-state-name,Values=running,stopped" --query "Reservations[].Instances[].InstanceId" --output text 2>/dev/null)
if [ ! -z "$INSTANCE_IDS" ]; then
    aws ec2 terminate-instances --instance-ids $INSTANCE_IDS 2>/dev/null || true
    echo "Waiting for instances to terminate..."
    aws ec2 wait instance-terminated --instance-ids $INSTANCE_IDS 2>/dev/null || true
fi

echo "Cleanup complete!"
