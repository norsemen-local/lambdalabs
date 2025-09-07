# 🛡️ LambdaLabs - AWS Privilege Escalation Lab

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-Educational%20Lab-orange.svg)](https://aws.amazon.com/)
[![Cost](https://img.shields.io/badge/Cost-~$0.28%2Fday-green.svg)](https://github.com/scenelauncher/lamda_testing)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> ⚠️ **Educational Use Only**: Creates intentionally vulnerable AWS infrastructure. Use only in dedicated testing accounts.

**LambdaLabs** simulates a complete AWS privilege escalation attack chain - from web application exploitation to sensitive data theft. Perfect for learning cloud security, IAM misconfigurations, and attack detection.

## 📊 Attack Chain Overview

This lab demonstrates a realistic attack progression exploiting common AWS misconfigurations:

```
┌───────────────────────┐
│  🌐 WEB EXPLOITATION  │
│                       │    📍 **Weak Point**: Struts2 CVE-2017-5638
│   Struts2 App         │    🎯 **Goal**: Code execution via file upload
│   Port 8080           │
└───────────┬───────────┘
            │
            │ Upload malicious JSP shell
            │
            ▼
┌───────────────────────┐
│  🔐 CREDENTIAL ACCESS │
│                       │    📍 **Weak Point**: EC2 Metadata Service
│   EC2 Instance        │    🎯 **Goal**: Extract IAM role credentials
│   (Web Shell)         │
└───────────┬───────────┘
            │
            │ curl 169.254.169.254/latest/meta-data/iam/...
            │
            ▼
┌───────────────────────┐
│  ⚙️ LAMBDA ESCALATION │
│                       │    📍 **Weak Point**: iam:PassRole permission
│   Lambda Creation     │    🎯 **Goal**: Assume higher-privilege role
│   (Higher Role)       │
└───────────┬───────────┘
            │
            │ Create Lambda with DevTeam-Group-Role
            │ 
            ▼
┌───────────────────────┐
│  📁 DATA EXFILTRATION │
│                       │    📍 **Weak Point**: Overprivileged S3 access
│   S3 Buckets Access   │    🎯 **Goal**: Extract sensitive data
│   (Sensitive Data)    │
└───────────────────────┘
```

**Key Misconfigurations Exploited:**
- 🔴 **EC2 Role** has `lambda:CreateFunction` + `iam:PassRole`
- 🔴 **Lambda Role** has broad S3 and IAM permissions
- 🔴 **Security Groups** allow unrestricted application access
- 🔴 **Metadata Service** accessible from compromised application

## 🚀 Quick Start

### ✅ Prerequisites Checklist

- [ ] **AWS Account**: Dedicated testing account (never production!)
- [ ] **AWS CLI**: Installed and configured (`aws configure`)
- [ ] **Python 3.7+**: With pip package manager
- [ ] **Git**: For cloning the repository
- [ ] **~$10/month budget**: For AWS resources during testing

### 📦 Installation (5 minutes)

1. **Clone and Enter Repository**
   ```bash
   git clone https://github.com/scenelauncher/lamda_testing.git
   cd lamda_testing
   ```

2. **Set Up Python Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Verify AWS Configuration**
   ```bash
   aws sts get-caller-identity
   # Should return your AWS account ID and user info
   ```

### 🎯 Complete Attack Chain (15 minutes)

**Launch the toolkit and follow the guided menu:**

```bash
python3 lambdalabs.py
```

**Recommended first-time flow:**

1. **[1] Deploy Infrastructure** → Creates vulnerable AWS environment
2. **[2] Build Lambda Packages** → Prepares attack tools  
3. **[3] Populate S3 Data** → Adds synthetic target data
4. **[4] Upload Web Shell** → Deploys JSP backdoor
5. **[6] Extract Credentials** → Harvests EC2 IAM credentials
6. **[7] Verify Identity** → Confirms credential validity
7. **[8] Lambda Escalation** → Privilege escalation attack
8. **[9] S3 Exploitation** → Data exfiltration demo
9. **[10] Cleanup** → Removes all AWS resources

> 💡 **Pro Tip**: Each menu option includes built-in guidance and confirmations. The toolkit will automatically detect your IP address and configure security groups.

### 🧹 Essential Cleanup

**Always run cleanup when finished:**

```bash
# Option 1: Use menu option [10] in lambdalabs.py
# Option 2: Use cleanup script directly
bash tools/cleanup_all.sh
```

## 📚 Learn More

For detailed information, advanced usage, and troubleshooting:

- **📖 Technical Details**: See [ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **⚙️ Advanced Configuration**: See [ADVANCED.md](docs/ADVANCED.md)  
- **🔍 Troubleshooting**: See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- **💰 Cost Management**: See [COSTS.md](docs/COSTS.md)
- **🛡️ Security Features**: See [SECURITY.md](docs/SECURITY.md)

## 📄 License

MIT License - see LICENSE file for details.

---

**Remember**: This creates intentionally vulnerable infrastructure. Use responsibly in dedicated testing environments only.
