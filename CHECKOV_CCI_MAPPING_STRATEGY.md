# Checkov to CCI Mapping Strategy

## Overview
Checkov maintains 7,971+ security policies across multiple cloud providers and frameworks. Mapping all of these to CCIs requires a systematic approach.

## Current Status
✅ **198 AWS rules mapped** (CKV_AWS_*)
✅ **49 Azure rules mapped** (CKV_AZURE_*)
✅ **31 GCP rules mapped** (CKV_GCP_*)
✅ **45 Kubernetes rules mapped** (CKV_K8S_*)
✅ **44 Alibaba Cloud rules mapped** (CKV_ALI_*)
✅ **11 Docker rules mapped** (CKV_DOCKER_*)
✅ **5 GitHub Actions rules mapped** (CKV_GHA_*)
✅ **12 Ansible rules mapped** (CKV_ANSIBLE_*, CKV2_ANSIBLE_*)
✅ **2 Argo Workflow rules mapped** (CKV_ARGO_*)
⏳ **Remaining: ~7,574 rules** across other providers and frameworks

**Total Mapped: 397 rules (5% of 7,971 total rules)**

## Breakdown by Category

### Cloud Providers
- **AWS** (CKV_AWS_*): ~500+ rules
- **Azure** (CKV_AZURE_*, CKV2_AZURE_*): ~800+ rules
- **GCP** (CKV_GCP_*, CKV2_GCP_*): ~400+ rules
- **Alibaba Cloud** (CKV_ALI_*): ~45 rules
- **Oracle Cloud** (CKV_OCI_*): ~100+ rules
- **IBM Cloud** (CKV_IBM_*): ~50+ rules

### Frameworks & Technologies
- **Kubernetes** (CKV_K8S_*, CKV2_K8S_*): ~300+ rules
- **Docker** (CKV_DOCKER_*): ~50+ rules
- **GitHub Actions** (CKV_GHA_*): ~20+ rules
- **GitLab** (CKV_GLR_*, CKV_GITLABCI_*): ~30+ rules
- **Bitbucket** (CKV_BITBUCKET_*): ~10+ rules
- **OpenStack** (CKV_OPENSTACK_*): ~40+ rules

### Configuration Management
- **Ansible** (CKV_ANSIBLE_*, CKV2_ANSIBLE_*): ~10+ rules
- **Argo Workflows** (CKV_ARGO_*): ~5+ rules
- **Terraform** (various): embedded in cloud rules

### Supply Chain & Secrets
- **Supply Chain** (CKV2_*): ~100+ rules
- **Secrets Detection**: embedded across frameworks
- **SAST findings**: ~5,000+ language-specific rules

## CCI Mapping Categories

### High-Level CCI Groupings

#### Access Control (AC Family)
- **AC-2**: Account Management
- **AC-3**: Access Enforcement
- **AC-4**: Information Flow Enforcement
- **AC-6**: Least Privilege
- **AC-17**: Remote Access

#### Identification & Authentication (IA Family)
- **IA-2**: Identification and Authentication
- **IA-5**: Authenticator Management
- **IA-8**: Identification and Authentication (Non-Organizational Users)

#### Audit & Accountability (AU Family)
- **AU-2**: Audit Events
- **AU-3**: Content of Audit Records
- **AU-6**: Audit Review, Analysis, and Reporting
- **AU-9**: Protection of Audit Information
- **AU-12**: Audit Generation

#### System & Communications Protection (SC Family)
- **SC-7**: Boundary Protection
- **SC-8**: Transmission Confidentiality and Integrity
- **SC-13**: Cryptographic Protection
- **SC-23**: Session Authenticity
- **SC-28**: Protection of Information at Rest

#### Configuration Management (CM Family)
- **CM-2**: Baseline Configuration
- **CM-5**: Access Restrictions for Change
- **CM-6**: Configuration Settings
- **CM-7**: Least Functionality
- **CM-8**: Information System Component Inventory

#### Contingency Planning (CP Family)
- **CP-9**: Information System Backup
- **CP-10**: Information System Recovery and Reconstitution

#### Risk Assessment (RA Family)
- **RA-5**: Vulnerability Scanning

#### System & Services Acquisition (SA Family)
- **SA-11**: Developer Security Testing and Evaluation

#### System & Information Integrity (SI Family)
- **SI-2**: Flaw Remediation
- **SI-4**: Information System Monitoring
- **SI-10**: Information Input Validation

## Common CCI Mappings by Rule Type

### Encryption Rules → SC-28, SC-13
```typescript
CCIs: ['CCI-001199', 'CCI-002475'] // SC-28, SC-28(1)
```

### Logging/Monitoring Rules → AU-2, AU-3, AU-12
```typescript
CCIs: ['CCI-000172', 'CCI-001464'] // AU-12, AU-2
```

### Access Control Rules → AC-3, AC-6
```typescript
CCIs: ['CCI-000213', 'CCI-001368'] // AC-3, AC-4
```

### Network Security Rules → SC-7, AC-4
```typescript
CCIs: ['CCI-001097', 'CCI-002403'] // SC-7, SC-8
```

### Password Policy Rules → IA-5
```typescript
CCIs: ['CCI-000764', 'CCI-001941'] // IA-5(1)
```

### TLS/HTTPS Rules → SC-8, SC-23
```typescript
CCIs: ['CCI-002418', 'CCI-002420'] // SC-8(1)
```

### Backup/Recovery Rules → CP-9, CP-10
```typescript
CCIs: ['CCI-000537', 'CCI-001876'] // CP-9, CP-10
```

### Vulnerability Scanning → RA-5, SA-11
```typescript
CCIs: ['CCI-001643', 'CCI-003173'] // RA-5, SA-11
```

### IAM/Authentication → IA-2, AC-2
```typescript
CCIs: ['CCI-000764', 'CCI-001941'] // IA-2, IA-5
```

## Implementation Approach

### Phase 1: Core Cloud Providers (IN PROGRESS)
✅ AWS (CKV_AWS_*): 198 rules mapped (baseline complete)
✅ Azure (CKV_AZURE_*): 49 rules mapped (baseline complete)
✅ GCP (CKV_GCP_*): 31 rules mapped (baseline complete)
⏳ Need expansion: AWS CKV_AWS_231-500+, Azure +750 rules, GCP +370 rules

### Phase 2: Kubernetes & Container Security (BASELINE COMPLETE)
✅ Kubernetes (CKV_K8S_*): 45 rules mapped (baseline complete)
✅ Docker (CKV_DOCKER_*): 11 rules mapped (baseline complete)
⏳ Need expansion: K8s +255 rules, Docker +39 rules

### Phase 3: Version 2 Rules (Advanced Checks)
⏳ CKV2_AWS_*: TBD
⏳ CKV2_AZURE_*: TBD
⏳ CKV2_GCP_*: TBD

### Phase 4: Additional Platforms (PARTIALLY COMPLETE)
✅ Alibaba Cloud (CKV_ALI_*): 44 rules mapped (complete)
⏳ Oracle Cloud (CKV_OCI_*): 0 rules mapped
⏳ OpenStack (CKV_OPENSTACK_*): 0 rules mapped

### Phase 5: DevOps & CI/CD (BASELINE COMPLETE)
✅ GitHub Actions (CKV_GHA_*): 5 rules mapped (baseline complete)
✅ Ansible (CKV_ANSIBLE_*, CKV2_ANSIBLE_*): 12 rules mapped (complete)
✅ Argo Workflows (CKV_ARGO_*): 2 rules mapped (complete)
⏳ GitLab (CKV_GLR_*, CKV_GITLABCI_*): 0 rules mapped
⏳ Bitbucket (CKV_BITBUCKET_*): 0 rules mapped
⏳ Need expansion: GitHub Actions +15 rules

## Automated Mapping Strategy

### Rule Pattern Recognition
Many Checkov rules follow patterns that can be automatically categorized:

1. **Encryption patterns** (contains "encrypt", "kms", "ssl", "tls"):
   - Map to SC-28, SC-13 CCIs

2. **Logging patterns** (contains "log", "audit", "monitoring"):
   - Map to AU-2, AU-3, AU-12 CCIs

3. **Public access patterns** (contains "public", "0.0.0.0", "internet"):
   - Map to AC-3, SC-7 CCIs

4. **Authentication patterns** (contains "iam", "auth", "mfa", "password"):
   - Map to IA-2, IA-5, AC-2 CCIs

5. **Backup patterns** (contains "backup", "snapshot", "retention"):
   - Map to CP-9, CP-10 CCIs

## Next Steps

### Option 1: Incremental Manual Mapping
Continue manually mapping rules by cloud provider, prioritizing most commonly used services.

### Option 2: Automated Classification
Build a script that:
1. Fetches all Checkov rule descriptions from the API/docs
2. Uses keyword matching to suggest CCI mappings
3. Generates mapping file for human review
4. Iteratively refine classifications

### Option 3: Community Contribution
1. Publish current mappings to GitHub
2. Create contribution guidelines
3. Accept PRs for additional mappings
4. Maintain central registry

## Resources

- [Checkov Policy Index](https://www.checkov.io/5.Policy%20Index/all.html)
- [CCI List](https://csrc.nist.gov/projects/control-correlation-identifier)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Checkov GitHub](https://github.com/bridgecrewio/checkov)

## Contributing New Mappings

To add new rule mappings:

1. Research the Checkov rule purpose
2. Identify the primary security control (encryption, logging, access, etc.)
3. Look up corresponding NIST 800-53 control
4. Find CCIs for that control in CciNistMappingData.ts
5. Add mapping to CheckovCciMappingData.ts
6. Update documentation

### Example:
```typescript
// New Azure rule for encryption
'CKV_AZURE_1': ['CCI-001199', 'CCI-002475'], // Storage encryption
```
