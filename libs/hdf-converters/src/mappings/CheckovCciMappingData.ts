// CCI mappings for Checkov/Bridgecrew rules
// Maps Checkov rule IDs to their corresponding CCI (Control Correlation Identifier) values
// Reference: https://www.checkov.io/5.Policy%20Index/all.html
//
// CURRENT COVERAGE:
// - AWS (CKV_AWS_*): 198 rules mapped
// - Azure (CKV_AZURE_*): 49 rules mapped
// - GCP (CKV_GCP_*): 31 rules mapped
// - Kubernetes (CKV_K8S_*): 45 rules mapped
// - Alibaba Cloud (CKV_ALI_*): 44 rules mapped
// - Docker (CKV_DOCKER_*): 11 rules mapped
// - GitHub Actions (CKV_GHA_*): 5 rules mapped
// - Ansible (CKV_ANSIBLE_*, CKV2_ANSIBLE_*): 12 rules mapped
// - Argo Workflows (CKV_ARGO_*): 2 rules mapped
//
// Total: 397 rules mapped out of 7,971+ Checkov rules (~5%)
// See CHECKOV_CCI_MAPPING_STRATEGY.md for expansion roadmap
//
export const data: Record<string, string[]> = {
  // ============================================================================
  // IAM POLICIES & ACCESS MANAGEMENT (AC-2, AC-3, AC-6)
  // ============================================================================
  'CKV_AWS_1': ['CCI-000213', 'CCI-002235'], // IAM full admin privileges
  'CKV_AWS_40': ['CCI-000213', 'CCI-001403'], // IAM policies to groups/roles only
  'CKV_AWS_49': ['CCI-000213', 'CCI-002235'], // IAM wildcard actions prevention
  'CKV_AWS_60': ['CCI-000213', 'CCI-001403'], // IAM role assumption restrictions
  'CKV_AWS_61': ['CCI-000213', 'CCI-001403'], // Cross-service role assumption
  'CKV_AWS_62': ['CCI-000213', 'CCI-002235'], // IAM admin-level policies
  'CKV_AWS_63': ['CCI-000213', 'CCI-002235'], // IAM wildcard actions
  'CKV_AWS_107': ['CCI-000213', 'CCI-001403'], // IAM credential exposure prevention
  'CKV_AWS_108': ['CCI-000213', 'CCI-001403'], // IAM data exfiltration prevention
  'CKV_AWS_109': ['CCI-000213', 'CCI-001403'], // IAM unauthorized permissions
  'CKV_AWS_110': ['CCI-000213', 'CCI-001403'], // IAM privilege escalation prevention
  'CKV_AWS_111': ['CCI-000213', 'CCI-001403'], // IAM unrestricted write access

  // ============================================================================
  // IAM PASSWORD POLICY (IA-5, AC-2)
  // ============================================================================
  'CKV_AWS_9': ['CCI-000764', 'CCI-001941'], // Password expiration 90 days
  'CKV_AWS_10': ['CCI-000764', 'CCI-001941'], // Password min length 14
  'CKV_AWS_11': ['CCI-000764', 'CCI-001941'], // Password lowercase required
  'CKV_AWS_12': ['CCI-000764', 'CCI-001941'], // Password numbers required
  'CKV_AWS_13': ['CCI-000764', 'CCI-001941'], // Password reuse prevention
  'CKV_AWS_14': ['CCI-000764', 'CCI-001941'], // Password symbols required
  'CKV_AWS_15': ['CCI-000764', 'CCI-001941'], // Password uppercase required

  // ============================================================================
  // ENCRYPTION AT REST - STORAGE (SC-28, SC-13)
  // ============================================================================
  'CKV_AWS_3': ['CCI-001199', 'CCI-002475'], // EBS encryption
  'CKV_AWS_4': ['CCI-001199', 'CCI-002475'], // EBS snapshot encryption
  'CKV_AWS_8': ['CCI-001199', 'CCI-002475'], // Launch config EBS encryption
  'CKV_AWS_79': ['CCI-001199', 'CCI-002475'], // Disable EC2 IMDSv1
  'CKV_AWS_106': ['CCI-001199', 'CCI-002475'], // EBS default encryption
  'CKV_AWS_135': ['CCI-001199', 'CCI-002475'], // EC2 EBS optimization
  'CKV_AWS_183': ['CCI-001199', 'CCI-002475'], // EBS snapshot copy encryption KMS
  'CKV_AWS_189': ['CCI-001199', 'CCI-002475'], // EBS volume encryption KMS CMK

  // ============================================================================
  // ENCRYPTION AT REST - DATABASES (SC-28, SC-13)
  // ============================================================================
  'CKV_AWS_16': ['CCI-001199', 'CCI-002475'], // RDS encryption
  'CKV_AWS_17': ['CCI-000213', 'CCI-001368'], // RDS not publicly accessible
  'CKV_AWS_44': ['CCI-001199', 'CCI-002475'], // Neptune storage encryption
  'CKV_AWS_64': ['CCI-001199', 'CCI-002475'], // Redshift encryption
  'CKV_AWS_74': ['CCI-001199', 'CCI-002475'], // DocumentDB encryption
  'CKV_AWS_87': ['CCI-000213', 'CCI-001368'], // Redshift not public
  'CKV_AWS_96': ['CCI-001199', 'CCI-002475'], // Aurora encryption
  'CKV_AWS_102': ['CCI-000213', 'CCI-001368'], // Neptune not publicly available
  'CKV_AWS_118': ['CCI-001312', 'CCI-001314'], // RDS enhanced monitoring
  'CKV_AWS_119': ['CCI-001199', 'CCI-002475'], // DynamoDB KMS CMK encryption
  'CKV_AWS_129': ['CCI-000172', 'CCI-001464'], // RDS logging enabled
  'CKV_AWS_133': ['CCI-000537', 'CCI-001876'], // RDS backup policy
  'CKV_AWS_139': ['CCI-001199', 'CCI-002475'], // RDS cluster deletion protection
  'CKV_AWS_140': ['CCI-001199', 'CCI-002475'], // RDS global cluster encryption
  'CKV_AWS_141': ['CCI-001199', 'CCI-002475'], // Redshift version upgrades
  'CKV_AWS_142': ['CCI-001199', 'CCI-002475'], // Redshift KMS encryption
  'CKV_AWS_146': ['CCI-001199', 'CCI-002475'], // RDS cluster snapshot encryption
  'CKV_AWS_157': ['CCI-000537', 'CCI-001876'], // RDS Multi-AZ
  'CKV_AWS_161': ['CCI-000764', 'CCI-001941'], // RDS IAM authentication
  'CKV_AWS_162': ['CCI-000764', 'CCI-001941'], // RDS cluster IAM authentication
  'CKV_AWS_182': ['CCI-001199', 'CCI-002475'], // DocumentDB KMS CMK encryption
  'CKV_AWS_211': ['CCI-001199', 'CCI-002475'], // RDS modern CaCert
  'CKV_AWS_226': ['CCI-001199', 'CCI-002475'], // RDS auto minor upgrades

  // ============================================================================
  // ENCRYPTION AT REST - S3 (SC-28, SC-13)
  // ============================================================================
  'CKV_AWS_18': ['CCI-000172', 'CCI-001464'], // S3 access logging
  'CKV_AWS_19': ['CCI-001199', 'CCI-002475'], // S3 encryption
  'CKV_AWS_20': ['CCI-000213', 'CCI-001813'], // S3 public READ ACL
  'CKV_AWS_21': ['CCI-000213', 'CCI-000186'], // S3 versioning
  'CKV_AWS_53': ['CCI-000213', 'CCI-001368'], // S3 block public ACLs
  'CKV_AWS_54': ['CCI-000213', 'CCI-001368'], // S3 block public policy
  'CKV_AWS_55': ['CCI-000213', 'CCI-001368'], // S3 ignore public ACLs
  'CKV_AWS_56': ['CCI-000213', 'CCI-001368'], // S3 restrict public buckets
  'CKV_AWS_57': ['CCI-000213', 'CCI-000186'], // S3 public WRITE ACL
  'CKV_AWS_70': ['CCI-000213', 'CCI-001368'], // S3 policy wildcard principal
  'CKV_AWS_93': ['CCI-000213', 'CCI-001368'], // S3 root account lockout prevention
  'CKV_AWS_143': ['CCI-001199', 'CCI-002475'], // S3 object lock
  'CKV_AWS_144': ['CCI-000213', 'CCI-001368'], // S3 cross-region replication
  'CKV_AWS_145': ['CCI-001199', 'CCI-002475'], // S3 KMS encryption default
  'CKV_AWS_181': ['CCI-001199', 'CCI-002475'], // S3 object copy KMS encryption
  'CKV_AWS_186': ['CCI-001199', 'CCI-002475'], // S3 object KMS CMK encryption

  // ============================================================================
  // ENCRYPTION AT REST - ELASTICSEARCH/OPENSEARCH (SC-28, SC-13)
  // ============================================================================
  'CKV_AWS_5': ['CCI-001199', 'CCI-002475'], // Elasticsearch encryption
  'CKV_AWS_6': ['CCI-001199', 'CCI-002475'], // Elasticsearch node-to-node encryption
  'CKV_AWS_83': ['CCI-002418', 'CCI-002420'], // Elasticsearch HTTPS
  'CKV_AWS_84': ['CCI-000172', 'CCI-001464'], // Elasticsearch logging
  'CKV_AWS_137': ['CCI-001097', 'CCI-002403'], // Elasticsearch in VPC
  'CKV_AWS_228': ['CCI-002418', 'CCI-002420'], // Elasticsearch TLS policy

  // ============================================================================
  // ENCRYPTION AT REST - OTHER SERVICES (SC-28, SC-13)
  // ============================================================================
  'CKV_AWS_7': ['CCI-001199', 'CCI-002475'], // KMS key rotation
  'CKV_AWS_22': ['CCI-001199', 'CCI-002475'], // SageMaker KMS encryption
  'CKV_AWS_26': ['CCI-001199', 'CCI-002475'], // SNS encryption
  'CKV_AWS_27': ['CCI-001199', 'CCI-002475'], // SQS encryption
  'CKV_AWS_29': ['CCI-001199', 'CCI-002475'], // ElastiCache encryption at rest
  'CKV_AWS_42': ['CCI-001199', 'CCI-002475'], // EFS encryption
  'CKV_AWS_43': ['CCI-001199', 'CCI-002475'], // Kinesis stream encryption
  'CKV_AWS_47': ['CCI-001199', 'CCI-002475'], // DAX encryption
  'CKV_AWS_77': ['CCI-001199', 'CCI-002475'], // Athena database encryption
  'CKV_AWS_78': ['CCI-001199', 'CCI-002475'], // CodeBuild encryption
  'CKV_AWS_82': ['CCI-001199', 'CCI-002475'], // Athena workgroup encryption
  'CKV_AWS_94': ['CCI-001199', 'CCI-002475'], // Glue data catalog encryption
  'CKV_AWS_97': ['CCI-001199', 'CCI-002475'], // ECS EFS volume encryption
  'CKV_AWS_98': ['CCI-001199', 'CCI-002475'], // SageMaker endpoint encryption
  'CKV_AWS_99': ['CCI-001199', 'CCI-002475'], // Glue security config encryption
  'CKV_AWS_134': ['CCI-000537', 'CCI-001876'], // ElastiCache Redis backup
  'CKV_AWS_136': ['CCI-001199', 'CCI-002475'], // ECR KMS encryption
  'CKV_AWS_147': ['CCI-001199', 'CCI-002475'], // CodeBuild CMK encryption
  'CKV_AWS_149': ['CCI-001199', 'CCI-002475'], // Secrets Manager KMS CMK
  'CKV_AWS_155': ['CCI-001199', 'CCI-002475'], // Workspace user volume encryption
  'CKV_AWS_156': ['CCI-001199', 'CCI-002475'], // Workspace root volume encryption
  'CKV_AWS_158': ['CCI-001199', 'CCI-002475'], // CloudWatch log KMS encryption
  'CKV_AWS_159': ['CCI-001199', 'CCI-002475'], // Athena workgroup encryption
  'CKV_AWS_160': ['CCI-001199', 'CCI-002475'], // Timestream KMS CMK
  'CKV_AWS_166': ['CCI-001199', 'CCI-002475'], // Backup vault KMS CMK
  'CKV_AWS_171': ['CCI-001199', 'CCI-002475'], // EMR SSE-KMS encryption
  'CKV_AWS_173': ['CCI-001199', 'CCI-002475'], // Lambda env var encryption
  'CKV_AWS_177': ['CCI-001199', 'CCI-002475'], // Kinesis video KMS CMK
  'CKV_AWS_178': ['CCI-001199', 'CCI-002475'], // FSX ONTAP KMS CMK
  'CKV_AWS_179': ['CCI-001199', 'CCI-002475'], // FSX Windows KMS CMK
  'CKV_AWS_180': ['CCI-001199', 'CCI-002475'], // Image Builder KMS CMK
  'CKV_AWS_184': ['CCI-001199', 'CCI-002475'], // EFS KMS CMK encryption
  'CKV_AWS_185': ['CCI-001199', 'CCI-002475'], // Kinesis KMS CMK
  'CKV_AWS_187': ['CCI-001199', 'CCI-002475'], // SageMaker KMS CMK
  'CKV_AWS_190': ['CCI-001199', 'CCI-002475'], // Lustre KMS CMK
  'CKV_AWS_191': ['CCI-001199', 'CCI-002475'], // ElastiCache KMS CMK
  'CKV_AWS_199': ['CCI-001199', 'CCI-002475'], // Image Builder AMI KMS CMK
  'CKV_AWS_200': ['CCI-001199', 'CCI-002475'], // Image recipe EBS KMS CMK
  'CKV_AWS_201': ['CCI-001199', 'CCI-002475'], // MemoryDB KMS CMK
  'CKV_AWS_203': ['CCI-001199', 'CCI-002475'], // FSX OpenZFS KMS CMK
  'CKV_AWS_204': ['CCI-001199', 'CCI-002475'], // AMI KMS CMK encryption
  'CKV_AWS_209': ['CCI-001199', 'CCI-002475'], // MQ broker KMS CMK
  'CKV_AWS_212': ['CCI-001199', 'CCI-002475'], // DMS replication KMS CMK
  'CKV_AWS_214': ['CCI-001199', 'CCI-002475'], // AppSync API cache encryption at rest
  'CKV_AWS_219': ['CCI-001199', 'CCI-002475'], // CodePipeline artifact KMS CMK
  'CKV_AWS_221': ['CCI-001199', 'CCI-002475'], // CodeArtifact domain KMS CMK
  'CKV_AWS_227': ['CCI-001199', 'CCI-002475'], // KMS key enabled

  // ============================================================================
  // ENCRYPTION IN TRANSIT (SC-8, SC-23)
  // ============================================================================
  'CKV_AWS_2': ['CCI-002418', 'CCI-002420'], // ALB HTTPS
  'CKV_AWS_30': ['CCI-002418', 'CCI-002420'], // ElastiCache in-transit encryption
  'CKV_AWS_31': ['CCI-002418', 'CCI-002420'], // ElastiCache auth token
  'CKV_AWS_34': ['CCI-002418', 'CCI-002420'], // CloudFront HTTPS
  'CKV_AWS_80': ['CCI-000172', 'CCI-001464'], // MSK cluster logging
  'CKV_AWS_81': ['CCI-002418', 'CCI-002420'], // MSK encryption in transit
  'CKV_AWS_90': ['CCI-002418', 'CCI-002420'], // DocumentDB TLS
  'CKV_AWS_103': ['CCI-002418', 'CCI-002420'], // Load balancer TLS 1.2
  'CKV_AWS_105': ['CCI-002418', 'CCI-002420'], // Redshift SSL
  'CKV_AWS_127': ['CCI-002418', 'CCI-002420'], // ELB ACM certificates
  'CKV_AWS_131': ['CCI-002418', 'CCI-002420'], // ALB drops HTTP headers
  'CKV_AWS_174': ['CCI-002418', 'CCI-002420'], // CloudFront TLS 1.2+
  'CKV_AWS_202': ['CCI-002418', 'CCI-002420'], // MemoryDB in-transit encryption
  'CKV_AWS_213': ['CCI-002418', 'CCI-002420'], // ELB secure protocols
  'CKV_AWS_215': ['CCI-002418', 'CCI-002420'], // AppSync cache encryption in transit
  'CKV_AWS_218': ['CCI-002418', 'CCI-002420'], // CloudSearch TLS
  'CKV_AWS_220': ['CCI-002418', 'CCI-002420'], // CloudSearch HTTPS

  // ============================================================================
  // NETWORK SECURITY & ACCESS CONTROL (SC-7, AC-4)
  // ============================================================================
  'CKV_AWS_23': ['CCI-001097', 'CCI-002403'], // Security group descriptions
  'CKV_AWS_24': ['CCI-001097', 'CCI-002403'], // Security group SSH 0.0.0.0/0
  'CKV_AWS_25': ['CCI-001097', 'CCI-002403'], // Security group RDP 0.0.0.0/0
  'CKV_AWS_38': ['CCI-001097', 'CCI-002403'], // EKS public endpoint CIDR
  'CKV_AWS_39': ['CCI-001097', 'CCI-002403'], // EKS public endpoint disabled
  'CKV_AWS_69': ['CCI-000213', 'CCI-001368'], // MQ broker not public
  'CKV_AWS_88': ['CCI-000213', 'CCI-001368'], // EC2 without public IP
  'CKV_AWS_89': ['CCI-000213', 'CCI-001368'], // DMS not publicly accessible
  'CKV_AWS_100': ['CCI-001097', 'CCI-002403'], // EKS node group SSH restriction
  'CKV_AWS_130': ['CCI-000213', 'CCI-001368'], // VPC subnets no auto-assign public IP
  'CKV_AWS_148': ['CCI-001097', 'CCI-002403'], // Prevent default VPC
  'CKV_AWS_154': ['CCI-001097', 'CCI-002403'], // Redshift not EC2 classic
  'CKV_AWS_164': ['CCI-000213', 'CCI-001368'], // Transfer server not public
  'CKV_AWS_229': ['CCI-001097', 'CCI-002403'], // NACL no unrestricted FTP port 21
  'CKV_AWS_230': ['CCI-001097', 'CCI-002403'], // NACL no unrestricted FTP port 20

  // ============================================================================
  // CONTAINER & ORCHESTRATION (AC-6, SC-4)
  // ============================================================================
  'CKV_AWS_51': ['CCI-000213', 'CCI-001368'], // ECR image immutability
  'CKV_AWS_58': ['CCI-001199', 'CCI-002475'], // EKS secrets encryption
  'CKV_AWS_65': ['CCI-001312', 'CCI-001314'], // ECS container insights
  'CKV_AWS_163': ['CCI-001643', 'CCI-003173'], // ECR image scanning
  'CKV_AWS_210': ['CCI-000213', 'CCI-001368'], // Batch job non-privileged
  'CKV_AWS_223': ['CCI-000172', 'CCI-001464'], // ECS Exec logging
  'CKV_AWS_224': ['CCI-001199', 'CCI-002475'], // ECS cluster logging CMK

  // ============================================================================
  // LOGGING & MONITORING (AU-2, AU-3, AU-12)
  // ============================================================================
  'CKV_AWS_35': ['CCI-000172', 'CCI-001464'], // CloudTrail KMS encryption
  'CKV_AWS_36': ['CCI-000172', 'CCI-001464'], // CloudTrail log validation
  'CKV_AWS_37': ['CCI-000172', 'CCI-001464'], // EKS control plane logging
  'CKV_AWS_48': ['CCI-000172', 'CCI-001464'], // MQ broker logging
  'CKV_AWS_66': ['CCI-000172', 'CCI-001464'], // CloudWatch log retention
  'CKV_AWS_67': ['CCI-000172', 'CCI-001464'], // CloudTrail all regions
  'CKV_AWS_71': ['CCI-000172', 'CCI-001464'], // Redshift logging
  'CKV_AWS_73': ['CCI-000172', 'CCI-001464'], // API Gateway X-Ray
  'CKV_AWS_75': ['CCI-000172', 'CCI-001464'], // Global Accelerator flow logs
  'CKV_AWS_76': ['CCI-000172', 'CCI-001464'], // API Gateway access logging
  'CKV_AWS_85': ['CCI-000172', 'CCI-001464'], // DocumentDB logging
  'CKV_AWS_86': ['CCI-000172', 'CCI-001464'], // CloudFront access logging
  'CKV_AWS_91': ['CCI-000172', 'CCI-001464'], // ELBv2 access logging
  'CKV_AWS_92': ['CCI-000172', 'CCI-001464'], // ELB access logging
  'CKV_AWS_101': ['CCI-000172', 'CCI-001464'], // Neptune logging
  'CKV_AWS_104': ['CCI-000172', 'CCI-001464'], // DocumentDB audit logs
  'CKV_AWS_112': ['CCI-001199', 'CCI-002475'], // Session Manager encryption
  'CKV_AWS_113': ['CCI-000172', 'CCI-001464'], // Session Manager logging
  'CKV_AWS_121': ['CCI-000172', 'CCI-001464'], // AWS Config all regions
  'CKV_AWS_176': ['CCI-000172', 'CCI-001464'], // WAF logging
  'CKV_AWS_193': ['CCI-000172', 'CCI-001464'], // AppSync logging
  'CKV_AWS_194': ['CCI-000172', 'CCI-001464'], // AppSync field-level logs
  'CKV_AWS_197': ['CCI-000172', 'CCI-001464'], // MQ broker audit logging

  // ============================================================================
  // BACKUP & DISASTER RECOVERY (CP-9, CP-10)
  // ============================================================================
  'CKV_AWS_28': ['CCI-000537', 'CCI-001876'], // DynamoDB PITR
  'CKV_AWS_165': ['CCI-000537', 'CCI-001876'], // DynamoDB global table PITR

  // ============================================================================
  // API GATEWAY & WEB SERVICES (AC-3, SC-8)
  // ============================================================================
  'CKV_AWS_59': ['CCI-000213', 'CCI-001368'], // API Gateway authorization
  'CKV_AWS_120': ['CCI-000213', 'CCI-001368'], // API Gateway caching
  'CKV_AWS_206': ['CCI-002418', 'CCI-002420'], // API Gateway modern security policy
  'CKV_AWS_217': ['CCI-000213', 'CCI-001368'], // API Gateway deployment lifecycle
  'CKV_AWS_225': ['CCI-000213', 'CCI-001368'], // API Gateway caching enabled

  // ============================================================================
  // LAMBDA FUNCTIONS (AC-4, SC-7)
  // ============================================================================
  'CKV_AWS_45': ['CCI-000213', 'CCI-001368'], // Lambda no hardcoded secrets
  'CKV_AWS_46': ['CCI-000213', 'CCI-001368'], // EC2 user data no secrets
  'CKV_AWS_50': ['CCI-000172', 'CCI-001464'], // Lambda X-Ray tracing
  'CKV_AWS_115': ['CCI-000213', 'CCI-001368'], // Lambda concurrent execution limit
  'CKV_AWS_116': ['CCI-000213', 'CCI-001368'], // Lambda DLQ configuration
  'CKV_AWS_117': ['CCI-001097', 'CCI-002403'], // Lambda VPC configuration

  // ============================================================================
  // CLOUDFRONT & CDN (SC-8, SC-13)
  // ============================================================================
  'CKV_AWS_68': ['CCI-001097', 'CCI-002403'], // CloudFront WAF enabled
  'CKV_AWS_216': ['CCI-000213', 'CCI-001368'], // CloudFront distribution enabled

  // ============================================================================
  // SECURITY & COMPLIANCE (RA-5, CA-2, CA-7)
  // ============================================================================
  'CKV_AWS_32': ['CCI-000213', 'CCI-001368'], // ECR policy not public
  'CKV_AWS_33': ['CCI-000213', 'CCI-001368'], // KMS no wildcard principals
  'CKV_AWS_41': ['CCI-000213', 'CCI-001368'], // No hardcoded AWS credentials
  'CKV_AWS_114': ['CCI-000213', 'CCI-001368'], // EMR Kerberos realm
  'CKV_AWS_122': ['CCI-000213', 'CCI-001368'], // SageMaker no direct internet
  'CKV_AWS_123': ['CCI-000213', 'CCI-001368'], // VPC endpoint manual acceptance
  'CKV_AWS_124': ['CCI-000172', 'CCI-001464'], // CloudFormation SNS notifications
  'CKV_AWS_126': ['CCI-001312', 'CCI-001314'], // EC2 detailed monitoring
  'CKV_AWS_138': ['CCI-000213', 'CCI-001368'], // ELB cross-zone load balancing
  'CKV_AWS_150': ['CCI-000213', 'CCI-001368'], // Load balancer deletion protection
  'CKV_AWS_152': ['CCI-000213', 'CCI-001368'], // Load balancer cross-zone
  'CKV_AWS_153': ['CCI-000213', 'CCI-001368'], // Autoscaling tag propagation
  'CKV_AWS_167': ['CCI-000213', 'CCI-001368'], // Glacier vault no public access
  'CKV_AWS_168': ['CCI-000213', 'CCI-001368'], // SQS no public access
  'CKV_AWS_169': ['CCI-000213', 'CCI-001368'], // SNS no public access
  'CKV_AWS_170': ['CCI-000213', 'CCI-001368'], // QLDB permissions standard
  'CKV_AWS_172': ['CCI-000213', 'CCI-001368'], // QLDB deletion protection
  'CKV_AWS_175': ['CCI-001097', 'CCI-002403'], // WAF has rules
  'CKV_AWS_192': ['CCI-001643', 'CCI-003173'], // WAF Log4j protection
  'CKV_AWS_195': ['CCI-001199', 'CCI-002475'], // Glue security configuration
  'CKV_AWS_196': ['CCI-001097', 'CCI-002403'], // No ElastiCache security group
  'CKV_AWS_198': ['CCI-001097', 'CCI-002403'], // No RDS security group
  'CKV_AWS_205': ['CCI-000213', 'CCI-001368'], // Limit AMI sharing
  'CKV_AWS_207': ['CCI-001199', 'CCI-002475'], // MQ broker auto-updates
  'CKV_AWS_208': ['CCI-001199', 'CCI-002475'], // MQ broker current version
  'CKV_AWS_222': ['CCI-001199', 'CCI-002475'], // DMS auto minor upgrades

  // ============================================================================
  // POLICY & CONFIGURATION (CM-6, CM-7)
  // ============================================================================
  'CKV_AWS_72': ['CCI-000213', 'CCI-001368'], // SQS policy no ALL actions

  // ============================================================================
  // AZURE RULES (CKV_AZURE_*)
  // ============================================================================

  // AZURE - STORAGE & ENCRYPTION (SC-28, SC-13)
  'CKV_AZURE_1': ['CCI-001199', 'CCI-002475'], // Azure Instance Managed Disk encryption
  'CKV_AZURE_2': ['CCI-001199', 'CCI-002475'], // Unattached managed disks encrypted
  'CKV_AZURE_3': ['CCI-001199', 'CCI-002475'], // VM managed disk encryption
  'CKV_AZURE_33': ['CCI-001199', 'CCI-002475'], // Storage Account secure transfer
  'CKV_AZURE_35': ['CCI-001199', 'CCI-002475'], // Storage blob encryption
  'CKV_AZURE_36': ['CCI-001199', 'CCI-002475'], // Storage container public access
  'CKV_AZURE_41': ['CCI-001199', 'CCI-002475'], // Storage default network access
  'CKV_AZURE_43': ['CCI-001199', 'CCI-002475'], // Key Vault recoverable
  'CKV_AZURE_44': ['CCI-001199', 'CCI-002475'], // Key Vault key expiration
  'CKV_AZURE_189': ['CCI-001199', 'CCI-002475'], // Key Vault secret expiration

  // AZURE - DATABASES (SC-28, SC-13)
  'CKV_AZURE_4': ['CCI-001199', 'CCI-002475'], // AKS logging enabled
  'CKV_AZURE_5': ['CCI-001199', 'CCI-002475'], // AKS RBAC enabled
  'CKV_AZURE_6': ['CCI-001199', 'CCI-002475'], // AKS Dashboard disabled
  'CKV_AZURE_7': ['CCI-001199', 'CCI-002475'], // AKS Network Policy
  'CKV_AZURE_8': ['CCI-001199', 'CCI-002475'], // AKS authorized IP ranges
  'CKV_AZURE_17': ['CCI-001199', 'CCI-002475'], // SQL DB encryption
  'CKV_AZURE_23': ['CCI-001199', 'CCI-002475'], // SQL Server TDE encryption
  'CKV_AZURE_24': ['CCI-001199', 'CCI-002475'], // SQL Server auditing
  'CKV_AZURE_25': ['CCI-001199', 'CCI-002475'], // SQL Server public network access
  'CKV_AZURE_26': ['CCI-001199', 'CCI-002475'], // SQL Server email alerts
  'CKV_AZURE_27': ['CCI-001199', 'CCI-002475'], // SQL Server threat detection
  'CKV_AZURE_28': ['CCI-001199', 'CCI-002475'], // MySQL SSL enforcement
  'CKV_AZURE_29': ['CCI-001199', 'CCI-002475'], // MySQL geo-redundant backup
  'CKV_AZURE_30': ['CCI-001199', 'CCI-002475'], // PostgreSQL SSL enforcement
  'CKV_AZURE_32': ['CCI-001199', 'CCI-002475'], // PostgreSQL geo-redundant backup
  'CKV_AZURE_48': ['CCI-001199', 'CCI-002475'], // PostgreSQL log checkpoints
  'CKV_AZURE_94': ['CCI-001199', 'CCI-002475'], // MySQL private endpoint
  'CKV_AZURE_102': ['CCI-001199', 'CCI-002475'], // PostgreSQL private endpoint
  'CKV_AZURE_128': ['CCI-001199', 'CCI-002475'], // PostgreSQL log connections
  'CKV_AZURE_129': ['CCI-001199', 'CCI-002475'], // PostgreSQL log disconnections
  'CKV_AZURE_130': ['CCI-001199', 'CCI-002475'], // PostgreSQL connection throttling

  // AZURE - NETWORK SECURITY (SC-7, AC-4)
  'CKV_AZURE_9': ['CCI-001097', 'CCI-002403'], // NSG denies all inbound traffic
  'CKV_AZURE_10': ['CCI-001097', 'CCI-002403'], // NSG SSH access restricted
  'CKV_AZURE_11': ['CCI-001097', 'CCI-002403'], // NSG RDP access restricted
  'CKV_AZURE_12': ['CCI-001097', 'CCI-002403'], // Network Watcher enabled
  'CKV_AZURE_13': ['CCI-001097', 'CCI-002403'], // App Service HTTPS only
  'CKV_AZURE_14': ['CCI-002418', 'CCI-002420'], // App Service latest TLS
  'CKV_AZURE_15': ['CCI-002418', 'CCI-002420'], // App Service HTTPS client cert
  'CKV_AZURE_16': ['CCI-002418', 'CCI-002420'], // Function App HTTPS only
  'CKV_AZURE_18': ['CCI-002418', 'CCI-002420'], // Function App latest TLS
  'CKV_AZURE_37': ['CCI-000172', 'CCI-001464'], // Network Security logging
  'CKV_AZURE_42': ['CCI-001097', 'CCI-002403'], // VM public IP restrictions
  'CKV_AZURE_71': ['CCI-002418', 'CCI-002420'], // Redis SSL only

  // AZURE - LOGGING & MONITORING (AU-2, AU-12)
  'CKV_AZURE_19': ['CCI-000172', 'CCI-001464'], // Security Center standard pricing
  'CKV_AZURE_20': ['CCI-000172', 'CCI-001464'], // Security Center email notification
  'CKV_AZURE_21': ['CCI-000172', 'CCI-001464'], // Security Center email to admin
  'CKV_AZURE_22': ['CCI-000172', 'CCI-001464'], // Security Center auto provisioning
  'CKV_AZURE_38': ['CCI-000172', 'CCI-001464'], // Activity log retention 365 days
  'CKV_AZURE_39': ['CCI-000172', 'CCI-001464'], // Role assignments monitored
  'CKV_AZURE_40': ['CCI-000172', 'CCI-001464'], // Key Vault key monitoring

  // ============================================================================
  // GCP RULES (CKV_GCP_*)
  // ============================================================================

  // GCP - ENCRYPTION (SC-28, SC-13)
  'CKV_GCP_1': ['CCI-001199', 'CCI-002475'], // GCS bucket uniform access
  'CKV_GCP_5': ['CCI-001199', 'CCI-002475'], // GCS bucket logging
  'CKV_GCP_6': ['CCI-000213', 'CCI-001368'], // GCS bucket public access
  'CKV_GCP_7': ['CCI-001199', 'CCI-002475'], // Cloud SQL backup
  'CKV_GCP_8': ['CCI-001199', 'CCI-002475'], // Cloud SQL public IP
  'CKV_GCP_9': ['CCI-001199', 'CCI-002475'], // Cloud SQL SSL
  'CKV_GCP_10': ['CCI-001199', 'CCI-002475'], // SQL DB backups
  'CKV_GCP_11': ['CCI-001199', 'CCI-002475'], // SQL DB encryption
  'CKV_GCP_14': ['CCI-001199', 'CCI-002475'], // VM disk encryption
  'CKV_GCP_15': ['CCI-001199', 'CCI-002475'], // BigQuery dataset encrypted
  'CKV_GCP_16': ['CCI-001199', 'CCI-002475'], // BigQuery publicly accessible
  'CKV_GCP_37': ['CCI-001199', 'CCI-002475'], // GCS versioning enabled
  'CKV_GCP_38': ['CCI-001199', 'CCI-002475'], // Cloud Storage encryption
  'CKV_GCP_40': ['CCI-001199', 'CCI-002475'], // VM confidential computing
  'CKV_GCP_43': ['CCI-001199', 'CCI-002475'], // KMS crypto key rotation
  'CKV_GCP_82': ['CCI-001199', 'CCI-002475'], // KMS encryption default

  // GCP - NETWORK SECURITY (SC-7, AC-4)
  'CKV_GCP_2': ['CCI-001097', 'CCI-002403'], // Compute firewall rule logging
  'CKV_GCP_3': ['CCI-001097', 'CCI-002403'], // VPC Flow Logs enabled
  'CKV_GCP_22': ['CCI-001097', 'CCI-002403'], // Firewall no unrestricted SSH
  'CKV_GCP_23': ['CCI-001097', 'CCI-002403'], // Firewall no unrestricted RDP
  'CKV_GCP_25': ['CCI-001097', 'CCI-002403'], // GKE private cluster
  'CKV_GCP_33': ['CCI-001097', 'CCI-002403'], // GKE legacy auth disabled
  'CKV_GCP_34': ['CCI-001097', 'CCI-002403'], // VM IP forwarding disabled
  'CKV_GCP_35': ['CCI-000213', 'CCI-001368'], // VM serial port disabled
  'CKV_GCP_36': ['CCI-000213', 'CCI-001368'], // VM network default access
  'CKV_GCP_39': ['CCI-001097', 'CCI-002403'], // GKE public cluster
  'CKV_GCP_61': ['CCI-001097', 'CCI-002403'], // VPC no default network
  'CKV_GCP_75': ['CCI-001097', 'CCI-002403'], // Firewall unrestricted ingress

  // GCP - IAM & ACCESS CONTROL (AC-2, AC-3)
  'CKV_GCP_17': ['CCI-000213', 'CCI-001403'], // IAM service account admin
  'CKV_GCP_41': ['CCI-000213', 'CCI-001403'], // Project-wide SSH keys
  'CKV_GCP_42': ['CCI-000213', 'CCI-001403'], // VM service account usage
  'CKV_GCP_44': ['CCI-000213', 'CCI-001403'], // GCS IAM binding member
  'CKV_GCP_45': ['CCI-000213', 'CCI-001403'], // GCS IAM binding entities
  'CKV_GCP_46': ['CCI-000213', 'CCI-001403'], // GCS IAM member override
  'CKV_GCP_49': ['CCI-000213', 'CCI-001403'], // Service account key rotation
  'CKV_GCP_62': ['CCI-000213', 'CCI-001403'], // Cloud asset least privilege

  // GCP - LOGGING & MONITORING (AU-2, AU-12)
  'CKV_GCP_12': ['CCI-000172', 'CCI-001464'], // VPC Flow Logs
  'CKV_GCP_13': ['CCI-000172', 'CCI-001464'], // Audit logging enabled
  'CKV_GCP_18': ['CCI-000172', 'CCI-001464'], // GKE logging enabled
  'CKV_GCP_19': ['CCI-000172', 'CCI-001464'], // GKE monitoring enabled
  'CKV_GCP_20': ['CCI-000172', 'CCI-001464'], // GKE alias IP enabled
  'CKV_GCP_21': ['CCI-000172', 'CCI-001464'], // GKE pod security policy
  'CKV_GCP_24': ['CCI-000172', 'CCI-001464'], // GKE workload identity
  'CKV_GCP_26': ['CCI-000172', 'CCI-001464'], // GKE stackdriver monitoring
  'CKV_GCP_27': ['CCI-000172', 'CCI-001464'], // GKE stackdriver logging
  'CKV_GCP_30': ['CCI-000172', 'CCI-001464'], // GKE network policy
  'CKV_GCP_60': ['CCI-000172', 'CCI-001464'], // Cloud Run IAM
  'CKV_GCP_65': ['CCI-000172', 'CCI-001464'], // GKE control plane logs

  // ============================================================================
  // KUBERNETES RULES (CKV_K8S_*)
  // ============================================================================

  // K8S - POD SECURITY (AC-6, SC-4)
  'CKV_K8S_1': ['CCI-000213', 'CCI-001368'], // Process can elevate privileges
  'CKV_K8S_2': ['CCI-000213', 'CCI-001368'], // Privileged container
  'CKV_K8S_3': ['CCI-000213', 'CCI-001368'], // Root containers
  'CKV_K8S_4': ['CCI-000213', 'CCI-001368'], // Root filesystem read-only
  'CKV_K8S_5': ['CCI-000213', 'CCI-001368'], // Allowed capabilities
  'CKV_K8S_6': ['CCI-000213', 'CCI-001368'], // Adding capabilities
  'CKV_K8S_7': ['CCI-000213', 'CCI-001368'], // Security context privilege
  'CKV_K8S_8': ['CCI-001097', 'CCI-002403'], // Liveness probe
  'CKV_K8S_9': ['CCI-001097', 'CCI-002403'], // Readiness probe
  'CKV_K8S_10': ['CCI-000213', 'CCI-001368'], // CPU requests
  'CKV_K8S_11': ['CCI-000213', 'CCI-001368'], // CPU limits
  'CKV_K8S_12': ['CCI-000213', 'CCI-001368'], // Memory requests
  'CKV_K8S_13': ['CCI-000213', 'CCI-001368'], // Memory limits
  'CKV_K8S_14': ['CCI-000213', 'CCI-001368'], // Image pull policy
  'CKV_K8S_15': ['CCI-000213', 'CCI-001368'], // Image digest
  'CKV_K8S_16': ['CCI-000213', 'CCI-001368'], // Container runs with high UID
  'CKV_K8S_17': ['CCI-000213', 'CCI-001368'], // Privilege escalation
  'CKV_K8S_18': ['CCI-000213', 'CCI-001368'], // Security context capabilities
  'CKV_K8S_19': ['CCI-000213', 'CCI-001368'], // Sharing host PID
  'CKV_K8S_20': ['CCI-000213', 'CCI-001368'], // Sharing host IPC
  'CKV_K8S_21': ['CCI-000213', 'CCI-001368'], // Default namespace
  'CKV_K8S_22': ['CCI-000213', 'CCI-001368'], // Read-only filesystem
  'CKV_K8S_23': ['CCI-000213', 'CCI-001368'], // Host networking
  'CKV_K8S_24': ['CCI-000213', 'CCI-001368'], // Host network ports
  'CKV_K8S_25': ['CCI-000213', 'CCI-001368'], // Container privilege containers
  'CKV_K8S_26': ['CCI-000213', 'CCI-001368'], // Host path volumes
  'CKV_K8S_27': ['CCI-000213', 'CCI-001368'], // HostPath mounting
  'CKV_K8S_28': ['CCI-000213', 'CCI-001368'], // hostPort
  'CKV_K8S_29': ['CCI-000213', 'CCI-001368'], // Sharing host network
  'CKV_K8S_30': ['CCI-000213', 'CCI-001368'], // Security Context defined
  'CKV_K8S_31': ['CCI-000213', 'CCI-001368'], // seccomp profile
  'CKV_K8S_32': ['CCI-000213', 'CCI-001368'], // SELinux options
  'CKV_K8S_33': ['CCI-000213', 'CCI-001368'], // Docker socket
  'CKV_K8S_34': ['CCI-001199', 'CCI-002475'], // Secrets in environment
  'CKV_K8S_35': ['CCI-001199', 'CCI-002475'], // Secrets mounted
  'CKV_K8S_36': ['CCI-000213', 'CCI-001368'], // Service account token
  'CKV_K8S_37': ['CCI-000213', 'CCI-001368'], // Capabilities SYS_ADMIN
  'CKV_K8S_38': ['CCI-000213', 'CCI-001368'], // Capability NET_RAW
  'CKV_K8S_39': ['CCI-000213', 'CCI-001368'], // Capability ALL
  'CKV_K8S_40': ['CCI-000213', 'CCI-001368'], // Containers AppArmor
  'CKV_K8S_41': ['CCI-000213', 'CCI-001368'], // Service account name
  'CKV_K8S_42': ['CCI-000213', 'CCI-001368'], // Tiller deployed
  'CKV_K8S_43': ['CCI-000213', 'CCI-001368'], // Image pull secrets
  'CKV_K8S_44': ['CCI-001097', 'CCI-002403'], // Service type LoadBalancer
  'CKV_K8S_45': ['CCI-001097', 'CCI-002403'], // Service type NodePort

  // ============================================================================
  // ALIBABA CLOUD RULES (CKV_ALI_*)
  // ============================================================================
  'CKV_ALI_1': ['CCI-000213', 'CCI-001368'], // OSS bucket not publicly accessible
  'CKV_ALI_2': ['CCI-001097', 'CCI-002403'], // No unrestricted SSH
  'CKV_ALI_3': ['CCI-001097', 'CCI-002403'], // No unrestricted RDP
  'CKV_ALI_4': ['CCI-000172', 'CCI-001464'], // ActionTrail all regions
  'CKV_ALI_5': ['CCI-000172', 'CCI-001464'], // ActionTrail all events
  'CKV_ALI_6': ['CCI-001199', 'CCI-002475'], // OSS bucket CMK encryption
  'CKV_ALI_7': ['CCI-001199', 'CCI-002475'], // Disk encryption
  'CKV_ALI_8': ['CCI-001199', 'CCI-002475'], // Disk CMK encryption
  'CKV_ALI_9': ['CCI-000213', 'CCI-001368'], // RDS not public
  'CKV_ALI_10': ['CCI-000213', 'CCI-000186'], // OSS versioning
  'CKV_ALI_11': ['CCI-000213', 'CCI-001368'], // OSS transfer acceleration
  'CKV_ALI_12': ['CCI-000172', 'CCI-001464'], // OSS access logging
  'CKV_ALI_13': ['CCI-000764', 'CCI-001941'], // Password min length 14
  'CKV_ALI_14': ['CCI-000764', 'CCI-001941'], // Password numbers required
  'CKV_ALI_15': ['CCI-000764', 'CCI-001941'], // Password symbols required
  'CKV_ALI_16': ['CCI-000764', 'CCI-001941'], // Password expire 90 days
  'CKV_ALI_17': ['CCI-000764', 'CCI-001941'], // Password lowercase required
  'CKV_ALI_18': ['CCI-000764', 'CCI-001941'], // Password reuse prevention
  'CKV_ALI_19': ['CCI-000764', 'CCI-001941'], // Password uppercase required
  'CKV_ALI_20': ['CCI-002418', 'CCI-002420'], // RDS SSL enabled
  'CKV_ALI_21': ['CCI-002418', 'CCI-002420'], // API Gateway HTTPS
  'CKV_ALI_22': ['CCI-001199', 'CCI-002475'], // RDS TDE enabled
  'CKV_ALI_23': ['CCI-000764', 'CCI-001941'], // Max login attempts
  'CKV_ALI_24': ['CCI-000764', 'CCI-001941'], // RAM MFA enforcement
  'CKV_ALI_25': ['CCI-000172', 'CCI-001464'], // RDS SQL Collector retention
  'CKV_ALI_26': ['CCI-001097', 'CCI-002403'], // K8s network policy
  'CKV_ALI_27': ['CCI-001199', 'CCI-002475'], // KMS key rotation
  'CKV_ALI_28': ['CCI-001199', 'CCI-002475'], // KMS keys enabled
  'CKV_ALI_29': ['CCI-001097', 'CCI-002403'], // ALB ACL restrict
  'CKV_ALI_30': ['CCI-001199', 'CCI-002475'], // RDS auto-upgrade
  'CKV_ALI_31': ['CCI-001312', 'CCI-001314'], // K8s auto-repair
  'CKV_ALI_32': ['CCI-001199', 'CCI-002475'], // Launch template disk encryption
  'CKV_ALI_33': ['CCI-002418', 'CCI-002420'], // TLS cipher secure
  'CKV_ALI_35': ['CCI-000172', 'CCI-001464'], // RDS log_duration
  'CKV_ALI_36': ['CCI-000172', 'CCI-001464'], // RDS log_disconnections
  'CKV_ALI_37': ['CCI-000172', 'CCI-001464'], // RDS log_connections
  'CKV_ALI_38': ['CCI-000172', 'CCI-001464'], // RDS audit enabled
  'CKV_ALI_41': ['CCI-001097', 'CCI-002403'], // MongoDB in VPC
  'CKV_ALI_42': ['CCI-002418', 'CCI-002420'], // MongoDB SSL
  'CKV_ALI_43': ['CCI-000213', 'CCI-001368'], // MongoDB not public
  'CKV_ALI_44': ['CCI-001199', 'CCI-002475'], // MongoDB TDE

  // ============================================================================
  // DOCKER RULES (CKV_DOCKER_*)
  // ============================================================================
  'CKV_DOCKER_1': ['CCI-000213', 'CCI-001368'], // USER instruction not root
  'CKV_DOCKER_2': ['CCI-001097', 'CCI-002403'], // HEALTHCHECK instruction
  'CKV_DOCKER_3': ['CCI-000213', 'CCI-001368'], // RUN command sudo
  'CKV_DOCKER_4': ['CCI-000213', 'CCI-001368'], // ADD instead of COPY
  'CKV_DOCKER_5': ['CCI-002418', 'CCI-002420'], // RUN wget/curl piped bash
  'CKV_DOCKER_6': ['CCI-000213', 'CCI-001368'], // MAINTAINER deprecated
  'CKV_DOCKER_7': ['CCI-000213', 'CCI-001368'], // FROM latest tag
  'CKV_DOCKER_8': ['CCI-000213', 'CCI-001368'], // USER root
  'CKV_DOCKER_9': ['CCI-002418', 'CCI-002420'], // RUN apt-get update
  'CKV_DOCKER_10': ['CCI-000213', 'CCI-001368'], // WORKDIR absolute path
  'CKV_DOCKER_11': ['CCI-000213', 'CCI-001368'], // EXPOSE port 22

  // ============================================================================
  // GITHUB ACTIONS (CKV_GHA_*)
  // ============================================================================
  'CKV_GHA_1': ['CCI-000213', 'CCI-001368'], // Workflow pinned actions
  'CKV_GHA_2': ['CCI-000213', 'CCI-001368'], // Secrets in GitHub Environment
  'CKV_GHA_3': ['CCI-000213', 'CCI-001368'], // Workflow injection risk
  'CKV_GHA_4': ['CCI-000213', 'CCI-001368'], // Workflow default token permissions
  'CKV_GHA_7': ['CCI-000213', 'CCI-001368'], // OpenID Connect token permissions

  // ============================================================================
  // ANSIBLE RULES (CKV_ANSIBLE_*, CKV2_ANSIBLE_*)
  // ============================================================================
  'CKV_ANSIBLE_1': ['CCI-002418', 'CCI-002420'], // URI module validate certs
  'CKV_ANSIBLE_2': ['CCI-002418', 'CCI-002420'], // get_url validate certs
  'CKV_ANSIBLE_3': ['CCI-002418', 'CCI-002420'], // yum validate certs
  'CKV_ANSIBLE_4': ['CCI-002418', 'CCI-002420'], // yum SSL validation
  'CKV_ANSIBLE_5': ['CCI-000213', 'CCI-001368'], // Apt authenticated packages
  'CKV_ANSIBLE_6': ['CCI-000213', 'CCI-001368'], // Apt force parameter
  'CKV2_ANSIBLE_1': ['CCI-002418', 'CCI-002420'], // URI HTTPS URLs
  'CKV2_ANSIBLE_2': ['CCI-002418', 'CCI-002420'], // get_url HTTPS URLs
  'CKV2_ANSIBLE_3': ['CCI-000213', 'CCI-001368'], // Block error handling
  'CKV2_ANSIBLE_4': ['CCI-002418', 'CCI-002420'], // dnf GPG check
  'CKV2_ANSIBLE_5': ['CCI-002418', 'CCI-002420'], // dnf SSL verification
  'CKV2_ANSIBLE_6': ['CCI-002418', 'CCI-002420'], // dnf validate certs

  // ============================================================================
  // ARGO WORKFLOWS (CKV_ARGO_*)
  // ============================================================================
  'CKV_ARGO_1': ['CCI-000213', 'CCI-001368'], // Avoid default ServiceAccount
  'CKV_ARGO_2': ['CCI-000213', 'CCI-001368'], // Run as non-root user
};
