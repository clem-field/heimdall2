// CCI Mappings for Checkov/Bridgecrew rules
// Updated: 2026-03-29
//
// Mapping Methodology:
//   CCI mappings derived from checkov-checks-enriched.json which maps each CKV check
//   to NIST SP 800-53 Rev 5 controls, then resolves to DISA CCI identifiers.
//
//   Chain: CKV check → NIST SP 800-53 Rev 5 control → DISA CCI
//
//   Each mapped entry includes a comment documenting:
//     - The NIST 800-53 Rev 5 control(s) for traceability
//     - The Checkov policy name for context
//
//   Total checks mapped: 1341
//   Source: checkov-checks-enriched.json (checkov --list + NIST/CCI enrichment)
export const data: Record<string, string[]> = {
  // CKV2_ADO_1: Ensure at least two approving reviews for PRs → NIST: CM-3(2), CM-5(1)
  'CKV2_ADO_1': ['CCI-001501', 'CCI-001510'],
  // CKV2_ANSIBLE_1: Ensure that HTTPS url is used with uri → NIST: SC-8(1)
  'CKV2_ANSIBLE_1': ['CCI-002420'],
  // CKV2_ANSIBLE_2: Ensure that HTTPS url is used with get_url → NIST: SC-8(1)
  'CKV2_ANSIBLE_2': ['CCI-002420'],
  // CKV2_ANSIBLE_3: Ensure block is handling task errors properly → NIST: CM-6
  'CKV2_ANSIBLE_3': ['CCI-000366'],
  // CKV2_ANSIBLE_4: Ensure that packages with untrusted or missing GPG signatures are not used by... → NIST: SI-7(6), SR-3
  'CKV2_ANSIBLE_4': ['CCI-002705', 'CCI-003610'],
  // CKV2_ANSIBLE_5: Ensure that SSL validation isn't disabled with dnf → NIST: CM-6
  'CKV2_ANSIBLE_5': ['CCI-000366'],
  // CKV2_ANSIBLE_6: Ensure that certificate validation isn't disabled with dnf → NIST: SC-8(1), SC-17
  'CKV2_ANSIBLE_6': ['CCI-002420', 'CCI-002448'],
  // CKV2_AWS_1: Ensure that all NACL are attached to subnets → NIST: CM-6
  'CKV2_AWS_1': ['CCI-000366'],
  // CKV2_AWS_10: Ensure CloudTrail trails are integrated with CloudWatch Logs → NIST: AU-12(1), AU-3(1)
  'CKV2_AWS_10': ['CCI-000172', 'CCI-000135'],
  // CKV2_AWS_11: Ensure VPC flow logging is enabled in all VPCs → NIST: SC-7(3)
  'CKV2_AWS_11': ['CCI-001098'],
  // CKV2_AWS_12: Ensure the default security group of every VPC restricts all traffic → NIST: SC-7(4)
  'CKV2_AWS_12': ['CCI-001099'],
  // CKV2_AWS_14: Ensure that IAM groups includes at least one IAM user → NIST: AC-6(1)
  'CKV2_AWS_14': ['CCI-000226'],
  // CKV2_AWS_15: Ensure that auto Scaling groups that are associated with a load balancer are ... → NIST: CP-10(4), SC-5(2)
  'CKV2_AWS_15': ['CCI-000557', 'CCI-002386'],
  // CKV2_AWS_16: Ensure that Auto Scaling is enabled on your DynamoDB tables → NIST: CP-10(4), SC-5(2)
  'CKV2_AWS_16': ['CCI-000557', 'CCI-002386'],
  // CKV2_AWS_18: Ensure that Elastic File System (Amazon EFS) file systems are added in the ba... → NIST: CM-6
  'CKV2_AWS_18': ['CCI-000366'],
  // CKV2_AWS_19: Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances → NIST: SC-7(3)
  'CKV2_AWS_19': ['CCI-001098'],
  // CKV2_AWS_2: Ensure that only encrypted EBS volumes are attached to EC2 instances → NIST: SC-28(1)
  'CKV2_AWS_2': ['CCI-002476'],
  // CKV2_AWS_20: Ensure that ALB redirects HTTP requests into HTTPS ones → NIST: SC-8(1), SC-7(4)
  'CKV2_AWS_20': ['CCI-002420', 'CCI-001099'],
  // CKV2_AWS_21: Ensure that all IAM users are members of at least one IAM group. → NIST: AC-6(1)
  'CKV2_AWS_21': ['CCI-000226'],
  // CKV2_AWS_22: Ensure an IAM User does not have access to the console → NIST: CM-6
  'CKV2_AWS_22': ['CCI-000366'],
  // CKV2_AWS_23: Route53 A Record has Attached Resource → NIST: CM-6
  'CKV2_AWS_23': ['CCI-000366'],
  // CKV2_AWS_27: Ensure Postgres RDS as aws_rds_cluster has Query Logging enabled → NIST: AU-2, AU-12
  'CKV2_AWS_27': ['CCI-000130', 'CCI-000169'],
  // CKV2_AWS_28: Ensure public facing ALB are protected by WAF → NIST: SC-7(14), SC-5(1)
  'CKV2_AWS_28': ['CCI-001109', 'CCI-002385'],
  // CKV2_AWS_29: Ensure public API gateway are protected by WAF → NIST: SC-7(14), SC-5(1)
  'CKV2_AWS_29': ['CCI-001109', 'CCI-002385'],
  // CKV2_AWS_3: Ensure GuardDuty is enabled to specific org/region → NIST: SI-4(4), RA-5(2)
  'CKV2_AWS_3': ['CCI-002686', 'CCI-001645'],
  // CKV2_AWS_30: Ensure Postgres RDS as aws_db_instance has Query Logging enabled → NIST: AU-2, AU-12
  'CKV2_AWS_30': ['CCI-000130', 'CCI-000169'],
  // CKV2_AWS_31: Ensure WAF2 has a Logging Configuration → NIST: AU-2, AU-12
  'CKV2_AWS_31': ['CCI-000130', 'CCI-000169'],
  // CKV2_AWS_32: Ensure CloudFront distribution has a response headers policy attached → NIST: IR-4(1), IR-5(1)
  'CKV2_AWS_32': ['CCI-000227', 'CCI-001310'],
  // CKV2_AWS_33: Ensure AppSync is protected by WAF → NIST: SC-7(14), SC-5(1)
  'CKV2_AWS_33': ['CCI-001109', 'CCI-002385'],
  // CKV2_AWS_34: AWS SSM Parameter should be Encrypted → NIST: SC-13
  'CKV2_AWS_34': ['CCI-002450'],
  // CKV2_AWS_35: AWS NAT Gateways should be utilized for the default route → NIST: CM-6
  'CKV2_AWS_35': ['CCI-000366'],
  // CKV2_AWS_36: Ensure terraform is not sending SSM secrets to untrusted domains over HTTP → NIST: CM-6
  'CKV2_AWS_36': ['CCI-000366'],
  // CKV2_AWS_37: Ensure CodeCommit associates an approval rule → NIST: CM-3(2), CM-5(1)
  'CKV2_AWS_37': ['CCI-001501', 'CCI-001510'],
  // CKV2_AWS_38: Ensure Domain Name System Security Extensions (DNSSEC) signing is enabled for... → NIST: SC-7(4), SC-20
  'CKV2_AWS_38': ['CCI-001099'],
  // CKV2_AWS_39: Ensure Domain Name System (DNS) query logging is enabled for Amazon Route 53 ... → NIST: AU-2, AU-12
  'CKV2_AWS_39': ['CCI-000130', 'CCI-000169'],
  // CKV2_AWS_4: Ensure API Gateway stage have logging level defined as appropriate → NIST: AU-2, AU-12
  'CKV2_AWS_4': ['CCI-000130', 'CCI-000169'],
  // CKV2_AWS_40: Ensure AWS IAM policy does not allow full IAM privileges → NIST: AC-6(10), AC-6(1)
  'CKV2_AWS_40': ['CCI-000235', 'CCI-000226'],
  // CKV2_AWS_41: Ensure an IAM role is attached to EC2 instance → NIST: AC-2(1), AC-3
  'CKV2_AWS_41': ['CCI-000016', 'CCI-000213'],
  // CKV2_AWS_42: Ensure AWS CloudFront distribution uses custom SSL certificate → NIST: CM-6
  'CKV2_AWS_42': ['CCI-000366'],
  // CKV2_AWS_43: Ensure S3 Bucket does not allow access to all Authenticated users → NIST: CM-6
  'CKV2_AWS_43': ['CCI-000366'],
  // CKV2_AWS_44: Ensure AWS route table with VPC peering does not contain routes overly permis... → NIST: SC-7(3)
  'CKV2_AWS_44': ['CCI-001098'],
  // CKV2_AWS_45: Ensure AWS Config recorder is enabled to record all supported resources → NIST: CM-6
  'CKV2_AWS_45': ['CCI-000366'],
  // CKV2_AWS_46: Ensure AWS CloudFront Distribution with S3 have Origin Access set to enabled → NIST: CM-6
  'CKV2_AWS_46': ['CCI-000366'],
  // CKV2_AWS_47: Ensure AWS CloudFront attached WAFv2 WebACL is configured with AMR for Log4j ... → NIST: SC-7(14), SI-3(7)
  'CKV2_AWS_47': ['CCI-001109', 'CCI-001248'],
  // CKV2_AWS_48: Ensure AWS Config must record all possible resources → NIST: CM-6
  'CKV2_AWS_48': ['CCI-000366'],
  // CKV2_AWS_49: Ensure AWS Database Migration Service endpoints have SSL configured → NIST: SC-8(1)
  'CKV2_AWS_49': ['CCI-002420'],
  // CKV2_AWS_5: Ensure that Security Groups are attached to another resource → NIST: CM-6
  'CKV2_AWS_5': ['CCI-000366'],
  // CKV2_AWS_50: Ensure AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature... → NIST: CP-10(2), CP-9
  'CKV2_AWS_50': ['CCI-000555', 'CCI-000509'],
  // CKV2_AWS_51: Ensure AWS API Gateway endpoints uses client certificate authentication → NIST: CM-6
  'CKV2_AWS_51': ['CCI-000366'],
  // CKV2_AWS_52: Ensure AWS ElasticSearch/OpenSearch Fine-grained access control is enabled → NIST: CM-6
  'CKV2_AWS_52': ['CCI-000366'],
  // CKV2_AWS_53: Ensure AWS API gateway request is validated → NIST: CM-6
  'CKV2_AWS_53': ['CCI-000366'],
  // CKV2_AWS_54: Ensure AWS CloudFront distribution is using secure SSL protocols for HTTPS co... → NIST: SC-8(1)
  'CKV2_AWS_54': ['CCI-002420'],
  // CKV2_AWS_55: Ensure AWS EMR cluster is configured with security configuration → NIST: CM-6
  'CKV2_AWS_55': ['CCI-000366'],
  // CKV2_AWS_56: Ensure AWS Managed IAMFullAccess IAM policy is not used. → NIST: CM-6
  'CKV2_AWS_56': ['CCI-000366'],
  // CKV2_AWS_57: Ensure Secrets Manager secrets should have automatic rotation enabled → NIST: IA-5(7), SC-28(1)
  'CKV2_AWS_57': ['CCI-000190', 'CCI-002476'],
  // CKV2_AWS_58: Ensure AWS Neptune cluster deletion protection is enabled → NIST: CM-6
  'CKV2_AWS_58': ['CCI-000366'],
  // CKV2_AWS_59: Ensure ElasticSearch/OpenSearch has dedicated master node enabled → NIST: CM-6
  'CKV2_AWS_59': ['CCI-000366'],
  // CKV2_AWS_6: Ensure that S3 bucket has a Public Access block → NIST: SC-7(5), AC-3
  'CKV2_AWS_6': ['CCI-001100', 'CCI-000213'],
  // CKV2_AWS_60: Ensure RDS instance with copy tags to snapshots is enabled → NIST: CM-6
  'CKV2_AWS_60': ['CCI-000366'],
  // CKV2_AWS_61: Ensure that an S3 bucket has a lifecycle configuration → NIST: MP-6(1), AU-11
  'CKV2_AWS_61': ['CCI-001904', 'CCI-000167'],
  // CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled → NIST: SI-4(5), IR-6(1)
  'CKV2_AWS_62': ['CCI-002687', 'CCI-000229'],
  // CKV2_AWS_63: Ensure Network firewall has logging configuration defined → NIST: AU-2, AU-12
  'CKV2_AWS_63': ['CCI-000130', 'CCI-000169'],
  // CKV2_AWS_64: Ensure KMS key Policy is defined → NIST: SC-28(1), SC-12(1)
  'CKV2_AWS_64': ['CCI-002476', 'CCI-002451'],
  // CKV2_AWS_65: Ensure access control lists for S3 buckets are disabled → NIST: AC-3(4)
  'CKV2_AWS_65': ['CCI-002166'],
  // CKV2_AWS_66: Ensure MWAA environment is not publicly accessible → NIST: SC-7(5), AC-3
  'CKV2_AWS_66': ['CCI-001100', 'CCI-000213'],
  // CKV2_AWS_68: Ensure SageMaker notebook instance IAM policy is not overly permissive → NIST: AC-6(10), AC-6(1)
  'CKV2_AWS_68': ['CCI-000235', 'CCI-000226'],
  // CKV2_AWS_69: Ensure AWS RDS database instance configured with encryption in transit → NIST: SC-8(1)
  'CKV2_AWS_69': ['CCI-002420'],
  // CKV2_AWS_7: Ensure that Amazon EMR clusters' security groups are not open to the world → NIST: CM-6
  'CKV2_AWS_7': ['CCI-000366'],
  // CKV2_AWS_70: Ensure API gateway method has authorization or API key set → NIST: AC-3(8), IA-2(8)
  'CKV2_AWS_70': ['CCI-002170', 'CCI-001953'],
  // CKV2_AWS_71: Ensure AWS ACM Certificate domain name does not include wildcards → NIST: CM-6
  'CKV2_AWS_71': ['CCI-000366'],
  // CKV2_AWS_72: Ensure AWS CloudFront origin protocol policy enforces HTTPS-only → NIST: CM-6
  'CKV2_AWS_72': ['CCI-000366'],
  // CKV2_AWS_73: Ensure AWS SQS uses CMK not AWS default keys for encryption → NIST: SC-28(1), SC-12(1)
  'CKV2_AWS_73': ['CCI-002476', 'CCI-002451'],
  // CKV2_AWS_74: Ensure AWS Load Balancers use strong ciphers → NIST: SC-8(1), SC-13
  'CKV2_AWS_74': ['CCI-002420', 'CCI-002450'],
  // CKV2_AWS_75: Ensure no open CORS policy → NIST: CM-6
  'CKV2_AWS_75': ['CCI-000366'],
  // CKV2_AWS_76: Ensure AWS ALB attached WAFv2 WebACL is configured with AMR for Log4j Vulnera... → NIST: SC-7(14), SI-3(7)
  'CKV2_AWS_76': ['CCI-001109', 'CCI-001248'],
  // CKV2_AWS_77: Ensure AWS API Gateway Rest API attached WAFv2 WebACL is configured with AMR ... → NIST: SC-7(14), SI-3(7)
  'CKV2_AWS_77': ['CCI-001109', 'CCI-001248'],
  // CKV2_AWS_78: Ensure AWS AppSync attached WAFv2 WebACL is configured with AMR for Log4j Vul... → NIST: SC-7(14), SI-3(7)
  'CKV2_AWS_78': ['CCI-001109', 'CCI-001248'],
  // CKV2_AWS_8: Ensure that RDS clusters has backup plan of AWS Backup → NIST: CM-6
  'CKV2_AWS_8': ['CCI-000366'],
  // CKV2_AWS_9: Ensure that EBS are added in the backup plans of AWS Backup → NIST: CM-6
  'CKV2_AWS_9': ['CCI-000366'],
  // CKV2_AZURE_1: Ensure storage for critical data are encrypted with Customer Managed Key → NIST: SC-28(1), SC-12(1)
  'CKV2_AZURE_1': ['CCI-002476', 'CCI-002451'],
  // CKV2_AZURE_10: Ensure that Microsoft Antimalware is configured to automatically updates for ... → NIST: CM-6
  'CKV2_AZURE_10': ['CCI-000366'],
  // CKV2_AZURE_11: Ensure that Azure Data Explorer encryption at rest uses a customer-managed key → NIST: SC-28(1)
  'CKV2_AZURE_11': ['CCI-002476'],
  // CKV2_AZURE_12: Ensure that virtual machines are backed up using Azure Backup → NIST: CM-6
  'CKV2_AZURE_12': ['CCI-000366'],
  // CKV2_AZURE_13: Ensure that sql servers enables data security policy → NIST: CM-6
  'CKV2_AZURE_13': ['CCI-000366'],
  // CKV2_AZURE_14: Ensure that Unattached disks are encrypted → NIST: SC-13
  'CKV2_AZURE_14': ['CCI-002450'],
  // CKV2_AZURE_15: Ensure that Azure data factories are encrypted with a customer-managed key → NIST: SC-28(1), SC-12(1)
  'CKV2_AZURE_15': ['CCI-002476', 'CCI-002451'],
  // CKV2_AZURE_16: Ensure that MySQL server enables customer-managed key for encryption → NIST: SC-28(1), SC-12(1)
  'CKV2_AZURE_16': ['CCI-002476', 'CCI-002451'],
  // CKV2_AZURE_17: Ensure that PostgreSQL server enables customer-managed key for encryption → NIST: SC-28(1), SC-12(1)
  'CKV2_AZURE_17': ['CCI-002476', 'CCI-002451'],
  // CKV2_AZURE_19: Ensure that Azure Synapse workspaces have no IP firewall rules attached → NIST: SC-7(4)
  'CKV2_AZURE_19': ['CCI-001099'],
  // CKV2_AZURE_2: Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setti... → NIST: RA-5(2)
  'CKV2_AZURE_2': ['CCI-001645'],
  // CKV2_AZURE_20: Ensure Storage logging is enabled for Table service for read requests → NIST: AU-2, AU-12
  'CKV2_AZURE_20': ['CCI-000130', 'CCI-000169'],
  // CKV2_AZURE_21: Ensure Storage logging is enabled for Blob service for read requests → NIST: AU-2, AU-12
  'CKV2_AZURE_21': ['CCI-000130', 'CCI-000169'],
  // CKV2_AZURE_22: Ensure that Cognitive Services enables customer-managed key for encryption → NIST: SC-28(1), SC-12(1)
  'CKV2_AZURE_22': ['CCI-002476', 'CCI-002451'],
  // CKV2_AZURE_23: Ensure Azure spring cloud is configured with Virtual network (Vnet) → NIST: CM-6
  'CKV2_AZURE_23': ['CCI-000366'],
  // CKV2_AZURE_24: Ensure Azure automation account does NOT have overly permissive network access → NIST: CM-6
  'CKV2_AZURE_24': ['CCI-000366'],
  // CKV2_AZURE_25: Ensure Azure SQL database Transparent Data Encryption (TDE) is enabled → NIST: SC-13
  'CKV2_AZURE_25': ['CCI-002450'],
  // CKV2_AZURE_26: Ensure Azure PostgreSQL Flexible server is not configured with overly permiss... → NIST: CM-6
  'CKV2_AZURE_26': ['CCI-000366'],
  // CKV2_AZURE_27: Ensure Azure AD authentication is enabled for Azure SQL (MSSQL) → NIST: CM-6
  'CKV2_AZURE_27': ['CCI-000366'],
  // CKV2_AZURE_29: Ensure AKS cluster has Azure CNI networking enabled → NIST: CM-6
  'CKV2_AZURE_29': ['CCI-000366'],
  // CKV2_AZURE_3: Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server → NIST: CM-6
  'CKV2_AZURE_3': ['CCI-000366'],
  // CKV2_AZURE_30: Ensure Azure Container Registry (ACR) has HTTPS enabled for webhook → NIST: SC-8(1)
  'CKV2_AZURE_30': ['CCI-002420'],
  // CKV2_AZURE_31: Ensure VNET subnet is configured with a Network Security Group (NSG) → NIST: SC-7(3)
  'CKV2_AZURE_31': ['CCI-001098'],
  // CKV2_AZURE_32: Ensure private endpoint is configured to key vault → NIST: SC-7(3)
  'CKV2_AZURE_32': ['CCI-001098'],
  // CKV2_AZURE_33: Ensure storage account is configured with private endpoint → NIST: SC-7(3)
  'CKV2_AZURE_33': ['CCI-001098'],
  // CKV2_AZURE_34: Ensure Azure SQL server firewall is not overly permissive → NIST: CM-6
  'CKV2_AZURE_34': ['CCI-000366'],
  // CKV2_AZURE_37: Ensure Azure MariaDB server is using latest TLS (1.2) → NIST: SC-8(1), SC-13
  'CKV2_AZURE_37': ['CCI-002420', 'CCI-002450'],
  // CKV2_AZURE_38: Ensure soft-delete is enabled on Azure storage account → NIST: CM-6
  'CKV2_AZURE_38': ['CCI-000366'],
  // CKV2_AZURE_39: Ensure Azure VM is not configured with public IP and serial console access → NIST: SC-7(5), AC-3
  'CKV2_AZURE_39': ['CCI-001100', 'CCI-000213'],
  // CKV2_AZURE_4: Ensure Azure SQL server ADS VA Send scan reports to is configured → NIST: RA-5(1), SI-2(1)
  'CKV2_AZURE_4': ['CCI-001644', 'CCI-002606'],
  // CKV2_AZURE_40: Ensure storage account is not configured with Shared Key authorization → NIST: CM-6
  'CKV2_AZURE_40': ['CCI-000366'],
  // CKV2_AZURE_41: Ensure storage account is configured with SAS expiration policy → NIST: CM-6
  'CKV2_AZURE_41': ['CCI-000366'],
  // CKV2_AZURE_42: Ensure Azure PostgreSQL server is configured with private endpoint → NIST: SC-7(3)
  'CKV2_AZURE_42': ['CCI-001098'],
  // CKV2_AZURE_43: Ensure Azure MariaDB server is configured with private endpoint → NIST: SC-7(3)
  'CKV2_AZURE_43': ['CCI-001098'],
  // CKV2_AZURE_44: Ensure Azure MySQL server is configured with private endpoint → NIST: SC-7(3)
  'CKV2_AZURE_44': ['CCI-001098'],
  // CKV2_AZURE_45: Ensure Microsoft SQL server is configured with private endpoint → NIST: SC-7(3)
  'CKV2_AZURE_45': ['CCI-001098'],
  // CKV2_AZURE_46: Ensure that Azure Synapse Workspace vulnerability assessment is enabled → NIST: RA-5(2)
  'CKV2_AZURE_46': ['CCI-001645'],
  // CKV2_AZURE_47: Ensure storage account is configured without blob anonymous access → NIST: CM-6
  'CKV2_AZURE_47': ['CCI-000366'],
  // CKV2_AZURE_48: Ensure that Databricks Workspaces enables customer-managed key for root DBFS ... → NIST: SC-28(1), SC-12(1)
  'CKV2_AZURE_48': ['CCI-002476', 'CCI-002451'],
  // CKV2_AZURE_49: Ensure that Azure Machine learning workspace is not configured with overly pe... → NIST: CM-6
  'CKV2_AZURE_49': ['CCI-000366'],
  // CKV2_AZURE_5: Ensure that VA setting 'Also send email notifications to admins and subscript... → NIST: CM-6
  'CKV2_AZURE_5': ['CCI-000366'],
  // CKV2_AZURE_50: Ensure Azure Storage Account storing Machine Learning workspace high business... → NIST: SC-7(5), AC-3
  'CKV2_AZURE_50': ['CCI-001100', 'CCI-000213'],
  // CKV2_AZURE_51: Ensure Synapse SQL Pool has a security alert policy → NIST: CM-6
  'CKV2_AZURE_51': ['CCI-000366'],
  // CKV2_AZURE_52: Ensure Synapse SQL Pool has vulnerability assessment attached → NIST: RA-5(2)
  'CKV2_AZURE_52': ['CCI-001645'],
  // CKV2_AZURE_53: Ensure Azure Synapse Workspace has extended audit logs → NIST: AU-2, AU-12
  'CKV2_AZURE_53': ['CCI-000130', 'CCI-000169'],
  // CKV2_AZURE_54: Ensure log monitoring is enabled for Synapse SQL Pool → NIST: AU-3(1), AU-12
  'CKV2_AZURE_54': ['CCI-000135', 'CCI-000169'],
  // CKV2_AZURE_55: Ensure Azure Spring Cloud app end-to-end TLS is enabled → NIST: SC-8(1)
  'CKV2_AZURE_55': ['CCI-002420'],
  // CKV2_AZURE_56: Ensure Azure MySQL Flexible Server is configured with private endpoint → NIST: SC-7(3)
  'CKV2_AZURE_56': ['CCI-001098'],
  // CKV2_AZURE_57: Ensure PostgreSQL Flexible Server is configured with private endpoint → NIST: SC-7(3)
  'CKV2_AZURE_57': ['CCI-001098'],
  // CKV2_AZURE_6: Ensure 'Allow access to Azure services' for PostgreSQL Database Server is dis... → NIST: CM-6
  'CKV2_AZURE_6': ['CCI-000366'],
  // CKV2_AZURE_7: Ensure that Azure Active Directory Admin is configured → NIST: CM-6
  'CKV2_AZURE_7': ['CCI-000366'],
  // CKV2_AZURE_8: Ensure the storage container storing the activity logs is not publicly access... → NIST: SC-7(5), AC-3
  'CKV2_AZURE_8': ['CCI-001100', 'CCI-000213'],
  // CKV2_AZURE_9: Ensure Virtual Machines are utilizing Managed Disks → NIST: CM-6
  'CKV2_AZURE_9': ['CCI-000366'],
  // CKV2_DOCKER_1: Ensure that sudo isn't used → NIST: CM-6
  'CKV2_DOCKER_1': ['CCI-000366'],
  // CKV2_DOCKER_10: Ensure that packages with untrusted or missing signatures are not used by rpm... → NIST: SI-7(6), SR-3
  'CKV2_DOCKER_10': ['CCI-002705', 'CCI-003610'],
  // CKV2_DOCKER_11: Ensure that the '--force-yes' option is not used, as it disables signature va... → NIST: SI-7(6), SR-3
  'CKV2_DOCKER_11': ['CCI-002705', 'CCI-003610'],
  // CKV2_DOCKER_12: Ensure that certificate validation isn't disabled for npm via the 'NPM_CONFIG... → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_12': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_13: Ensure that certificate validation isn't disabled for npm or yarn by setting ... → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_13': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_14: Ensure that certificate validation isn't disabled for git by setting the envi... → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_14': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_15: Ensure that the yum and dnf package managers are not configured to disable SS... → NIST: SC-8(1)
  'CKV2_DOCKER_15': ['CCI-002420'],
  // CKV2_DOCKER_16: Ensure that certificate validation isn't disabled with pip via the 'PIP_TRUST... → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_16': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_17: Ensure that 'chpasswd' is not used to set or remove passwords → NIST: CM-6
  'CKV2_DOCKER_17': ['CCI-000366'],
  // CKV2_DOCKER_2: Ensure that certificate validation isn't disabled with curl → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_2': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_3: Ensure that certificate validation isn't disabled with wget → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_3': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_4: Ensure that certificate validation isn't disabled with the pip '--trusted-hos... → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_4': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_5: Ensure that certificate validation isn't disabled with the PYTHONHTTPSVERIFY ... → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_5': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_6: Ensure that certificate validation isn't disabled with the NODE_TLS_REJECT_UN... → NIST: SC-8(1), SC-17
  'CKV2_DOCKER_6': ['CCI-002420', 'CCI-002448'],
  // CKV2_DOCKER_7: Ensure that packages with untrusted or missing signatures are not used by apk... → NIST: SI-7(6), SR-3
  'CKV2_DOCKER_7': ['CCI-002705', 'CCI-003610'],
  // CKV2_DOCKER_8: Ensure that packages with untrusted or missing signatures are not used by apt... → NIST: SI-7(6), SR-3
  'CKV2_DOCKER_8': ['CCI-002705', 'CCI-003610'],
  // CKV2_DOCKER_9: Ensure that packages with untrusted or missing GPG signatures are not used by... → NIST: SI-7(6), SR-3
  'CKV2_DOCKER_9': ['CCI-002705', 'CCI-003610'],
  // CKV2_GCP_1: Ensure GKE clusters are not running using the Compute Engine default service ... → NIST: AC-6(5), CM-6(1)
  'CKV2_GCP_1': ['CCI-000230', 'CCI-001515'],
  // CKV2_GCP_10: Ensure GCP Cloud Function HTTP trigger is secured → NIST: CM-6
  'CKV2_GCP_10': ['CCI-000366'],
  // CKV2_GCP_11: Ensure GCP GCR Container Vulnerability Scanning is enabled → NIST: RA-5(2)
  'CKV2_GCP_11': ['CCI-001645'],
  // CKV2_GCP_12: Ensure GCP compute firewall ingress does not allow unrestricted access to all... → NIST: SC-7(5)
  'CKV2_GCP_12': ['CCI-001100'],
  // CKV2_GCP_13: Ensure PostgreSQL database flag 'log_duration' is set to 'on' → NIST: CM-6
  'CKV2_GCP_13': ['CCI-000366'],
  // CKV2_GCP_14: Ensure PostgreSQL database flag 'log_executor_stats' is set to 'off' → NIST: CM-6
  'CKV2_GCP_14': ['CCI-000366'],
  // CKV2_GCP_15: Ensure PostgreSQL database flag 'log_parser_stats' is set to 'off' → NIST: CM-6
  'CKV2_GCP_15': ['CCI-000366'],
  // CKV2_GCP_16: Ensure PostgreSQL database flag 'log_planner_stats' is set to 'off' → NIST: CM-6
  'CKV2_GCP_16': ['CCI-000366'],
  // CKV2_GCP_17: Ensure PostgreSQL database flag 'log_statement_stats' is set to 'off' → NIST: CM-6
  'CKV2_GCP_17': ['CCI-000366'],
  // CKV2_GCP_18: Ensure GCP network defines a firewall and does not use the default firewall → NIST: SC-7(4)
  'CKV2_GCP_18': ['CCI-001099'],
  // CKV2_GCP_19: Ensure GCP Kubernetes engine clusters have 'alpha cluster' feature disabled → NIST: CM-7(2)
  'CKV2_GCP_19': ['CCI-001521'],
  // CKV2_GCP_2: Ensure legacy networks do not exist for a project → NIST: CM-6
  'CKV2_GCP_2': ['CCI-000366'],
  // CKV2_GCP_20: Ensure MySQL DB instance has point-in-time recovery backup configured → NIST: CP-9(1)
  'CKV2_GCP_20': ['CCI-000510'],
  // CKV2_GCP_21: Ensure Vertex AI instance disks are encrypted with a Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_21': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_22: Ensure Document AI Processors are encrypted with a Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_22': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_23: Ensure Document AI Warehouse Location is configured to use a Customer Managed... → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_23': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_24: Ensure Vertex AI endpoint uses a Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_24': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_25: Ensure Vertex AI featurestore uses a Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_25': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_26: Ensure Vertex AI tensorboard uses a Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_26': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_27: Ensure Vertex AI workbench instance disks are encrypted with a Customer Manag... → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_27': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_28: Ensure Vertex AI workbench instances are private → NIST: CM-6
  'CKV2_GCP_28': ['CCI-000366'],
  // CKV2_GCP_29: Ensure logging is enabled for Dialogflow agents → NIST: AU-2, AU-12
  'CKV2_GCP_29': ['CCI-000130', 'CCI-000169'],
  // CKV2_GCP_3: Ensure that there are only GCP-managed service account keys for each service ... → NIST: CM-6
  'CKV2_GCP_3': ['CCI-000366'],
  // CKV2_GCP_30: Ensure logging is enabled for Dialogflow CX agents → NIST: AU-2, AU-12
  'CKV2_GCP_30': ['CCI-000130', 'CCI-000169'],
  // CKV2_GCP_31: Ensure logging is enabled for Dialogflow CX webhooks → NIST: AU-2, AU-12
  'CKV2_GCP_31': ['CCI-000130', 'CCI-000169'],
  // CKV2_GCP_32: Ensure TPU v2 is private → NIST: CM-6
  'CKV2_GCP_32': ['CCI-000366'],
  // CKV2_GCP_33: Ensure Vertex AI endpoint is private → NIST: CM-6
  'CKV2_GCP_33': ['CCI-000366'],
  // CKV2_GCP_34: Ensure Vertex AI index endpoint is private → NIST: CM-6
  'CKV2_GCP_34': ['CCI-000366'],
  // CKV2_GCP_35: Ensure Vertex AI runtime is encrypted with a Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_35': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_36: Ensure Vertex AI runtime is private → NIST: SC-7(3)
  'CKV2_GCP_36': ['CCI-001098'],
  // CKV2_GCP_37: Ensure GCP compute regional forwarding rule does not use HTTP proxies with EX... → NIST: CM-6
  'CKV2_GCP_37': ['CCI-000366'],
  // CKV2_GCP_38: Ensure GCP compute global forwarding rule does not use HTTP proxies with EXTE... → NIST: CM-6
  'CKV2_GCP_38': ['CCI-000366'],
  // CKV2_GCP_4: Ensure that retention policies on log buckets are configured using Bucket Lock → NIST: AU-2, AU-12
  'CKV2_GCP_4': ['CCI-000130', 'CCI-000169'],
  // CKV2_GCP_5: Ensure that Cloud Audit Logging is configured properly across all services an... → NIST: AU-2, AU-12
  'CKV2_GCP_5': ['CCI-000130', 'CCI-000169'],
  // CKV2_GCP_6: Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_6': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_7: Ensure that a MySQL database instance does not allow anyone to connect with a... → NIST: CM-6
  'CKV2_GCP_7': ['CCI-000366'],
  // CKV2_GCP_8: Ensure that Cloud KMS Key Rings are not anonymously or publicly accessible → NIST: SC-28(1), SC-12(1)
  'CKV2_GCP_8': ['CCI-002476', 'CCI-002451'],
  // CKV2_GCP_9: Ensure that Container Registry repositories are not anonymously or publicly a... → NIST: SC-7(5), AC-3
  'CKV2_GCP_9': ['CCI-001100', 'CCI-000213'],
  // CKV2_GHA_1: Ensure top-level permissions are not set to write-all → NIST: CM-6
  'CKV2_GHA_1': ['CCI-000366'],
  // CKV2_GIT_1: Ensure each Repository has branch protection associated → NIST: CM-6
  'CKV2_GIT_1': ['CCI-000366'],
  // CKV2_IBM_1: Ensure load balancer for VPC is private (disable public access) → NIST: SC-7(3)
  'CKV2_IBM_1': ['CCI-001098'],
  // CKV2_IBM_2: Ensure VPC classic access is disabled → NIST: SC-7(3)
  'CKV2_IBM_2': ['CCI-001098'],
  // CKV2_IBM_3: Ensure API key creation is restricted in account settings → NIST: AC-2(3), IA-5(1)
  'CKV2_IBM_3': ['CCI-000018', 'CCI-000192'],
  // CKV2_IBM_4: Ensure Multi-Factor Authentication (MFA) is enabled at the account level → NIST: IA-2(1), IA-2(2)
  'CKV2_IBM_4': ['CCI-000765', 'CCI-000766'],
  // CKV2_IBM_5: Ensure Service ID creation is restricted in account settings → NIST: CM-6
  'CKV2_IBM_5': ['CCI-000366'],
  // CKV2_IBM_7: Ensure Kubernetes clusters are accessible by using private endpoint and NOT p... → NIST: SC-7(3)
  'CKV2_IBM_7': ['CCI-001098'],
  // CKV2_K8S_1: RoleBinding should not allow privilege escalation to a ServiceAccount or Node... → NIST: AC-6(1), AC-6(5)
  'CKV2_K8S_1': ['CCI-000226', 'CCI-000230'],
  // CKV2_K8S_2: Granting `create` permissions to `nodes/proxy` or `pods/exec` sub resources a... → NIST: CM-6
  'CKV2_K8S_2': ['CCI-000366'],
  // CKV2_K8S_3: No ServiceAccount/Node should have `impersonate` permissions for groups/users... → NIST: CM-6
  'CKV2_K8S_3': ['CCI-000366'],
  // CKV2_K8S_4: ServiceAccounts and nodes that can modify services/status may set the `status... → NIST: CM-6
  'CKV2_K8S_4': ['CCI-000366'],
  // CKV2_K8S_5: No ServiceAccount/Node should be able to read all secrets → NIST: CM-6
  'CKV2_K8S_5': ['CCI-000366'],
  // CKV2_K8S_6: Minimize the admission of pods which lack an associated NetworkPolicy → NIST: CM-6(1), SI-7(1)
  'CKV2_K8S_6': ['CCI-001515', 'CCI-002700'],
  // CKV2_OCI_1: Ensure administrator users are not associated with API keys → NIST: AC-6(1), AC-6(5)
  'CKV2_OCI_1': ['CCI-000226', 'CCI-000230'],
  // CKV2_OCI_2: Ensure NSG does not allow all traffic on RDP port (3389) → NIST: SC-7(4)
  'CKV2_OCI_2': ['CCI-001099'],
  // CKV2_OCI_3: Ensure Kubernetes engine cluster is configured with NSG(s) → NIST: CM-6
  'CKV2_OCI_3': ['CCI-000366'],
  // CKV2_OCI_4: Ensure File Storage File System access is restricted to root users → NIST: AC-6(1), AC-6(5)
  'CKV2_OCI_4': ['CCI-000226', 'CCI-000230'],
  // CKV2_OCI_5: Ensure Kubernetes Engine Cluster boot volume is configured with in-transit da... → NIST: SC-13
  'CKV2_OCI_5': ['CCI-002450'],
  // CKV2_OCI_6: Ensure Kubernetes Engine Cluster pod security policy is enforced → NIST: CM-7(2), AC-6(10)
  'CKV2_OCI_6': ['CCI-001521', 'CCI-000235'],
  // CKV_ALI_1: Alibaba Cloud OSS bucket accessible to public → NIST: AC-3, SC-7(5)
  'CKV_ALI_1': ['CCI-000213', 'CCI-001100'],
  // CKV_ALI_10: Ensure OSS bucket has versioning enabled → NIST: CP-9(1), AU-9(2)
  'CKV_ALI_10': ['CCI-000510', 'CCI-000164'],
  // CKV_ALI_11: Ensure OSS bucket has transfer Acceleration enabled → NIST: CM-6
  'CKV_ALI_11': ['CCI-000366'],
  // CKV_ALI_12: Ensure the OSS bucket has access logging enabled → NIST: AU-2, AU-12
  'CKV_ALI_12': ['CCI-000130', 'CCI-000169'],
  // CKV_ALI_13: Ensure RAM password policy requires minimum length of 14 or greater → NIST: IA-5(1)
  'CKV_ALI_13': ['CCI-000192'],
  // CKV_ALI_14: Ensure RAM password policy requires at least one number → NIST: AC-6(1)
  'CKV_ALI_14': ['CCI-000226'],
  // CKV_ALI_15: Ensure RAM password policy requires at least one symbol → NIST: AC-6(1)
  'CKV_ALI_15': ['CCI-000226'],
  // CKV_ALI_16: Ensure RAM password policy expires passwords within 90 days or less → NIST: IA-5(1)
  'CKV_ALI_16': ['CCI-000192'],
  // CKV_ALI_17: Ensure RAM password policy requires at least one lowercase letter → NIST: AC-6(1)
  'CKV_ALI_17': ['CCI-000226'],
  // CKV_ALI_18: Ensure RAM password policy prevents password reuse → NIST: IA-5(1)
  'CKV_ALI_18': ['CCI-000192'],
  // CKV_ALI_19: Ensure RAM password policy requires at least one uppercase letter → NIST: AC-6(1)
  'CKV_ALI_19': ['CCI-000226'],
  // CKV_ALI_2: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 → NIST: SC-7(5)
  'CKV_ALI_2': ['CCI-001100'],
  // CKV_ALI_20: Ensure RDS instance uses SSL → NIST: CM-6
  'CKV_ALI_20': ['CCI-000366'],
  // CKV_ALI_21: Ensure API Gateway API Protocol HTTPS → NIST: CM-6
  'CKV_ALI_21': ['CCI-000366'],
  // CKV_ALI_22: Ensure Transparent Data Encryption is Enabled on instance → NIST: SC-13
  'CKV_ALI_22': ['CCI-002450'],
  // CKV_ALI_23: Ensure Ram Account Password Policy Max Login Attempts not > 5 → NIST: IA-5(1)
  'CKV_ALI_23': ['CCI-000192'],
  // CKV_ALI_24: Ensure RAM enforces MFA → NIST: IA-2(1), IA-2(2)
  'CKV_ALI_24': ['CCI-000765', 'CCI-000766'],
  // CKV_ALI_25: Ensure RDS Instance SQL Collector Retention Period should be greater than 180 → NIST: CM-6
  'CKV_ALI_25': ['CCI-000366'],
  // CKV_ALI_26: Ensure Kubernetes installs plugin Terway or Flannel to support standard policies → NIST: CM-6
  'CKV_ALI_26': ['CCI-000366'],
  // CKV_ALI_27: Ensure KMS Key Rotation is enabled → NIST: SC-28(1), SC-12(1)
  'CKV_ALI_27': ['CCI-002476', 'CCI-002451'],
  // CKV_ALI_28: Ensure KMS Keys are enabled → NIST: SC-28(1), SC-12(1)
  'CKV_ALI_28': ['CCI-002476', 'CCI-002451'],
  // CKV_ALI_29: Alibaba ALB ACL does not restrict Access → NIST: SC-7(9), AU-12(1)
  'CKV_ALI_29': ['CCI-001104', 'CCI-000172'],
  // CKV_ALI_3: Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 → NIST: SC-7(5)
  'CKV_ALI_3': ['CCI-001100'],
  // CKV_ALI_30: Ensure RDS instance auto upgrades for minor versions → NIST: CM-6
  'CKV_ALI_30': ['CCI-000366'],
  // CKV_ALI_31: Ensure K8s nodepools are set to auto repair → NIST: CM-6
  'CKV_ALI_31': ['CCI-000366'],
  // CKV_ALI_32: Ensure launch template data disks are encrypted → NIST: SC-13
  'CKV_ALI_32': ['CCI-002450'],
  // CKV_ALI_33: Alibaba Cloud Cypher Policy are secure → NIST: CM-6
  'CKV_ALI_33': ['CCI-000366'],
  // CKV_ALI_35: Ensure RDS instance has log_duration enabled → NIST: CM-6
  'CKV_ALI_35': ['CCI-000366'],
  // CKV_ALI_36: Ensure RDS instance has log_disconnections enabled → NIST: CM-6
  'CKV_ALI_36': ['CCI-000366'],
  // CKV_ALI_37: Ensure RDS instance has log_connections enabled → NIST: CM-6
  'CKV_ALI_37': ['CCI-000366'],
  // CKV_ALI_38: Ensure log audit is enabled for RDS → NIST: AU-2, AU-12
  'CKV_ALI_38': ['CCI-000130', 'CCI-000169'],
  // CKV_ALI_4: Ensure Action Trail Logging for all regions → NIST: AU-2, AU-12
  'CKV_ALI_4': ['CCI-000130', 'CCI-000169'],
  // CKV_ALI_41: Ensure MongoDB is deployed inside a VPC → NIST: SC-7(3)
  'CKV_ALI_41': ['CCI-001098'],
  // CKV_ALI_42: Ensure Mongodb instance uses SSL → NIST: CM-6
  'CKV_ALI_42': ['CCI-000366'],
  // CKV_ALI_43: Ensure MongoDB instance is not public → NIST: AC-3, SC-7(5)
  'CKV_ALI_43': ['CCI-000213', 'CCI-001100'],
  // CKV_ALI_44: Ensure MongoDB has Transparent Data Encryption Enabled → NIST: SC-13
  'CKV_ALI_44': ['CCI-002450'],
  // CKV_ALI_5: Ensure Action Trail Logging for all events → NIST: AU-2, AU-12
  'CKV_ALI_5': ['CCI-000130', 'CCI-000169'],
  // CKV_ALI_6: Ensure OSS bucket is encrypted with Customer Master Key → NIST: SC-13
  'CKV_ALI_6': ['CCI-002450'],
  // CKV_ALI_7: Ensure disk is encrypted → NIST: SC-28(1)
  'CKV_ALI_7': ['CCI-002476'],
  // CKV_ALI_8: Ensure Disk is encrypted with Customer Master Key → NIST: SC-28(1)
  'CKV_ALI_8': ['CCI-002476'],
  // CKV_ALI_9: Ensure database instance is not public → NIST: AC-3, SC-7(5)
  'CKV_ALI_9': ['CCI-000213', 'CCI-001100'],
  // CKV_ANSIBLE_1: Ensure that certificate validation isn't disabled with uri → NIST: SC-8(1), SC-17
  'CKV_ANSIBLE_1': ['CCI-002420', 'CCI-002448'],
  // CKV_ANSIBLE_2: Ensure that certificate validation isn't disabled with get_url → NIST: SC-8(1), SC-17
  'CKV_ANSIBLE_2': ['CCI-002420', 'CCI-002448'],
  // CKV_ANSIBLE_3: Ensure that certificate validation isn't disabled with yum → NIST: SC-8(1), SC-17
  'CKV_ANSIBLE_3': ['CCI-002420', 'CCI-002448'],
  // CKV_ANSIBLE_4: Ensure that SSL validation isn't disabled with yum → NIST: CM-6
  'CKV_ANSIBLE_4': ['CCI-000366'],
  // CKV_ANSIBLE_5: Ensure that packages with untrusted or missing signatures are not used → NIST: SI-7(6), SR-3
  'CKV_ANSIBLE_5': ['CCI-002705', 'CCI-003610'],
  // CKV_ANSIBLE_6: Ensure that the force parameter is not used, as it disables signature validat... → NIST: SI-7(6), SR-3
  'CKV_ANSIBLE_6': ['CCI-002705', 'CCI-003610'],
  // CKV_ARGO_1: Ensure Workflow pods are not using the default ServiceAccount → NIST: AC-6(5), CM-6(1)
  'CKV_ARGO_1': ['CCI-000230', 'CCI-001515'],
  // CKV_ARGO_2: Ensure Workflow pods are running as non-root user → NIST: AC-6(1), AC-6(5)
  'CKV_ARGO_2': ['CCI-000226', 'CCI-000230'],
  // CKV_AWS_1: Ensure IAM policies that allow full "*-*" administrative privileges are not c... → NIST: AC-6(10), AC-6(1)
  'CKV_AWS_1': ['CCI-000235', 'CCI-000226'],
  // CKV_AWS_10: Ensure IAM password policy requires minimum length of 14 or greater → NIST: IA-5(1)
  'CKV_AWS_10': ['CCI-000192'],
  // CKV_AWS_100: Ensure AWS EKS node group does not have implicit SSH access from 0.0.0.0/0 → NIST: AC-17(2), IA-2(6)
  'CKV_AWS_100': ['CCI-000069', 'CCI-001941'],
  // CKV_AWS_101: Ensure Neptune logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_101': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_102: Ensure Neptune Cluster instance is not publicly available → NIST: CM-6
  'CKV_AWS_102': ['CCI-000366'],
  // CKV_AWS_103: Ensure that Load Balancer Listener is using at least TLS v1.2 → NIST: SC-8(1), SC-13
  'CKV_AWS_103': ['CCI-002420', 'CCI-002450'],
  // CKV_AWS_104: Ensure DocumentDB has audit logs enabled → NIST: AU-2, AU-12
  'CKV_AWS_104': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_105: Ensure Redshift uses SSL → NIST: CM-6
  'CKV_AWS_105': ['CCI-000366'],
  // CKV_AWS_106: Ensure EBS default encryption is enabled → NIST: SC-13
  'CKV_AWS_106': ['CCI-002450'],
  // CKV_AWS_107: Ensure IAM policies does not allow credentials exposure → NIST: CM-6
  'CKV_AWS_107': ['CCI-000366'],
  // CKV_AWS_108: Ensure IAM policies does not allow data exfiltration → NIST: SC-28(1), MP-4
  'CKV_AWS_108': ['CCI-002476', 'CCI-001821'],
  // CKV_AWS_109: Ensure IAM policies does not allow permissions management without constraints → NIST: CM-6
  'CKV_AWS_109': ['CCI-000366'],
  // CKV_AWS_11: Ensure IAM password policy requires at least one lowercase letter → NIST: AC-6(1)
  'CKV_AWS_11': ['CCI-000226'],
  // CKV_AWS_110: Ensure IAM policies does not allow privilege escalation → NIST: CM-6
  'CKV_AWS_110': ['CCI-000366'],
  // CKV_AWS_111: Ensure IAM policies does not allow write access without constraints → NIST: CM-6
  'CKV_AWS_111': ['CCI-000366'],
  // CKV_AWS_112: Ensure Session Manager data is encrypted in transit → NIST: SC-8(1)
  'CKV_AWS_112': ['CCI-002420'],
  // CKV_AWS_113: Ensure Session Manager logs are enabled and encrypted → NIST: SC-13
  'CKV_AWS_113': ['CCI-002450'],
  // CKV_AWS_114: Ensure that EMR clusters with Kerberos have Kerberos Realm set → NIST: CM-6
  'CKV_AWS_114': ['CCI-000366'],
  // CKV_AWS_115: Ensure that AWS Lambda function is configured for function-level concurrent e... → NIST: CM-6
  'CKV_AWS_115': ['CCI-000366'],
  // CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) → NIST: CM-6
  'CKV_AWS_116': ['CCI-000366'],
  // CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC → NIST: SC-7(3)
  'CKV_AWS_117': ['CCI-001098'],
  // CKV_AWS_118: Ensure that enhanced monitoring is enabled for Amazon RDS instances → NIST: AU-2, AU-12
  'CKV_AWS_118': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_119: Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_119': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_12: Ensure IAM password policy requires at least one number → NIST: AC-6(1)
  'CKV_AWS_12': ['CCI-000226'],
  // CKV_AWS_120: Ensure API Gateway caching is enabled → NIST: CM-6(1)
  'CKV_AWS_120': ['CCI-001515'],
  // CKV_AWS_121: Ensure AWS Config is enabled in all regions → NIST: CM-6
  'CKV_AWS_121': ['CCI-000366'],
  // CKV_AWS_122: Ensure that direct internet access is disabled for an Amazon SageMaker Notebo... → NIST: CM-6
  'CKV_AWS_122': ['CCI-000366'],
  // CKV_AWS_123: Ensure that VPC Endpoint Service is configured for Manual Acceptance → NIST: SC-7(3)
  'CKV_AWS_123': ['CCI-001098'],
  // CKV_AWS_124: Ensure that CloudFormation stacks are sending event notifications to an SNS t... → NIST: SI-4(5), IR-6(1)
  'CKV_AWS_124': ['CCI-002687', 'CCI-000229'],
  // CKV_AWS_126: Ensure that detailed monitoring is enabled for EC2 instances → NIST: AU-2, AU-12
  'CKV_AWS_126': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_127: Ensure that Elastic Load Balancer(s) uses SSL certificates provided by AWS Ce... → NIST: SC-8(1), SC-7(4)
  'CKV_AWS_127': ['CCI-002420', 'CCI-001099'],
  // CKV_AWS_129: Ensure that respective logs of Amazon Relational Database Service (Amazon RDS... → NIST: AU-2, AU-12
  'CKV_AWS_129': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_13: Ensure IAM password policy prevents password reuse → NIST: IA-5(1)
  'CKV_AWS_13': ['CCI-000192'],
  // CKV_AWS_130: Ensure VPC subnets do not assign public IP by default → NIST: SC-7(3)
  'CKV_AWS_130': ['CCI-001098'],
  // CKV_AWS_131: Ensure that ALB drops HTTP headers → NIST: CM-6
  'CKV_AWS_131': ['CCI-000366'],
  // CKV_AWS_133: Ensure that RDS instances has backup policy → NIST: CM-6
  'CKV_AWS_133': ['CCI-000366'],
  // CKV_AWS_134: Ensure that Amazon ElastiCache Redis clusters have automatic backup turned on → NIST: CM-6
  'CKV_AWS_134': ['CCI-000366'],
  // CKV_AWS_135: Ensure that EC2 is EBS optimized → NIST: CM-6
  'CKV_AWS_135': ['CCI-000366'],
  // CKV_AWS_136: Ensure that ECR repositories are encrypted using KMS → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_136': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_137: Ensure that Elasticsearch is configured inside a VPC → NIST: SC-7(3)
  'CKV_AWS_137': ['CCI-001098'],
  // CKV_AWS_138: Ensure that ELB is cross-zone-load-balancing enabled → NIST: CM-6
  'CKV_AWS_138': ['CCI-000366'],
  // CKV_AWS_139: Ensure that RDS clusters have deletion protection enabled → NIST: CM-6
  'CKV_AWS_139': ['CCI-000366'],
  // CKV_AWS_14: Ensure IAM password policy requires at least one symbol → NIST: AC-6(1)
  'CKV_AWS_14': ['CCI-000226'],
  // CKV_AWS_140: Ensure that RDS global clusters are encrypted → NIST: SC-13
  'CKV_AWS_140': ['CCI-002450'],
  // CKV_AWS_141: Ensured that Redshift cluster allowing version upgrade by default → NIST: SI-2(2)
  'CKV_AWS_141': ['CCI-002607'],
  // CKV_AWS_142: Ensure that Redshift cluster is encrypted by KMS → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_142': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_143: Ensure that S3 bucket has lock configuration enabled by default → NIST: CM-6
  'CKV_AWS_143': ['CCI-000366'],
  // CKV_AWS_144: Ensure that S3 bucket has cross-region replication enabled → NIST: CP-6(1), CP-9(3)
  'CKV_AWS_144': ['CCI-000504', 'CCI-000512'],
  // CKV_AWS_145: Ensure that S3 buckets are encrypted with KMS by default → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_145': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_146: Ensure that RDS database cluster snapshot is encrypted → NIST: SC-13
  'CKV_AWS_146': ['CCI-002450'],
  // CKV_AWS_147: Ensure that CodeBuild projects are encrypted using CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_147': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_148: Ensure no default VPC is planned to be provisioned → NIST: SC-7(3)
  'CKV_AWS_148': ['CCI-001098'],
  // CKV_AWS_149: Ensure that Secrets Manager secret is encrypted using KMS CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_149': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_15: Ensure IAM password policy requires at least one uppercase letter → NIST: AC-6(1)
  'CKV_AWS_15': ['CCI-000226'],
  // CKV_AWS_150: Ensure that Load Balancer has deletion protection enabled → NIST: CM-6
  'CKV_AWS_150': ['CCI-000366'],
  // CKV_AWS_152: Ensure that Load Balancer (Network/Gateway) has cross-zone load balancing ena... → NIST: CM-6
  'CKV_AWS_152': ['CCI-000366'],
  // CKV_AWS_153: Autoscaling groups should supply tags to launch configurations → NIST: CM-6
  'CKV_AWS_153': ['CCI-000366'],
  // CKV_AWS_154: Ensure Redshift is not deployed outside of a VPC → NIST: SC-7(3)
  'CKV_AWS_154': ['CCI-001098'],
  // CKV_AWS_155: Ensure that Workspace user volumes are encrypted → NIST: SC-13
  'CKV_AWS_155': ['CCI-002450'],
  // CKV_AWS_156: Ensure that Workspace root volumes are encrypted → NIST: SC-13
  'CKV_AWS_156': ['CCI-002450'],
  // CKV_AWS_157: Ensure that RDS instances have Multi-AZ enabled → NIST: CP-10(2), CP-9
  'CKV_AWS_157': ['CCI-000555', 'CCI-000509'],
  // CKV_AWS_158: Ensure that CloudWatch Log Group is encrypted by KMS → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_158': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_159: Ensure that Athena Workgroup is encrypted → NIST: SC-13
  'CKV_AWS_159': ['CCI-002450'],
  // CKV_AWS_16: Ensure all data stored in the RDS is securely encrypted at rest → NIST: SC-28(1)
  'CKV_AWS_16': ['CCI-002476'],
  // CKV_AWS_160: Ensure that Timestream database is encrypted with KMS CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_160': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_161: Ensure RDS database has IAM authentication enabled → NIST: CM-6
  'CKV_AWS_161': ['CCI-000366'],
  // CKV_AWS_162: Ensure RDS cluster has IAM authentication enabled → NIST: CM-6
  'CKV_AWS_162': ['CCI-000366'],
  // CKV_AWS_163: Ensure ECR image scanning on push is enabled → NIST: RA-5(1), SI-2(1)
  'CKV_AWS_163': ['CCI-001644', 'CCI-002606'],
  // CKV_AWS_164: Ensure Transfer Server is not exposed publicly. → NIST: CM-6
  'CKV_AWS_164': ['CCI-000366'],
  // CKV_AWS_165: Ensure DynamoDB global table point in time recovery (backup) is enabled → NIST: CP-9(1)
  'CKV_AWS_165': ['CCI-000510'],
  // CKV_AWS_166: Ensure Backup Vault is encrypted at rest using KMS CMK → NIST: SC-28(1)
  'CKV_AWS_166': ['CCI-002476'],
  // CKV_AWS_167: Ensure Glacier Vault access policy is not public by only allowing specific se... → NIST: SC-7(5), AC-3
  'CKV_AWS_167': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_168: Ensure SQS queue policy is not public by only allowing specific services or p... → NIST: SC-7(5), AC-3
  'CKV_AWS_168': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_169: Ensure SNS topic policy is not public by only allowing specific services or p... → NIST: SC-7(5), AC-3
  'CKV_AWS_169': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_17: Ensure all data stored in RDS is not publicly accessible → NIST: SC-7(5), AC-3
  'CKV_AWS_17': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_170: Ensure QLDB ledger permissions mode is set to STANDARD → NIST: CM-6
  'CKV_AWS_170': ['CCI-000366'],
  // CKV_AWS_171: Ensure EMR Cluster security configuration encryption is using SSE-KMS → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_171': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_172: Ensure QLDB ledger has deletion protection enabled → NIST: CM-6
  'CKV_AWS_172': ['CCI-000366'],
  // CKV_AWS_173: Check encryption settings for Lambda environment variable → NIST: IA-5(7), SC-28(1)
  'CKV_AWS_173': ['CCI-000190', 'CCI-002476'],
  // CKV_AWS_174: Verify CloudFront Distribution Viewer Certificate is using TLS v1.2 or higher → NIST: SC-8(1), SC-13
  'CKV_AWS_174': ['CCI-002420', 'CCI-002450'],
  // CKV_AWS_175: Ensure WAF has associated rules → NIST: SC-7(14), SC-5(1)
  'CKV_AWS_175': ['CCI-001109', 'CCI-002385'],
  // CKV_AWS_176: Ensure Logging is enabled for WAF Web Access Control Lists → NIST: SC-7(14), SC-5(1)
  'CKV_AWS_176': ['CCI-001109', 'CCI-002385'],
  // CKV_AWS_177: Ensure Kinesis Video Stream is encrypted by KMS using a customer managed Key ... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_177': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_178: Ensure fx ontap file system is encrypted by KMS using a customer managed Key ... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_178': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_179: Ensure FSX Windows filesystem is encrypted by KMS using a customer managed Ke... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_179': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_18: Ensure the S3 bucket has access logging enabled → NIST: AU-2, AU-12
  'CKV_AWS_18': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_180: Ensure Image Builder component is encrypted by KMS using a customer managed K... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_180': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_181: Ensure S3 Object Copy is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_181': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_182: Ensure DocumentDB is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_182': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_183: Ensure EBS Snapshot Copy is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_183': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_184: Ensure resource is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_184': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_185: Ensure Kinesis Stream is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_185': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_186: Ensure S3 bucket Object is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_186': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_187: Ensure Sagemaker domain and notebook instance are encrypted by KMS using a cu... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_187': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_189: Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_189': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_19: Ensure the S3 bucket has server-side-encryption enabled → NIST: SC-13
  'CKV_AWS_19': ['CCI-002450'],
  // CKV_AWS_190: Ensure lustre file systems is encrypted by KMS using a customer managed Key (... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_190': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_191: Ensure ElastiCache replication group is encrypted by KMS using a customer man... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_191': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_192: Ensure WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell → NIST: SC-7(14), SC-5(1)
  'CKV_AWS_192': ['CCI-001109', 'CCI-002385'],
  // CKV_AWS_193: Ensure AppSync has Logging enabled → NIST: AU-2, AU-12
  'CKV_AWS_193': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_194: Ensure AppSync has Field-Level logs enabled → NIST: AU-2, AU-12
  'CKV_AWS_194': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_195: Ensure Glue component has a security configuration associated → NIST: CM-6
  'CKV_AWS_195': ['CCI-000366'],
  // CKV_AWS_196: Ensure no aws_elasticache_security_group resources exist → NIST: CM-6
  'CKV_AWS_196': ['CCI-000366'],
  // CKV_AWS_197: Ensure MQ Broker Audit logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_197': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_198: Ensure no aws_db_security_group resources exist → NIST: CM-6
  'CKV_AWS_198': ['CCI-000366'],
  // CKV_AWS_199: Ensure Image Builder Distribution Configuration encrypts AMI's using KMS - a ... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_199': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_2: Ensure ALB protocol is HTTPS → NIST: SC-8(1), SC-7(4)
  'CKV_AWS_2': ['CCI-002420', 'CCI-001099'],
  // CKV_AWS_20: Ensure the S3 bucket does not allow READ permissions to everyone → NIST: CM-6
  'CKV_AWS_20': ['CCI-000366'],
  // CKV_AWS_200: Ensure that Image Recipe EBS Disk are encrypted with CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_200': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_201: Ensure MemoryDB is encrypted at rest using KMS CMKs → NIST: SC-28(1)
  'CKV_AWS_201': ['CCI-002476'],
  // CKV_AWS_202: Ensure MemoryDB data is encrypted in transit → NIST: SC-8(1)
  'CKV_AWS_202': ['CCI-002420'],
  // CKV_AWS_203: Ensure resource is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_203': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_204: Ensure AMIs are encrypted using KMS CMKs → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_204': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_205: Ensure to Limit AMI launch Permissions → NIST: AC-3
  'CKV_AWS_205': ['CCI-000213'],
  // CKV_AWS_206: Ensure API Gateway Domain uses a modern security Policy → NIST: SC-7(4), SC-20
  'CKV_AWS_206': ['CCI-001099'],
  // CKV_AWS_207: Ensure MQ Broker minor version updates are enabled → NIST: CM-6
  'CKV_AWS_207': ['CCI-000366'],
  // CKV_AWS_208: Ensure MQ Broker version is current → NIST: CM-6
  'CKV_AWS_208': ['CCI-000366'],
  // CKV_AWS_209: Ensure MQ broker encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_209': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_21: Ensure the S3 bucket has versioning enabled → NIST: CP-9(1), AU-9(2)
  'CKV_AWS_21': ['CCI-000510', 'CCI-000164'],
  // CKV_AWS_210: Batch job does not define a privileged container → NIST: CM-6
  'CKV_AWS_210': ['CCI-000366'],
  // CKV_AWS_211: Ensure RDS uses a modern CaCert → NIST: CM-6
  'CKV_AWS_211': ['CCI-000366'],
  // CKV_AWS_212: Ensure DMS replication instance is encrypted by KMS using a customer managed ... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_212': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_213: Ensure ELB Policy uses only secure protocols → NIST: SC-8(1), SC-7(4)
  'CKV_AWS_213': ['CCI-002420', 'CCI-001099'],
  // CKV_AWS_214: Ensure AppSync API Cache is encrypted at rest → NIST: SC-28(1)
  'CKV_AWS_214': ['CCI-002476'],
  // CKV_AWS_215: Ensure AppSync API Cache is encrypted in transit → NIST: SC-8(1)
  'CKV_AWS_215': ['CCI-002420'],
  // CKV_AWS_216: Ensure CloudFront distribution is enabled → NIST: CM-6
  'CKV_AWS_216': ['CCI-000366'],
  // CKV_AWS_217: Ensure Create before destroy for API deployments → NIST: CM-6
  'CKV_AWS_217': ['CCI-000366'],
  // CKV_AWS_218: Ensure that CloudSearch is using latest TLS → NIST: CM-6
  'CKV_AWS_218': ['CCI-000366'],
  // CKV_AWS_219: Ensure CodePipeline Artifact store is using a KMS CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_219': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_22: Ensure SageMaker Notebook is encrypted at rest using KMS CMK → NIST: SC-28(1)
  'CKV_AWS_22': ['CCI-002476'],
  // CKV_AWS_220: Ensure that CloudSearch is using https → NIST: CM-6
  'CKV_AWS_220': ['CCI-000366'],
  // CKV_AWS_221: Ensure CodeArtifact Domain is encrypted by KMS using a customer managed Key (... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_221': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_222: Ensure DMS replication instance gets all minor upgrade automatically → NIST: SI-2(2)
  'CKV_AWS_222': ['CCI-002607'],
  // CKV_AWS_223: Ensure ECS Cluster enables logging of ECS Exec → NIST: AU-2, AU-12
  'CKV_AWS_223': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_224: Ensure ECS Cluster logging is enabled and client to container communication u... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_224': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_225: Ensure API Gateway method setting caching is enabled → NIST: CM-6(1)
  'CKV_AWS_225': ['CCI-001515'],
  // CKV_AWS_226: Ensure DB instance gets all minor upgrades automatically → NIST: CM-6
  'CKV_AWS_226': ['CCI-000366'],
  // CKV_AWS_227: Ensure KMS key is enabled → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_227': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_228: Verify Elasticsearch domain is using an up to date TLS policy → NIST: SC-8(1), SC-13
  'CKV_AWS_228': ['CCI-002420', 'CCI-002450'],
  // CKV_AWS_229: Ensure no NACL allow ingress from 0.0.0.0:0 to port 21 → NIST: SC-7(5)
  'CKV_AWS_229': ['CCI-001100'],
  // CKV_AWS_23: Ensure every security groups rule has a description → NIST: CM-6
  'CKV_AWS_23': ['CCI-000366'],
  // CKV_AWS_230: Ensure no NACL allow ingress from 0.0.0.0:0 to port 20 → NIST: SC-7(5)
  'CKV_AWS_230': ['CCI-001100'],
  // CKV_AWS_231: Ensure no NACL allow ingress from 0.0.0.0:0 to port 3389 → NIST: SC-7(5)
  'CKV_AWS_231': ['CCI-001100'],
  // CKV_AWS_232: Ensure no NACL allow ingress from 0.0.0.0:0 to port 22 → NIST: SC-7(5)
  'CKV_AWS_232': ['CCI-001100'],
  // CKV_AWS_233: Ensure Create before destroy for ACM certificates → NIST: CM-6
  'CKV_AWS_233': ['CCI-000366'],
  // CKV_AWS_234: Verify logging preference for ACM certificates → NIST: AU-2, AU-12
  'CKV_AWS_234': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_235: Ensure that copied AMIs are encrypted → NIST: SC-13
  'CKV_AWS_235': ['CCI-002450'],
  // CKV_AWS_236: Ensure AMI copying uses a CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_236': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_237: Ensure Create before destroy for API Gateway → NIST: CM-6
  'CKV_AWS_237': ['CCI-000366'],
  // CKV_AWS_238: Ensure that GuardDuty detector is enabled → NIST: SI-4(4), RA-5(2)
  'CKV_AWS_238': ['CCI-002686', 'CCI-001645'],
  // CKV_AWS_239: Ensure DAX cluster endpoint is using TLS → NIST: CM-6
  'CKV_AWS_239': ['CCI-000366'],
  // CKV_AWS_24: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 → NIST: SC-7(5)
  'CKV_AWS_24': ['CCI-001100'],
  // CKV_AWS_240: Ensure Kinesis Firehose delivery stream is encrypted → NIST: SC-13
  'CKV_AWS_240': ['CCI-002450'],
  // CKV_AWS_241: Ensure that Kinesis Firehose Delivery Streams are encrypted with CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_241': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_242: Ensure MWAA environment has scheduler logs enabled → NIST: AU-2, AU-12
  'CKV_AWS_242': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_243: Ensure MWAA environment has worker logs enabled → NIST: AU-2, AU-12
  'CKV_AWS_243': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_244: Ensure MWAA environment has webserver logs enabled → NIST: AU-2, AU-12
  'CKV_AWS_244': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_245: Ensure replicated backups are encrypted at rest using KMS CMKs → NIST: SC-28(1)
  'CKV_AWS_245': ['CCI-002476'],
  // CKV_AWS_246: Ensure RDS Cluster activity streams are encrypted using KMS CMKs → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_246': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_247: Ensure all data stored in the Elasticsearch is encrypted with a CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_247': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_248: Ensure that Elasticsearch is not using the default Security Group → NIST: CM-6
  'CKV_AWS_248': ['CCI-000366'],
  // CKV_AWS_249: Ensure that the Execution Role ARN and the Task Role ARN are different in ECS... → NIST: CM-6
  'CKV_AWS_249': ['CCI-000366'],
  // CKV_AWS_25: Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 → NIST: SC-7(5)
  'CKV_AWS_25': ['CCI-001100'],
  // CKV_AWS_250: Ensure that RDS PostgreSQL instances use a non vulnerable version with the lo... → NIST: CM-6
  'CKV_AWS_250': ['CCI-000366'],
  // CKV_AWS_251: Ensure CloudTrail logging is enabled → NIST: AU-12(1), AU-3(1)
  'CKV_AWS_251': ['CCI-000172', 'CCI-000135'],
  // CKV_AWS_252: Ensure CloudTrail defines an SNS Topic → NIST: AU-12(1), AU-3(1)
  'CKV_AWS_252': ['CCI-000172', 'CCI-000135'],
  // CKV_AWS_253: Ensure DLM cross region events are encrypted → NIST: CP-6(1), CP-9(3)
  'CKV_AWS_253': ['CCI-000504', 'CCI-000512'],
  // CKV_AWS_254: Ensure DLM cross region events are encrypted with Customer Managed Key → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_254': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_255: Ensure DLM cross region schedules are encrypted → NIST: CP-6(1), CP-9(3)
  'CKV_AWS_255': ['CCI-000504', 'CCI-000512'],
  // CKV_AWS_256: Ensure DLM cross region schedules are encrypted using a Customer Managed Key → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_256': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_257: Ensure CodeCommit branch changes have at least 2 approvals → NIST: CM-3(2), CM-5(1)
  'CKV_AWS_257': ['CCI-001501', 'CCI-001510'],
  // CKV_AWS_258: Ensure that Lambda function URLs AuthType is not None → NIST: CM-6
  'CKV_AWS_258': ['CCI-000366'],
  // CKV_AWS_259: Ensure CloudFront response header policy enforces Strict Transport Security → NIST: IR-4(1), IR-5(1)
  'CKV_AWS_259': ['CCI-000227', 'CCI-001310'],
  // CKV_AWS_26: Ensure all data stored in the SNS topic is encrypted → NIST: SC-13
  'CKV_AWS_26': ['CCI-002450'],
  // CKV_AWS_260: Ensure no security groups allow ingress from 0.0.0.0:0 to port 80 → NIST: SC-7(5)
  'CKV_AWS_260': ['CCI-001100'],
  // CKV_AWS_261: Ensure HTTP HTTPS Target group defines Healthcheck → NIST: CM-6
  'CKV_AWS_261': ['CCI-000366'],
  // CKV_AWS_262: Ensure Kendra index Server side encryption uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_262': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_263: Ensure AppFlow flow uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_263': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_264: Ensure AppFlow connector profile uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_264': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_265: Ensure Keyspaces Table uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_265': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_266: Ensure DB Snapshot copy uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_266': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_267: Ensure that Comprehend Entity Recognizer's model is encrypted by KMS using a ... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_267': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_268: Ensure that Comprehend Entity Recognizer's volume is encrypted by KMS using a... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_268': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_269: Ensure Connect Instance Kinesis Video Stream Storage Config uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_269': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_27: Ensure all data stored in the SQS queue is encrypted → NIST: SC-13
  'CKV_AWS_27': ['CCI-002450'],
  // CKV_AWS_270: Ensure Connect Instance S3 Storage Config uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_270': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_271: Ensure DynamoDB table replica KMS encryption uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_271': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing → NIST: CM-6
  'CKV_AWS_272': ['CCI-000366'],
  // CKV_AWS_273: Ensure access is controlled through SSO and not AWS IAM defined users → NIST: IA-2(12), IA-8(2)
  'CKV_AWS_273': ['CCI-001957', 'CCI-001954'],
  // CKV_AWS_274: Disallow IAM roles, users, and groups from using the AWS AdministratorAccess ... → NIST: CM-6
  'CKV_AWS_274': ['CCI-000366'],
  // CKV_AWS_275: Disallow policies from using the AWS AdministratorAccess policy → NIST: CM-6
  'CKV_AWS_275': ['CCI-000366'],
  // CKV_AWS_276: Ensure Data Trace is not enabled in API Gateway Method Settings → NIST: SI-4(2), AU-12
  'CKV_AWS_276': ['CCI-002684', 'CCI-000169'],
  // CKV_AWS_277: Ensure no security groups allow ingress from 0.0.0.0:0 to port -1 → NIST: SC-7(5)
  'CKV_AWS_277': ['CCI-001100'],
  // CKV_AWS_278: Ensure MemoryDB snapshot is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_278': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_279: Ensure Neptune snapshot is securely encrypted → NIST: SC-13
  'CKV_AWS_279': ['CCI-002450'],
  // CKV_AWS_28: Ensure DynamoDB point in time recovery (backup) is enabled → NIST: CP-9(1)
  'CKV_AWS_28': ['CCI-000510'],
  // CKV_AWS_280: Ensure Neptune snapshot is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_280': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_281: Ensure RedShift snapshot copy is encrypted by KMS using a customer managed Ke... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_281': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_282: Ensure that Redshift Serverless namespace is encrypted by KMS using a custome... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_282': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_283: Ensure no IAM policies documents allow ALL or any AWS principal permissions t... → NIST: CM-6
  'CKV_AWS_283': ['CCI-000366'],
  // CKV_AWS_284: Ensure State Machine has X-Ray tracing enabled → NIST: SI-4(2), AU-12
  'CKV_AWS_284': ['CCI-002684', 'CCI-000169'],
  // CKV_AWS_285: Ensure State Machine has execution history logging enabled → NIST: AU-2, AU-12
  'CKV_AWS_285': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_286: Ensure IAM policies does not allow privilege escalation → NIST: CM-6
  'CKV_AWS_286': ['CCI-000366'],
  // CKV_AWS_287: Ensure IAM policies does not allow credentials exposure → NIST: CM-6
  'CKV_AWS_287': ['CCI-000366'],
  // CKV_AWS_288: Ensure IAM policies does not allow data exfiltration → NIST: SC-28(1), MP-4
  'CKV_AWS_288': ['CCI-002476', 'CCI-001821'],
  // CKV_AWS_289: Ensure IAM policies does not allow permissions management / resource exposure... → NIST: CM-6
  'CKV_AWS_289': ['CCI-000366'],
  // CKV_AWS_29: Ensure all data stored in the ElastiCache Replication Group is securely encry... → NIST: SC-28(1)
  'CKV_AWS_29': ['CCI-002476'],
  // CKV_AWS_290: Ensure IAM policies does not allow write access without constraints → NIST: CM-6
  'CKV_AWS_290': ['CCI-000366'],
  // CKV_AWS_291: Ensure MSK nodes are private → NIST: CM-6
  'CKV_AWS_291': ['CCI-000366'],
  // CKV_AWS_292: Ensure DocumentDB Global Cluster is encrypted at rest (default is unencrypted) → NIST: SC-28(1)
  'CKV_AWS_292': ['CCI-002476'],
  // CKV_AWS_293: Ensure that AWS database instances have deletion protection enabled → NIST: CM-6
  'CKV_AWS_293': ['CCI-000366'],
  // CKV_AWS_294: Ensure CloudTrail Event Data Store uses CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_294': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_295: Ensure DataSync Location Object Storage doesn't expose secrets → NIST: CM-6
  'CKV_AWS_295': ['CCI-000366'],
  // CKV_AWS_296: Ensure DMS endpoint uses Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_296': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_297: Ensure EventBridge Scheduler Schedule uses Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_297': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_298: Ensure DMS S3 uses Customer Managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_298': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_3: Ensure all data stored in the EBS is securely encrypted → NIST: SC-13
  'CKV_AWS_3': ['CCI-002450'],
  // CKV_AWS_30: Ensure all data stored in the ElastiCache Replication Group is securely encry... → NIST: SC-8(1)
  'CKV_AWS_30': ['CCI-002420'],
  // CKV_AWS_300: Ensure S3 lifecycle configuration sets period for aborting failed uploads → NIST: MP-6(1), AU-11
  'CKV_AWS_300': ['CCI-001904', 'CCI-000167'],
  // CKV_AWS_301: Ensure that AWS Lambda function is not publicly accessible → NIST: SC-7(5), AC-3
  'CKV_AWS_301': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_302: Ensure DB Snapshots are not Public → NIST: AC-3, SC-7(5)
  'CKV_AWS_302': ['CCI-000213', 'CCI-001100'],
  // CKV_AWS_303: Ensure SSM documents are not Public → NIST: AC-3, SC-7(5)
  'CKV_AWS_303': ['CCI-000213', 'CCI-001100'],
  // CKV_AWS_304: Ensure Secrets Manager secrets should be rotated within 90 days → NIST: IA-5(7), SC-28(1)
  'CKV_AWS_304': ['CCI-000190', 'CCI-002476'],
  // CKV_AWS_305: Ensure CloudFront distribution has a default root object configured → NIST: IA-5(7), CM-6(1)
  'CKV_AWS_305': ['CCI-000190', 'CCI-001515'],
  // CKV_AWS_306: Ensure SageMaker notebook instances should be launched into a custom VPC → NIST: SC-7(3)
  'CKV_AWS_306': ['CCI-001098'],
  // CKV_AWS_307: Ensure SageMaker Users should not have root access to SageMaker notebook inst... → NIST: AC-6(1), AC-6(5)
  'CKV_AWS_307': ['CCI-000226', 'CCI-000230'],
  // CKV_AWS_308: Ensure API Gateway method setting caching is set to encrypted → NIST: SC-13
  'CKV_AWS_308': ['CCI-002450'],
  // CKV_AWS_309: Ensure API GatewayV2 routes specify an authorization type → NIST: CM-6
  'CKV_AWS_309': ['CCI-000366'],
  // CKV_AWS_31: Ensure all data stored in the ElastiCache Replication Group is securely encry... → NIST: SC-8(1)
  'CKV_AWS_31': ['CCI-002420'],
  // CKV_AWS_310: Ensure CloudFront distributions should have origin failover configured → NIST: CP-10(2), CP-9
  'CKV_AWS_310': ['CCI-000555', 'CCI-000509'],
  // CKV_AWS_311: Ensure that CodeBuild S3 logs are encrypted → NIST: SC-13
  'CKV_AWS_311': ['CCI-002450'],
  // CKV_AWS_312: Ensure Elastic Beanstalk environments have enhanced health reporting enabled → NIST: CM-6
  'CKV_AWS_312': ['CCI-000366'],
  // CKV_AWS_313: Ensure RDS cluster configured to copy tags to snapshots → NIST: CM-6
  'CKV_AWS_313': ['CCI-000366'],
  // CKV_AWS_314: Ensure CodeBuild project environments have a logging configuration → NIST: AU-2, AU-12
  'CKV_AWS_314': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_315: Ensure EC2 Auto Scaling groups use EC2 launch templates → NIST: CP-10(4), SC-5(2)
  'CKV_AWS_315': ['CCI-000557', 'CCI-002386'],
  // CKV_AWS_316: Ensure CodeBuild project environments do not have privileged mode enabled → NIST: CM-6
  'CKV_AWS_316': ['CCI-000366'],
  // CKV_AWS_317: Ensure Elasticsearch Domain Audit Logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_317': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_318: Ensure Elasticsearch domains are configured with at least three dedicated mas... → NIST: CM-6
  'CKV_AWS_318': ['CCI-000366'],
  // CKV_AWS_319: Ensure that CloudWatch alarm actions are enabled → NIST: SI-4(5), IR-6(1)
  'CKV_AWS_319': ['CCI-002687', 'CCI-000229'],
  // CKV_AWS_32: Ensure ECR policy is not set to public → NIST: AC-3, SC-7(5)
  'CKV_AWS_32': ['CCI-000213', 'CCI-001100'],
  // CKV_AWS_320: Ensure Redshift clusters do not use the default database name → NIST: CM-6
  'CKV_AWS_320': ['CCI-000366'],
  // CKV_AWS_321: Ensure Redshift clusters use enhanced VPC routing → NIST: SC-7(3)
  'CKV_AWS_321': ['CCI-001098'],
  // CKV_AWS_322: Ensure ElastiCache for Redis cache clusters have auto minor version upgrades ... → NIST: CM-6(1)
  'CKV_AWS_322': ['CCI-001515'],
  // CKV_AWS_323: Ensure ElastiCache clusters do not use the default subnet group → NIST: SC-7(3)
  'CKV_AWS_323': ['CCI-001098'],
  // CKV_AWS_324: Ensure that RDS Cluster log capture is enabled → NIST: AU-2, AU-12
  'CKV_AWS_324': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_325: Ensure that RDS Cluster audit logging is enabled for MySQL engine → NIST: AU-2, AU-12
  'CKV_AWS_325': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_326: Ensure that RDS Aurora Clusters have backtracking enabled → NIST: CM-6
  'CKV_AWS_326': ['CCI-000366'],
  // CKV_AWS_327: Ensure RDS Clusters are encrypted using KMS CMKs → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_327': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_328: Ensure that ALB is configured with defensive or strictest desync mitigation mode → NIST: CM-6
  'CKV_AWS_328': ['CCI-000366'],
  // CKV_AWS_329: EFS access points should enforce a root directory → NIST: CM-6
  'CKV_AWS_329': ['CCI-000366'],
  // CKV_AWS_33: Ensure KMS key policy does not contain wildcard (*) principal → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_33': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_331: Ensure Transit Gateways do not automatically accept VPC attachment requests → NIST: SC-7(3)
  'CKV_AWS_331': ['CCI-001098'],
  // CKV_AWS_332: Ensure ECS Fargate services run on the latest Fargate platform version → NIST: CM-6
  'CKV_AWS_332': ['CCI-000366'],
  // CKV_AWS_333: Ensure ECS services do not have public IP addresses assigned to them automati... → NIST: SC-7(5), AC-3
  'CKV_AWS_333': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_334: Ensure ECS containers should run as non-privileged → NIST: CM-6
  'CKV_AWS_334': ['CCI-000366'],
  // CKV_AWS_335: Ensure ECS task definitions should not share the host's process namespace → NIST: CM-6
  'CKV_AWS_335': ['CCI-000366'],
  // CKV_AWS_336: Ensure ECS containers are limited to read-only access to root filesystems → NIST: CM-6(1), AU-9(4)
  'CKV_AWS_336': ['CCI-001515', 'CCI-000166'],
  // CKV_AWS_337: Ensure SSM parameters are using KMS CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_337': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_338: Ensure CloudWatch log groups retains logs for at least 1 year → NIST: AU-2, AU-12
  'CKV_AWS_338': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_339: Ensure EKS clusters run on a supported Kubernetes version → NIST: CM-6
  'CKV_AWS_339': ['CCI-000366'],
  // CKV_AWS_34: Ensure CloudFront Distribution ViewerProtocolPolicy is set to HTTPS → NIST: CM-6
  'CKV_AWS_34': ['CCI-000366'],
  // CKV_AWS_340: Ensure Elastic Beanstalk managed platform updates are enabled → NIST: CM-6
  'CKV_AWS_340': ['CCI-000366'],
  // CKV_AWS_341: Ensure Launch template should not have a metadata response hop limit greater ... → NIST: IR-4(1), IR-5(1)
  'CKV_AWS_341': ['CCI-000227', 'CCI-001310'],
  // CKV_AWS_342: Ensure WAF rule has any actions → NIST: SC-7(14), SC-5(1)
  'CKV_AWS_342': ['CCI-001109', 'CCI-002385'],
  // CKV_AWS_343: Ensure Amazon Redshift clusters should have automatic snapshots enabled → NIST: CM-6
  'CKV_AWS_343': ['CCI-000366'],
  // CKV_AWS_344: Ensure that Network firewalls have deletion protection enabled → NIST: CM-6
  'CKV_AWS_344': ['CCI-000366'],
  // CKV_AWS_345: Ensure that Network firewall encryption is via a CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_345': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_346: Ensure Network Firewall Policy defines an encryption configuration that uses ... → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_346': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_347: Ensure Neptune is encrypted by KMS using a customer managed Key (CMK) → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_347': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_348: Ensure IAM root user does not have Access keys → NIST: AC-6(1), AC-6(5)
  'CKV_AWS_348': ['CCI-000226', 'CCI-000230'],
  // CKV_AWS_349: Ensure EMR Cluster security configuration encrypts local disks → NIST: SC-13
  'CKV_AWS_349': ['CCI-002450'],
  // CKV_AWS_35: Ensure CloudTrail logs are encrypted at rest using KMS CMKs → NIST: SC-28(1)
  'CKV_AWS_35': ['CCI-002476'],
  // CKV_AWS_350: Ensure EMR Cluster security configuration encrypts EBS disks → NIST: SC-13
  'CKV_AWS_350': ['CCI-002450'],
  // CKV_AWS_351: Ensure EMR Cluster security configuration encrypts InTransit → NIST: SC-13
  'CKV_AWS_351': ['CCI-002450'],
  // CKV_AWS_352: Ensure NACL ingress does not allow all Ports → NIST: SC-7(5)
  'CKV_AWS_352': ['CCI-001100'],
  // CKV_AWS_353: Ensure that RDS instances have performance insights enabled → NIST: CM-6
  'CKV_AWS_353': ['CCI-000366'],
  // CKV_AWS_354: Ensure RDS Performance Insights are encrypted using KMS CMKs → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_354': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_355: Ensure no IAM policies documents allow "*" as a statement's resource for rest... → NIST: AC-6(1)
  'CKV_AWS_355': ['CCI-000226'],
  // CKV_AWS_356: Ensure no IAM policies documents allow "*" as a statement's resource for rest... → NIST: AC-6(1)
  'CKV_AWS_356': ['CCI-000226'],
  // CKV_AWS_357: Ensure Transfer Server allows only secure protocols → NIST: CM-6
  'CKV_AWS_357': ['CCI-000366'],
  // CKV_AWS_358: Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims ... → NIST: IA-2(12), IA-8(2)
  'CKV_AWS_358': ['CCI-001957', 'CCI-001954'],
  // CKV_AWS_359: Neptune DB clusters should have IAM database authentication enabled → NIST: CM-6
  'CKV_AWS_359': ['CCI-000366'],
  // CKV_AWS_36: Ensure CloudTrail log file validation is enabled → NIST: AU-12(1), AU-3(1)
  'CKV_AWS_36': ['CCI-000172', 'CCI-000135'],
  // CKV_AWS_360: Ensure DocumentDB has an adequate backup retention period → NIST: CM-6
  'CKV_AWS_360': ['CCI-000366'],
  // CKV_AWS_361: Ensure that Neptune DB cluster has automated backups enabled with adequate re... → NIST: CM-6
  'CKV_AWS_361': ['CCI-000366'],
  // CKV_AWS_362: Neptune DB clusters should be configured to copy tags to snapshots → NIST: CM-6
  'CKV_AWS_362': ['CCI-000366'],
  // CKV_AWS_363: Ensure Lambda Runtime is not deprecated → NIST: CM-6
  'CKV_AWS_363': ['CCI-000366'],
  // CKV_AWS_364: Ensure that AWS Lambda function permissions delegated to AWS services are lim... → NIST: CM-6
  'CKV_AWS_364': ['CCI-000366'],
  // CKV_AWS_365: Ensure SES Configuration Set enforces TLS usage → NIST: CM-6
  'CKV_AWS_365': ['CCI-000366'],
  // CKV_AWS_367: Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt model artifacts → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_367': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_368: Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt data on attached... → NIST: SC-28(1)
  'CKV_AWS_368': ['CCI-002476'],
  // CKV_AWS_369: Ensure Amazon Sagemaker Data Quality Job encrypts all communications between ... → NIST: SC-13
  'CKV_AWS_369': ['CCI-002450'],
  // CKV_AWS_37: Ensure Amazon EKS control plane logging is enabled for all log types → NIST: AU-2, AU-12
  'CKV_AWS_37': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_370: Ensure Amazon SageMaker model uses network isolation → NIST: SC-7(3)
  'CKV_AWS_370': ['CCI-001098'],
  // CKV_AWS_371: Ensure Amazon SageMaker Notebook Instance only allows for IMDSv2 → NIST: CM-6
  'CKV_AWS_371': ['CCI-000366'],
  // CKV_AWS_372: Ensure Amazon SageMaker Flow Definition uses KMS for output configurations → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_372': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_373: Ensure Bedrock Agent is encrypted with a CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_373': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_374: Ensure AWS CloudFront web distribution has geo restriction enabled → NIST: CM-6
  'CKV_AWS_374': ['CCI-000366'],
  // CKV_AWS_375: Ensure AWS S3 bucket does not have global view ACL permissions enabled → NIST: CM-6
  'CKV_AWS_375': ['CCI-000366'],
  // CKV_AWS_376: Ensure AWS Elastic Load Balancer listener uses TLS/SSL → NIST: SC-8(1), SC-7(4)
  'CKV_AWS_376': ['CCI-002420', 'CCI-001099'],
  // CKV_AWS_377: Ensure Route 53 domains have transfer lock protection → NIST: CM-6
  'CKV_AWS_377': ['CCI-000366'],
  // CKV_AWS_378: Ensure AWS Load Balancer doesn't use HTTP protocol → NIST: SC-8(1)
  'CKV_AWS_378': ['CCI-002420'],
  // CKV_AWS_379: Ensure AWS S3 bucket is configured with secure data transport policy → NIST: CM-6
  'CKV_AWS_379': ['CCI-000366'],
  // CKV_AWS_38: Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0 → NIST: SC-7(5), AC-3
  'CKV_AWS_38': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_380: Ensure AWS Transfer Server uses latest Security Policy → NIST: CM-6
  'CKV_AWS_380': ['CCI-000366'],
  // CKV_AWS_381: Make sure that aws_codegurureviewer_repository_association has a CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AWS_381': ['CCI-002476', 'CCI-002451'],
  // CKV_AWS_382: Ensure no security groups allow egress from 0.0.0.0:0 to port -1 → NIST: SC-7(5)
  'CKV_AWS_382': ['CCI-001100'],
  // CKV_AWS_383: Ensure AWS Bedrock agent is associated with Bedrock guardrails → NIST: CM-6
  'CKV_AWS_383': ['CCI-000366'],
  // CKV_AWS_384: Ensure no hard-coded secrets exist in Parameter Store values → NIST: IA-5(7), SC-28(1)
  'CKV_AWS_384': ['CCI-000190', 'CCI-002476'],
  // CKV_AWS_385: Ensure AWS SNS topic policies do not allow cross-account access → NIST: AC-4(21), AC-3
  'CKV_AWS_385': ['CCI-001414', 'CCI-000213'],
  // CKV_AWS_386: Reduce potential for WhoAMI cloud image name confusion attack → NIST: CM-6
  'CKV_AWS_386': ['CCI-000366'],
  // CKV_AWS_387: Ensure SQS policy does not allow public access through wildcards → NIST: SC-7(5), AC-3
  'CKV_AWS_387': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_388: Ensure AWS Aurora PostgreSQL is not exposed to local file read vulnerability → NIST: CM-6
  'CKV_AWS_388': ['CCI-000366'],
  // CKV_AWS_389: Ensure AWS Auto Scaling group launch configuration doesn't have public IP add... → NIST: SC-7(5), AC-3
  'CKV_AWS_389': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_39: Ensure Amazon EKS public endpoint disabled → NIST: SC-7(5), AC-3
  'CKV_AWS_39': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_390: Ensure AWS EMR block public access setting is enabled → NIST: SC-7(5), AC-3
  'CKV_AWS_390': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_391: Avoid AWS Redshift cluster with commonly used master username and public acce... → NIST: SC-7(5), AC-3
  'CKV_AWS_391': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_392: Ensure AWS S3 access point block public access setting is enabled → NIST: SC-7(5), AC-3
  'CKV_AWS_392': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_40: Ensure IAM policies are attached only to groups or roles (Reducing access man... → NIST: AC-6(10), AC-6(1)
  'CKV_AWS_40': ['CCI-000235', 'CCI-000226'],
  // CKV_AWS_41: Ensure no hard coded AWS access key and secret key exists in provider → NIST: IA-5(7), CM-6(1)
  'CKV_AWS_41': ['CCI-000190', 'CCI-001515'],
  // CKV_AWS_42: Ensure EFS is securely encrypted → NIST: SC-13
  'CKV_AWS_42': ['CCI-002450'],
  // CKV_AWS_43: Ensure Kinesis Stream is securely encrypted → NIST: SC-13
  'CKV_AWS_43': ['CCI-002450'],
  // CKV_AWS_44: Ensure Neptune storage is securely encrypted → NIST: SC-13
  'CKV_AWS_44': ['CCI-002450'],
  // CKV_AWS_45: Ensure no hard-coded secrets exist in Lambda environment → NIST: IA-5(7), CM-6(1)
  'CKV_AWS_45': ['CCI-000190', 'CCI-001515'],
  // CKV_AWS_46: Ensure no hard-coded secrets exist in EC2 user data → NIST: IA-5(7), CM-6(1)
  'CKV_AWS_46': ['CCI-000190', 'CCI-001515'],
  // CKV_AWS_47: Ensure DAX is encrypted at rest (default is unencrypted) → NIST: SC-28(1)
  'CKV_AWS_47': ['CCI-002476'],
  // CKV_AWS_48: Ensure MQ Broker logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_48': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_49: Ensure no IAM policies documents allow "*" as a statement's actions → NIST: CM-6
  'CKV_AWS_49': ['CCI-000366'],
  // CKV_AWS_5: Ensure all data stored in the Elasticsearch is securely encrypted at rest → NIST: SC-28(1)
  'CKV_AWS_5': ['CCI-002476'],
  // CKV_AWS_50: X-Ray tracing is enabled for Lambda → NIST: SI-4(2), AU-12
  'CKV_AWS_50': ['CCI-002684', 'CCI-000169'],
  // CKV_AWS_51: Ensure ECR Image Tags are immutable → NIST: RA-5(5), SI-7(1)
  'CKV_AWS_51': ['CCI-001648', 'CCI-002700'],
  // CKV_AWS_53: Ensure S3 bucket has block public ACLs enabled → NIST: AC-3, SC-7(5)
  'CKV_AWS_53': ['CCI-000213', 'CCI-001100'],
  // CKV_AWS_54: Ensure S3 bucket has block public policy enabled → NIST: AC-3, SC-7(5)
  'CKV_AWS_54': ['CCI-000213', 'CCI-001100'],
  // CKV_AWS_55: Ensure S3 bucket has ignore public ACLs enabled → NIST: AC-3, SC-7(5)
  'CKV_AWS_55': ['CCI-000213', 'CCI-001100'],
  // CKV_AWS_56: Ensure S3 bucket has RestrictPublicBuckets enabled → NIST: CM-6
  'CKV_AWS_56': ['CCI-000366'],
  // CKV_AWS_57: Ensure the S3 bucket does not allow WRITE permissions to everyone → NIST: CM-6
  'CKV_AWS_57': ['CCI-000366'],
  // CKV_AWS_58: Ensure EKS Cluster has Secrets Encryption Enabled → NIST: SC-13
  'CKV_AWS_58': ['CCI-002450'],
  // CKV_AWS_59: Ensure there is no open access to back-end resources through API → NIST: CM-6
  'CKV_AWS_59': ['CCI-000366'],
  // CKV_AWS_6: Ensure all Elasticsearch has node-to-node encryption enabled → NIST: SC-13
  'CKV_AWS_6': ['CCI-002450'],
  // CKV_AWS_60: Ensure IAM role allows only specific services or principals to assume it → NIST: CM-6
  'CKV_AWS_60': ['CCI-000366'],
  // CKV_AWS_61: Ensure AWS IAM policy does not allow assume role permission across all services → NIST: AC-6(1), AC-6(5)
  'CKV_AWS_61': ['CCI-000226', 'CCI-000230'],
  // CKV_AWS_62: Ensure no IAM policies that allow full "*-*" administrative privileges are no... → NIST: AC-6(10), AC-6(1)
  'CKV_AWS_62': ['CCI-000235', 'CCI-000226'],
  // CKV_AWS_63: Ensure no IAM policies documents allow "*" as a statement's actions → NIST: CM-6
  'CKV_AWS_63': ['CCI-000366'],
  // CKV_AWS_64: Ensure all data stored in the Redshift cluster is securely encrypted at rest → NIST: SC-28(1)
  'CKV_AWS_64': ['CCI-002476'],
  // CKV_AWS_65: Ensure container insights are enabled on ECS cluster → NIST: CM-6
  'CKV_AWS_65': ['CCI-000366'],
  // CKV_AWS_66: Ensure that CloudWatch Log Group specifies retention days → NIST: AU-11
  'CKV_AWS_66': ['CCI-000167'],
  // CKV_AWS_67: Ensure CloudTrail is enabled in all Regions → NIST: AU-12(1), AU-3(1)
  'CKV_AWS_67': ['CCI-000172', 'CCI-000135'],
  // CKV_AWS_68: CloudFront Distribution should have WAF enabled → NIST: SC-7(14), SC-5(1)
  'CKV_AWS_68': ['CCI-001109', 'CCI-002385'],
  // CKV_AWS_69: Ensure Amazon MQ Broker should not have public access → NIST: SC-7(5), AC-3
  'CKV_AWS_69': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_7: Ensure rotation for customer created CMKs is enabled → NIST: CM-6
  'CKV_AWS_7': ['CCI-000366'],
  // CKV_AWS_70: Ensure S3 bucket does not allow an action with any Principal → NIST: CM-6
  'CKV_AWS_70': ['CCI-000366'],
  // CKV_AWS_71: Ensure Redshift Cluster logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_71': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_72: Ensure SQS policy does not allow ALL (*) actions. → NIST: CM-6
  'CKV_AWS_72': ['CCI-000366'],
  // CKV_AWS_73: Ensure API Gateway has X-Ray Tracing enabled → NIST: SI-4(2), AU-12
  'CKV_AWS_73': ['CCI-002684', 'CCI-000169'],
  // CKV_AWS_74: Ensure DocumentDB is encrypted at rest (default is unencrypted) → NIST: SC-28(1)
  'CKV_AWS_74': ['CCI-002476'],
  // CKV_AWS_75: Ensure Global Accelerator accelerator has flow logs enabled → NIST: AU-2, AU-12
  'CKV_AWS_75': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_76: Ensure API Gateway has Access Logging enabled → NIST: AU-2, AU-12
  'CKV_AWS_76': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_77: Ensure Athena Database is encrypted at rest (default is unencrypted) → NIST: SC-28(1)
  'CKV_AWS_77': ['CCI-002476'],
  // CKV_AWS_78: Ensure that CodeBuild Project encryption is not disabled → NIST: SC-13
  'CKV_AWS_78': ['CCI-002450'],
  // CKV_AWS_79: Ensure Instance Metadata Service Version 1 is not enabled → NIST: CM-6
  'CKV_AWS_79': ['CCI-000366'],
  // CKV_AWS_8: Ensure all data stored in the Launch configuration EBS is securely encrypted → NIST: CM-6(1)
  'CKV_AWS_8': ['CCI-001515'],
  // CKV_AWS_80: Ensure MSK Cluster logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_80': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_81: Ensure MSK Cluster encryption in rest and transit is enabled → NIST: SC-28(1)
  'CKV_AWS_81': ['CCI-002476'],
  // CKV_AWS_82: Ensure Athena Workgroup should enforce configuration to prevent client disabl... → NIST: SC-13
  'CKV_AWS_82': ['CCI-002450'],
  // CKV_AWS_83: Ensure Elasticsearch Domain enforces HTTPS → NIST: CM-6
  'CKV_AWS_83': ['CCI-000366'],
  // CKV_AWS_84: Ensure Elasticsearch Domain Logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_84': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_85: Ensure DocumentDB Logging is enabled → NIST: AU-2, AU-12
  'CKV_AWS_85': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_86: Ensure CloudFront Distribution has Access Logging enabled → NIST: AU-2, AU-12
  'CKV_AWS_86': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_87: Redshift cluster should not be publicly accessible → NIST: SC-7(5), AC-3
  'CKV_AWS_87': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_88: EC2 instance should not have public IP. → NIST: SC-7(5), AC-3
  'CKV_AWS_88': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_89: DMS replication instance should not be publicly accessible → NIST: SC-7(5), AC-3
  'CKV_AWS_89': ['CCI-001100', 'CCI-000213'],
  // CKV_AWS_9: Ensure IAM password policy expires passwords within 90 days or less → NIST: IA-5(1)
  'CKV_AWS_9': ['CCI-000192'],
  // CKV_AWS_90: Ensure DocumentDB TLS is not disabled → NIST: CM-6
  'CKV_AWS_90': ['CCI-000366'],
  // CKV_AWS_91: Ensure the ELBv2 (Application/Network) has access logging enabled → NIST: AU-2, AU-12
  'CKV_AWS_91': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_92: Ensure the ELB has access logging enabled → NIST: SC-7(9), AU-12(1)
  'CKV_AWS_92': ['CCI-001104', 'CCI-000172'],
  // CKV_AWS_93: Ensure S3 bucket policy does not lockout all but root user. (Prevent lockouts... → NIST: AC-6(1), AC-6(5)
  'CKV_AWS_93': ['CCI-000226', 'CCI-000230'],
  // CKV_AWS_94: Ensure Glue Data Catalog Encryption is enabled → NIST: SC-13
  'CKV_AWS_94': ['CCI-002450'],
  // CKV_AWS_95: Ensure API Gateway V2 has Access Logging enabled → NIST: AU-2, AU-12
  'CKV_AWS_95': ['CCI-000130', 'CCI-000169'],
  // CKV_AWS_96: Ensure all data stored in Aurora is securely encrypted at rest → NIST: SC-28(1)
  'CKV_AWS_96': ['CCI-002476'],
  // CKV_AWS_97: Ensure Encryption in transit is enabled for EFS volumes in ECS Task definitions → NIST: SC-28(1)
  'CKV_AWS_97': ['CCI-002476'],
  // CKV_AWS_98: Ensure all data stored in the Sagemaker Endpoint is securely encrypted at rest → NIST: SC-28(1)
  'CKV_AWS_98': ['CCI-002476'],
  // CKV_AWS_99: Ensure Glue Security Configuration Encryption is enabled → NIST: SC-13
  'CKV_AWS_99': ['CCI-002450'],
  // CKV_AZUREPIPELINES_1: Ensure container job uses a non latest version tag → NIST: SI-2(2)
  'CKV_AZUREPIPELINES_1': ['CCI-002607'],
  // CKV_AZUREPIPELINES_2: Ensure container job uses a version digest → NIST: RA-5(5), SI-7(1)
  'CKV_AZUREPIPELINES_2': ['CCI-001648', 'CCI-002700'],
  // CKV_AZUREPIPELINES_3: Ensure set variable is not marked as a secret → NIST: CM-6
  'CKV_AZUREPIPELINES_3': ['CCI-000366'],
  // CKV_AZUREPIPELINES_5: Detecting image usages in azure pipelines workflows → NIST: CM-6
  'CKV_AZUREPIPELINES_5': ['CCI-000366'],
  // CKV_AZURE_1: Ensure Azure Instance does not use basic authentication(Use SSH Key Instead) → NIST: AC-17(2), IA-2(6)
  'CKV_AZURE_1': ['CCI-000069', 'CCI-001941'],
  // CKV_AZURE_10: Ensure that SSH access is restricted from the internet → NIST: AC-17(2), IA-2(6)
  'CKV_AZURE_10': ['CCI-000069', 'CCI-001941'],
  // CKV_AZURE_100: Ensure that Cosmos DB accounts have customer-managed keys to encrypt data at ... → NIST: SC-28(1)
  'CKV_AZURE_100': ['CCI-002476'],
  // CKV_AZURE_101: Ensure that Azure Cosmos DB disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_101': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_102: Ensure that PostgreSQL server enables geo-redundant backups → NIST: CP-6(1), CP-9(3)
  'CKV_AZURE_102': ['CCI-000504', 'CCI-000512'],
  // CKV_AZURE_103: Ensure that Azure Data Factory uses Git repository for source control → NIST: CM-6
  'CKV_AZURE_103': ['CCI-000366'],
  // CKV_AZURE_104: Ensure that Azure Data factory public network access is disabled → NIST: SC-7(5), AC-3
  'CKV_AZURE_104': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_105: Ensure that Data Lake Store accounts enables encryption → NIST: SC-13
  'CKV_AZURE_105': ['CCI-002450'],
  // CKV_AZURE_106: Ensure that Azure Event Grid Domain public network access is disabled → NIST: SC-7(5), AC-3
  'CKV_AZURE_106': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_107: Ensure that API management services use virtual networks → NIST: CM-6
  'CKV_AZURE_107': ['CCI-000366'],
  // CKV_AZURE_108: Ensure that Azure IoT Hub disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_108': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_109: Ensure that key vault allows firewall rules settings → NIST: SC-7(4)
  'CKV_AZURE_109': ['CCI-001099'],
  // CKV_AZURE_11: Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) → NIST: SC-7(5)
  'CKV_AZURE_11': ['CCI-001100'],
  // CKV_AZURE_110: Ensure that key vault enables purge protection → NIST: SC-12(2)
  'CKV_AZURE_110': ['CCI-002452'],
  // CKV_AZURE_111: Ensure that key vault enables soft delete → NIST: SC-12(2)
  'CKV_AZURE_111': ['CCI-002452'],
  // CKV_AZURE_112: Ensure that key vault key is backed by HSM → NIST: SC-12(2)
  'CKV_AZURE_112': ['CCI-002452'],
  // CKV_AZURE_113: Ensure that SQL server disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_113': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_114: Ensure that key vault secrets have "content_type" set → NIST: SC-12(2)
  'CKV_AZURE_114': ['CCI-002452'],
  // CKV_AZURE_115: Ensure that AKS enables private clusters → NIST: SC-7(3)
  'CKV_AZURE_115': ['CCI-001098'],
  // CKV_AZURE_116: Ensure that AKS uses Azure Policies Add-on → NIST: CM-6
  'CKV_AZURE_116': ['CCI-000366'],
  // CKV_AZURE_117: Ensure that AKS uses disk encryption set → NIST: SC-28(1)
  'CKV_AZURE_117': ['CCI-002476'],
  // CKV_AZURE_118: Ensure that Network Interfaces disable IP forwarding → NIST: CM-6
  'CKV_AZURE_118': ['CCI-000366'],
  // CKV_AZURE_12: Ensure that Network Security Group Flow Log retention period is 'greater than... → NIST: SC-7(9), AU-12(1)
  'CKV_AZURE_12': ['CCI-001104', 'CCI-000172'],
  // CKV_AZURE_120: Ensure that Application Gateway enables WAF → NIST: SC-7(14), SC-5(1)
  'CKV_AZURE_120': ['CCI-001109', 'CCI-002385'],
  // CKV_AZURE_121: Ensure that Azure Front Door enables WAF → NIST: SC-7(14), SC-5(1)
  'CKV_AZURE_121': ['CCI-001109', 'CCI-002385'],
  // CKV_AZURE_122: Ensure that Application Gateway uses WAF in "Detection" or "Prevention" modes → NIST: SC-7(14), SC-5(1)
  'CKV_AZURE_122': ['CCI-001109', 'CCI-002385'],
  // CKV_AZURE_123: Ensure that Azure Front Door uses WAF in "Detection" or "Prevention" modes → NIST: SC-7(14), SC-5(1)
  'CKV_AZURE_123': ['CCI-001109', 'CCI-002385'],
  // CKV_AZURE_124: Ensure that Azure Cognitive Search disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_124': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_125: Ensures that Service Fabric use three levels of protection available → NIST: CM-6
  'CKV_AZURE_125': ['CCI-000366'],
  // CKV_AZURE_126: Ensures that Active Directory is used for authentication for Service Fabric → NIST: CM-6
  'CKV_AZURE_126': ['CCI-000366'],
  // CKV_AZURE_127: Ensure that My SQL server enables Threat detection policy → NIST: CM-6
  'CKV_AZURE_127': ['CCI-000366'],
  // CKV_AZURE_128: Ensure that PostgreSQL server enables Threat detection policy → NIST: CM-6
  'CKV_AZURE_128': ['CCI-000366'],
  // CKV_AZURE_129: Ensure that MariaDB server enables geo-redundant backups → NIST: CP-6(1), CP-9(3)
  'CKV_AZURE_129': ['CCI-000504', 'CCI-000512'],
  // CKV_AZURE_13: Ensure App Service Authentication is set on Azure App Service → NIST: CM-6
  'CKV_AZURE_13': ['CCI-000366'],
  // CKV_AZURE_130: Ensure that PostgreSQL server enables infrastructure encryption → NIST: SC-13
  'CKV_AZURE_130': ['CCI-002450'],
  // CKV_AZURE_131: Ensure that 'Security contact emails' is set → NIST: CM-6
  'CKV_AZURE_131': ['CCI-000366'],
  // CKV_AZURE_132: Ensure cosmosdb does not allow privileged escalation by restricting managemen... → NIST: CM-6
  'CKV_AZURE_132': ['CCI-000366'],
  // CKV_AZURE_133: Ensure Front Door WAF prevents message lookup in Log4j2. See CVE-2021-44228 a... → NIST: SC-7(14), SC-5(1)
  'CKV_AZURE_133': ['CCI-001109', 'CCI-002385'],
  // CKV_AZURE_134: Ensure that Cognitive Services accounts disable public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_134': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_135: Ensure Application Gateway WAF prevents message lookup in Log4j2. See CVE-202... → NIST: SC-7(14), SC-5(1)
  'CKV_AZURE_135': ['CCI-001109', 'CCI-002385'],
  // CKV_AZURE_136: Ensure that PostgreSQL Flexible server enables geo-redundant backups → NIST: CP-6(1), CP-9(3)
  'CKV_AZURE_136': ['CCI-000504', 'CCI-000512'],
  // CKV_AZURE_137: Ensure ACR admin account is disabled → NIST: AC-6(1), AC-6(5)
  'CKV_AZURE_137': ['CCI-000226', 'CCI-000230'],
  // CKV_AZURE_138: Ensures that ACR disables anonymous pulling of images → NIST: CM-6
  'CKV_AZURE_138': ['CCI-000366'],
  // CKV_AZURE_139: Ensure ACR set to disable public networking → NIST: CM-7(1)
  'CKV_AZURE_139': ['CCI-000382'],
  // CKV_AZURE_14: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service → NIST: SC-8(1)
  'CKV_AZURE_14': ['CCI-002420'],
  // CKV_AZURE_140: Ensure that Local Authentication is disabled on CosmosDB → NIST: CM-6
  'CKV_AZURE_140': ['CCI-000366'],
  // CKV_AZURE_141: Ensure AKS local admin account is disabled → NIST: AC-6(1), AC-6(5)
  'CKV_AZURE_141': ['CCI-000226', 'CCI-000230'],
  // CKV_AZURE_142: Ensure Machine Learning Compute Cluster Local Authentication is disabled → NIST: CM-6
  'CKV_AZURE_142': ['CCI-000366'],
  // CKV_AZURE_143: Ensure AKS cluster nodes do not have public IP addresses → NIST: SC-7(5), AC-3
  'CKV_AZURE_143': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_144: Ensure that Public Access is disabled for Machine Learning Workspace → NIST: SC-7(5), AC-3
  'CKV_AZURE_144': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_145: Ensure Function app is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_145': ['CCI-002607'],
  // CKV_AZURE_146: Ensure server parameter 'log_retention' is set to 'ON' for PostgreSQL Databas... → NIST: CM-6
  'CKV_AZURE_146': ['CCI-000366'],
  // CKV_AZURE_147: Ensure PostgreSQL is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_147': ['CCI-002607'],
  // CKV_AZURE_148: Ensure Redis Cache is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_148': ['CCI-002607'],
  // CKV_AZURE_149: Ensure that Virtual machine does not enable password authentication → NIST: CM-6
  'CKV_AZURE_149': ['CCI-000366'],
  // CKV_AZURE_15: Ensure web app is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_15': ['CCI-002607'],
  // CKV_AZURE_150: Ensure Machine Learning Compute Cluster Minimum Nodes Set To 0 → NIST: CM-6
  'CKV_AZURE_150': ['CCI-000366'],
  // CKV_AZURE_151: Ensure Windows VM enables encryption → NIST: SC-13
  'CKV_AZURE_151': ['CCI-002450'],
  // CKV_AZURE_152: Ensure Client Certificates are enforced for API management → NIST: CM-6
  'CKV_AZURE_152': ['CCI-000366'],
  // CKV_AZURE_153: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service Slot → NIST: SC-8(1)
  'CKV_AZURE_153': ['CCI-002420'],
  // CKV_AZURE_154: Ensure the App service slot is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_154': ['CCI-002607'],
  // CKV_AZURE_155: Ensure debugging is disabled for the App service slot → NIST: CM-6
  'CKV_AZURE_155': ['CCI-000366'],
  // CKV_AZURE_156: Ensure default Auditing policy for a SQL Server is configured to capture and ... → NIST: AU-2, AU-12
  'CKV_AZURE_156': ['CCI-000130', 'CCI-000169'],
  // CKV_AZURE_157: Ensure that Synapse workspace has data_exfiltration_protection_enabled → NIST: CM-6
  'CKV_AZURE_157': ['CCI-000366'],
  // CKV_AZURE_158: Ensure Databricks Workspace data plane to control plane communication happens... → NIST: SC-7(3)
  'CKV_AZURE_158': ['CCI-001098'],
  // CKV_AZURE_159: Ensure function app builtin logging is enabled → NIST: AU-2, AU-12
  'CKV_AZURE_159': ['CCI-000130', 'CCI-000169'],
  // CKV_AZURE_160: Ensure that HTTP (port 80) access is restricted from the internet → NIST: CM-6
  'CKV_AZURE_160': ['CCI-000366'],
  // CKV_AZURE_161: Ensures Spring Cloud API Portal is enabled on for HTTPS → NIST: CM-6
  'CKV_AZURE_161': ['CCI-000366'],
  // CKV_AZURE_162: Ensures Spring Cloud API Portal Public Access Is Disabled → NIST: SC-7(5), AC-3
  'CKV_AZURE_162': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_163: Enable vulnerability scanning for container images. → NIST: RA-5(2)
  'CKV_AZURE_163': ['CCI-001645'],
  // CKV_AZURE_164: Ensures that ACR uses signed/trusted images → NIST: SI-7(6), SR-3
  'CKV_AZURE_164': ['CCI-002705', 'CCI-003610'],
  // CKV_AZURE_165: Ensure geo-replicated container registries to match multi-region container de... → NIST: CP-6(1), CP-9(3)
  'CKV_AZURE_165': ['CCI-000504', 'CCI-000512'],
  // CKV_AZURE_166: Ensure container image quarantine, scan, and mark images verified → NIST: RA-5(1), SI-2(1)
  'CKV_AZURE_166': ['CCI-001644', 'CCI-002606'],
  // CKV_AZURE_167: Ensure a retention policy is set to cleanup untagged manifests. → NIST: MP-6(1), AU-11
  'CKV_AZURE_167': ['CCI-001904', 'CCI-000167'],
  // CKV_AZURE_168: Ensure Azure Kubernetes Cluster (AKS) nodes should use a minimum number of 50... → NIST: CM-6
  'CKV_AZURE_168': ['CCI-000366'],
  // CKV_AZURE_169: Ensure Azure Kubernetes Cluster (AKS) nodes use scale sets → NIST: CM-6
  'CKV_AZURE_169': ['CCI-000366'],
  // CKV_AZURE_17: Ensure the web app has 'Client Certificates (Incoming client certificates)' set → NIST: CM-6
  'CKV_AZURE_17': ['CCI-000366'],
  // CKV_AZURE_170: Ensure that AKS use the Paid Sku for its SLA → NIST: CM-6
  'CKV_AZURE_170': ['CCI-000366'],
  // CKV_AZURE_171: Ensure AKS cluster upgrade channel is chosen → NIST: SI-2(2)
  'CKV_AZURE_171': ['CCI-002607'],
  // CKV_AZURE_172: Ensure autorotation of Secrets Store CSI Driver secrets for AKS clusters → NIST: IA-5(7), SC-28(1)
  'CKV_AZURE_172': ['CCI-000190', 'CCI-002476'],
  // CKV_AZURE_173: Ensure API management uses at least TLS 1.2 → NIST: SC-8(1), SC-13
  'CKV_AZURE_173': ['CCI-002420', 'CCI-002450'],
  // CKV_AZURE_174: Ensure API management public access is disabled → NIST: SC-7(5), AC-3
  'CKV_AZURE_174': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_175: Ensure Web PubSub uses a SKU with an SLA → NIST: CM-6
  'CKV_AZURE_175': ['CCI-000366'],
  // CKV_AZURE_177: Ensure Windows VM enables automatic updates → NIST: CM-6
  'CKV_AZURE_177': ['CCI-000366'],
  // CKV_AZURE_178: Ensure linux VM enables SSH with keys for secure communication → NIST: AC-17(2), IA-2(6)
  'CKV_AZURE_178': ['CCI-000069', 'CCI-001941'],
  // CKV_AZURE_179: Ensure VM agent is installed → NIST: CM-6
  'CKV_AZURE_179': ['CCI-000366'],
  // CKV_AZURE_18: Ensure that 'HTTP Version' is the latest if used to run the web app → NIST: CM-6
  'CKV_AZURE_18': ['CCI-000366'],
  // CKV_AZURE_180: Ensure that data explorer uses Sku with an SLA → NIST: CM-6
  'CKV_AZURE_180': ['CCI-000366'],
  // CKV_AZURE_182: Ensure that VNET has at least 2 connected DNS Endpoints → NIST: CM-6
  'CKV_AZURE_182': ['CCI-000366'],
  // CKV_AZURE_183: Ensure that VNET uses local DNS addresses → NIST: CM-6
  'CKV_AZURE_183': ['CCI-000366'],
  // CKV_AZURE_184: Ensure 'local_auth_enabled' is set to 'False' → NIST: CM-6
  'CKV_AZURE_184': ['CCI-000366'],
  // CKV_AZURE_185: Ensure 'Public Access' is not Enabled for App configuration → NIST: SC-7(5), AC-3
  'CKV_AZURE_185': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_186: Ensure App configuration encryption block is set. → NIST: SC-13
  'CKV_AZURE_186': ['CCI-002450'],
  // CKV_AZURE_187: Ensure App configuration purge protection is enabled → NIST: CM-6
  'CKV_AZURE_187': ['CCI-000366'],
  // CKV_AZURE_188: Ensure App configuration Sku is standard → NIST: CM-6(1)
  'CKV_AZURE_188': ['CCI-001515'],
  // CKV_AZURE_189: Ensure that Azure Key Vault disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_189': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_19: Ensure that standard pricing tier is selected → NIST: CM-6
  'CKV_AZURE_19': ['CCI-000366'],
  // CKV_AZURE_190: Ensure that Storage blobs restrict public access → NIST: SC-7(5), AC-3
  'CKV_AZURE_190': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_192: Ensure that Azure Event Grid Topic local Authentication is disabled → NIST: CM-6
  'CKV_AZURE_192': ['CCI-000366'],
  // CKV_AZURE_193: Ensure public network access is disabled for Azure Event Grid Topic → NIST: SC-7(5), AC-3
  'CKV_AZURE_193': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_195: Ensure that Azure Event Grid Domain local Authentication is disabled → NIST: CM-6
  'CKV_AZURE_195': ['CCI-000366'],
  // CKV_AZURE_196: Ensure that SignalR uses a Paid Sku for its SLA → NIST: CM-6
  'CKV_AZURE_196': ['CCI-000366'],
  // CKV_AZURE_197: Ensure the Azure CDN disables the HTTP endpoint → NIST: CM-6
  'CKV_AZURE_197': ['CCI-000366'],
  // CKV_AZURE_198: Ensure the Azure CDN enables the HTTPS endpoint → NIST: CM-6
  'CKV_AZURE_198': ['CCI-000366'],
  // CKV_AZURE_199: Ensure that Azure Service Bus uses double encryption → NIST: SC-13
  'CKV_AZURE_199': ['CCI-002450'],
  // CKV_AZURE_2: Ensure Azure managed disk have encryption enabled → NIST: SC-28(1)
  'CKV_AZURE_2': ['CCI-002476'],
  // CKV_AZURE_20: Ensure that security contact 'Phone number' is set → NIST: CM-6
  'CKV_AZURE_20': ['CCI-000366'],
  // CKV_AZURE_200: Ensure the Azure CDN endpoint is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_200': ['CCI-002607'],
  // CKV_AZURE_201: Ensure that Azure Service Bus uses a customer-managed key to encrypt data → NIST: SC-28(1), SC-12(1)
  'CKV_AZURE_201': ['CCI-002476', 'CCI-002451'],
  // CKV_AZURE_203: Ensure Azure Service Bus Local Authentication is disabled → NIST: CM-6
  'CKV_AZURE_203': ['CCI-000366'],
  // CKV_AZURE_204: Ensure 'public network access enabled' is set to 'False' for Azure Service Bus → NIST: SC-7(5), AC-3
  'CKV_AZURE_204': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_205: Ensure Azure Service Bus is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_205': ['CCI-002607'],
  // CKV_AZURE_206: Ensure that Storage Accounts use replication → NIST: CM-6
  'CKV_AZURE_206': ['CCI-000366'],
  // CKV_AZURE_208: Ensure that Azure Cognitive Search maintains SLA for index updates → NIST: CM-6
  'CKV_AZURE_208': ['CCI-000366'],
  // CKV_AZURE_209: Ensure that Azure Cognitive Search maintains SLA for search index queries → NIST: CM-6
  'CKV_AZURE_209': ['CCI-000366'],
  // CKV_AZURE_21: Ensure that 'Send email notification for high severity alerts' is set to 'On' → NIST: SI-4(5), IR-6(1)
  'CKV_AZURE_21': ['CCI-002687', 'CCI-000229'],
  // CKV_AZURE_210: Ensure Azure Cognitive Search service allowed IPS does not give public Access → NIST: SC-7(5), AC-3
  'CKV_AZURE_210': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_211: Ensure App Service plan suitable for production use → NIST: CM-6(1)
  'CKV_AZURE_211': ['CCI-001515'],
  // CKV_AZURE_212: Ensure App Service has a minimum number of instances for failover → NIST: CP-10(2), CP-9
  'CKV_AZURE_212': ['CCI-000555', 'CCI-000509'],
  // CKV_AZURE_213: Ensure that App Service configures health check → NIST: CM-6
  'CKV_AZURE_213': ['CCI-000366'],
  // CKV_AZURE_214: Ensure App Service is set to be always on → NIST: CM-6
  'CKV_AZURE_214': ['CCI-000366'],
  // CKV_AZURE_215: Ensure API management backend uses https → NIST: CM-6
  'CKV_AZURE_215': ['CCI-000366'],
  // CKV_AZURE_216: Ensure DenyIntelMode is set to Deny for Azure Firewalls → NIST: CM-6
  'CKV_AZURE_216': ['CCI-000366'],
  // CKV_AZURE_217: Ensure Azure Application gateways listener that allow connection requests ove... → NIST: CM-6
  'CKV_AZURE_217': ['CCI-000366'],
  // CKV_AZURE_218: Ensure Application Gateway defines secure protocols for in transit communication → NIST: CM-6
  'CKV_AZURE_218': ['CCI-000366'],
  // CKV_AZURE_219: Ensure Firewall defines a firewall policy → NIST: CM-6
  'CKV_AZURE_219': ['CCI-000366'],
  // CKV_AZURE_22: Ensure that 'Send email notification for high severity alerts' is set to 'On' → NIST: SI-4(5), IR-6(1)
  'CKV_AZURE_22': ['CCI-002687', 'CCI-000229'],
  // CKV_AZURE_220: Ensure Firewall policy has IDPS mode as deny → NIST: CM-6
  'CKV_AZURE_220': ['CCI-000366'],
  // CKV_AZURE_221: Ensure that Azure Function App public network access is disabled → NIST: SC-7(5), AC-3
  'CKV_AZURE_221': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_222: Ensure that Azure Web App public network access is disabled → NIST: SC-7(5), AC-3
  'CKV_AZURE_222': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_223: Ensure Event Hub Namespace uses at least TLS 1.2 → NIST: SC-8(1), SC-13
  'CKV_AZURE_223': ['CCI-002420', 'CCI-002450'],
  // CKV_AZURE_224: Ensure that the Ledger feature is enabled on database that requires cryptogra... → NIST: SI-7(6), SR-3
  'CKV_AZURE_224': ['CCI-002705', 'CCI-003610'],
  // CKV_AZURE_225: Ensure the App Service Plan is zone redundant → NIST: CM-6
  'CKV_AZURE_225': ['CCI-000366'],
  // CKV_AZURE_226: Ensure ephemeral disks are used for OS disks → NIST: CM-6
  'CKV_AZURE_226': ['CCI-000366'],
  // CKV_AZURE_227: Ensure that the AKS cluster encrypt temp disks, caches, and data flows betwee... → NIST: SC-28(1)
  'CKV_AZURE_227': ['CCI-002476'],
  // CKV_AZURE_228: Ensure the Azure Event Hub Namespace is zone redundant → NIST: CM-6
  'CKV_AZURE_228': ['CCI-000366'],
  // CKV_AZURE_229: Ensure the Azure SQL Database Namespace is zone redundant → NIST: CM-6
  'CKV_AZURE_229': ['CCI-000366'],
  // CKV_AZURE_23: Ensure that 'Auditing' is set to 'Enabled' for SQL servers → NIST: AU-2, AU-12
  'CKV_AZURE_23': ['CCI-000130', 'CCI-000169'],
  // CKV_AZURE_230: Standard Replication should be enabled → NIST: CM-6
  'CKV_AZURE_230': ['CCI-000366'],
  // CKV_AZURE_231: Ensure App Service Environment is zone redundant → NIST: CM-6
  'CKV_AZURE_231': ['CCI-000366'],
  // CKV_AZURE_232: Ensure that only critical system pods run on system nodes → NIST: CM-6
  'CKV_AZURE_232': ['CCI-000366'],
  // CKV_AZURE_233: Ensure Azure Container Registry (ACR) is zone redundant → NIST: CM-6
  'CKV_AZURE_233': ['CCI-000366'],
  // CKV_AZURE_234: Ensure that Azure Defender for cloud is set to On for Resource Manager → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_234': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_235: Ensure that Azure container environment variables are configured with secure ... → NIST: IA-5(7), SC-28(1)
  'CKV_AZURE_235': ['CCI-000190', 'CCI-002476'],
  // CKV_AZURE_236: Ensure that Cognitive Services accounts disable local authentication → NIST: CM-6
  'CKV_AZURE_236': ['CCI-000366'],
  // CKV_AZURE_237: Ensure dedicated data endpoints are enabled. → NIST: CM-6
  'CKV_AZURE_237': ['CCI-000366'],
  // CKV_AZURE_239: Ensure Azure Synapse Workspace administrator login password is not exposed → NIST: AC-6(1), AC-6(5)
  'CKV_AZURE_239': ['CCI-000226', 'CCI-000230'],
  // CKV_AZURE_24: Ensure that 'Auditing' Retention is 'greater than 90 days' for SQL servers → NIST: CM-6
  'CKV_AZURE_24': ['CCI-000366'],
  // CKV_AZURE_240: Ensure Azure Synapse Workspace is encrypted with a CMK → NIST: SC-28(1), SC-12(1)
  'CKV_AZURE_240': ['CCI-002476', 'CCI-002451'],
  // CKV_AZURE_241: Ensure Synapse SQL pools are encrypted → NIST: SC-13
  'CKV_AZURE_241': ['CCI-002450'],
  // CKV_AZURE_242: Ensure isolated compute is enabled for Synapse Spark pools → NIST: CM-6
  'CKV_AZURE_242': ['CCI-000366'],
  // CKV_AZURE_243: Ensure Azure Machine learning workspace is configured with private endpoint → NIST: SC-7(3)
  'CKV_AZURE_243': ['CCI-001098'],
  // CKV_AZURE_244: Avoid the use of local users for Azure Storage unless necessary → NIST: CM-6
  'CKV_AZURE_244': ['CCI-000366'],
  // CKV_AZURE_245: Ensure that Azure Container group is deployed into virtual network → NIST: CM-6
  'CKV_AZURE_245': ['CCI-000366'],
  // CKV_AZURE_246: Ensure Azure AKS cluster HTTP application routing is disabled → NIST: CM-6
  'CKV_AZURE_246': ['CCI-000366'],
  // CKV_AZURE_247: Ensure that Azure Cognitive Services account hosted with OpenAI is configured... → NIST: SC-28(1), MP-4
  'CKV_AZURE_247': ['CCI-002476', 'CCI-001821'],
  // CKV_AZURE_248: Ensure that if Azure Batch account public network access in case 'enabled' th... → NIST: SC-7(5), AC-3
  'CKV_AZURE_248': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_249: Ensure Azure GitHub Actions OIDC trust policy is configured securely → NIST: IA-2(12), IA-8(2)
  'CKV_AZURE_249': ['CCI-001957', 'CCI-001954'],
  // CKV_AZURE_25: Azure SQL Server threat detection alerts are enabled for all threat types → NIST: CM-6
  'CKV_AZURE_25': ['CCI-000366'],
  // CKV_AZURE_250: Ensure Storage Sync Service is not configured with overly permissive network ... → NIST: CM-6
  'CKV_AZURE_250': ['CCI-000366'],
  // CKV_AZURE_251: Ensure Azure Virtual Machine disks are configured without public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_251': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_26: Ensure that 'Send Alerts To' is enabled for MSSQL servers → NIST: CM-6
  'CKV_AZURE_26': ['CCI-000366'],
  // CKV_AZURE_27: Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers → NIST: CM-6
  'CKV_AZURE_27': ['CCI-000366'],
  // CKV_AZURE_28: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server → NIST: SC-8(1)
  'CKV_AZURE_28': ['CCI-002420'],
  // CKV_AZURE_29: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database S... → NIST: SC-8(1)
  'CKV_AZURE_29': ['CCI-002420'],
  // CKV_AZURE_3: Ensure that 'supportsHttpsTrafficOnly' is set to 'true' → NIST: CM-6
  'CKV_AZURE_3': ['CCI-000366'],
  // CKV_AZURE_30: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Datab... → NIST: CM-6
  'CKV_AZURE_30': ['CCI-000366'],
  // CKV_AZURE_31: Ensure configuration 'log_connections' is set to 'ON' for PostgreSQL Database... → NIST: CM-6
  'CKV_AZURE_31': ['CCI-000366'],
  // CKV_AZURE_32: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL... → NIST: CM-6
  'CKV_AZURE_32': ['CCI-000366'],
  // CKV_AZURE_33: Ensure Storage logging is enabled for Queue service for read, write and delet... → NIST: AU-2, AU-12
  'CKV_AZURE_33': ['CCI-000130', 'CCI-000169'],
  // CKV_AZURE_34: Ensure that 'Public access level' is set to Private for blob containers → NIST: SC-7(5), AC-3
  'CKV_AZURE_34': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_35: Ensure default network access rule for Storage Accounts is set to deny → NIST: CM-6
  'CKV_AZURE_35': ['CCI-000366'],
  // CKV_AZURE_36: Ensure 'Trusted Microsoft Services' is enabled for Storage Account access → NIST: CM-6
  'CKV_AZURE_36': ['CCI-000366'],
  // CKV_AZURE_37: Ensure that Activity Log Retention is set 365 days or greater → NIST: AU-12(1), AU-3(1)
  'CKV_AZURE_37': ['CCI-000172', 'CCI-000135'],
  // CKV_AZURE_38: Ensure audit profile captures all the activities → NIST: AU-2, AU-12
  'CKV_AZURE_38': ['CCI-000130', 'CCI-000169'],
  // CKV_AZURE_39: Ensure that no custom subscription owner roles are created → NIST: CM-6
  'CKV_AZURE_39': ['CCI-000366'],
  // CKV_AZURE_4: Ensure AKS logging to Azure Monitoring is Configured → NIST: AU-2, AU-12
  'CKV_AZURE_4': ['CCI-000130', 'CCI-000169'],
  // CKV_AZURE_40: Ensure that the expiration date is set on all keys → NIST: CM-6
  'CKV_AZURE_40': ['CCI-000366'],
  // CKV_AZURE_41: Ensure that the expiration date is set on all secrets → NIST: CM-6
  'CKV_AZURE_41': ['CCI-000366'],
  // CKV_AZURE_42: Ensure the key vault is recoverable → NIST: SC-12(2)
  'CKV_AZURE_42': ['CCI-002452'],
  // CKV_AZURE_43: Ensure Storage Accounts adhere to the naming rules → NIST: CM-6
  'CKV_AZURE_43': ['CCI-000366'],
  // CKV_AZURE_44: Ensure Storage Account is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_44': ['CCI-002607'],
  // CKV_AZURE_45: Ensure that no sensitive credentials are exposed in VM custom_data → NIST: CM-6
  'CKV_AZURE_45': ['CCI-000366'],
  // CKV_AZURE_47: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MariaDB servers → NIST: SC-8(1)
  'CKV_AZURE_47': ['CCI-002420'],
  // CKV_AZURE_48: Ensure 'public network access enabled' is set to 'False' for MariaDB servers → NIST: SC-7(5), AC-3
  'CKV_AZURE_48': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_49: Ensure Azure linux scale set does not use basic authentication(Use SSH Key In... → NIST: AC-17(2), IA-2(6)
  'CKV_AZURE_49': ['CCI-000069', 'CCI-001941'],
  // CKV_AZURE_5: Ensure RBAC is enabled on AKS clusters → NIST: CM-6
  'CKV_AZURE_5': ['CCI-000366'],
  // CKV_AZURE_50: Ensure Virtual Machine Extensions are not Installed → NIST: CM-6
  'CKV_AZURE_50': ['CCI-000366'],
  // CKV_AZURE_52: Ensure MSSQL is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_52': ['CCI-002607'],
  // CKV_AZURE_53: Ensure 'public network access enabled' is set to 'False' for mySQL servers → NIST: SC-7(5), AC-3
  'CKV_AZURE_53': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_54: Ensure MySQL is using the latest version of TLS encryption → NIST: SI-2(2)
  'CKV_AZURE_54': ['CCI-002607'],
  // CKV_AZURE_55: Ensure that Azure Defender is set to On for Servers → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_55': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_56: Ensure that function apps enables Authentication → NIST: CM-6
  'CKV_AZURE_56': ['CCI-000366'],
  // CKV_AZURE_57: Ensure that CORS disallows every resource to access app services → NIST: CM-6
  'CKV_AZURE_57': ['CCI-000366'],
  // CKV_AZURE_58: Ensure that Azure Synapse workspaces enables managed virtual networks → NIST: CM-6
  'CKV_AZURE_58': ['CCI-000366'],
  // CKV_AZURE_59: Ensure that Storage accounts disallow public access → NIST: SC-7(5), AC-3
  'CKV_AZURE_59': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_6: Ensure AKS has an API Server Authorized IP Ranges enabled → NIST: CM-6
  'CKV_AZURE_6': ['CCI-000366'],
  // CKV_AZURE_61: Ensure that Azure Defender is set to On for App Service → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_61': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_62: Ensure function apps are not accessible from all regions → NIST: CM-6
  'CKV_AZURE_62': ['CCI-000366'],
  // CKV_AZURE_63: Ensure that App service enables HTTP logging → NIST: AU-2, AU-12
  'CKV_AZURE_63': ['CCI-000130', 'CCI-000169'],
  // CKV_AZURE_64: Ensure that Azure File Sync disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_64': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_65: Ensure that App service enables detailed error messages → NIST: CM-6
  'CKV_AZURE_65': ['CCI-000366'],
  // CKV_AZURE_66: Ensure that App service enables failed request tracing → NIST: SI-4(2), AU-12
  'CKV_AZURE_66': ['CCI-002684', 'CCI-000169'],
  // CKV_AZURE_67: Ensure that 'HTTP Version' is the latest, if used to run the Function app → NIST: CM-6
  'CKV_AZURE_67': ['CCI-000366'],
  // CKV_AZURE_68: Ensure that PostgreSQL server disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_68': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_69: Ensure that Azure Defender is set to On for Azure SQL database servers → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_69': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_7: Ensure AKS cluster has Network Policy configured → NIST: SC-7(3)
  'CKV_AZURE_7': ['CCI-001098'],
  // CKV_AZURE_70: Ensure that Function apps is only accessible over HTTPS → NIST: CM-6
  'CKV_AZURE_70': ['CCI-000366'],
  // CKV_AZURE_72: Ensure that remote debugging is not enabled for app services → NIST: CM-6
  'CKV_AZURE_72': ['CCI-000366'],
  // CKV_AZURE_73: Ensure that Automation account variables are encrypted → NIST: SC-13
  'CKV_AZURE_73': ['CCI-002450'],
  // CKV_AZURE_74: Ensure that Azure Data Explorer (Kusto) uses disk encryption → NIST: SC-28(1)
  'CKV_AZURE_74': ['CCI-002476'],
  // CKV_AZURE_75: Ensure that Azure Data Explorer uses double encryption → NIST: SC-13
  'CKV_AZURE_75': ['CCI-002450'],
  // CKV_AZURE_76: Ensure that Azure Batch account uses key vault to encrypt data → NIST: SC-12(2)
  'CKV_AZURE_76': ['CCI-002452'],
  // CKV_AZURE_77: Ensure that UDP Services are restricted from the Internet → NIST: CM-6
  'CKV_AZURE_77': ['CCI-000366'],
  // CKV_AZURE_78: Ensure FTP deployments are disabled → NIST: CM-6
  'CKV_AZURE_78': ['CCI-000366'],
  // CKV_AZURE_79: Ensure that Azure Defender is set to On for SQL servers on machines → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_79': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_8: Ensure Kubernetes Dashboard is disabled → NIST: CM-7(2)
  'CKV_AZURE_8': ['CCI-001521'],
  // CKV_AZURE_80: Ensure that 'Net Framework' version is the latest, if used as a part of the w... → NIST: SI-2(2)
  'CKV_AZURE_80': ['CCI-002607'],
  // CKV_AZURE_81: Ensure that 'PHP version' is the latest, if used to run the web app → NIST: CM-6
  'CKV_AZURE_81': ['CCI-000366'],
  // CKV_AZURE_82: Ensure that 'Python version' is the latest, if used to run the web app → NIST: CM-6
  'CKV_AZURE_82': ['CCI-000366'],
  // CKV_AZURE_83: Ensure that 'Java version' is the latest, if used to run the web app → NIST: CM-6
  'CKV_AZURE_83': ['CCI-000366'],
  // CKV_AZURE_84: Ensure that Azure Defender is set to On for Storage → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_84': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_85: Ensure that Azure Defender is set to On for Kubernetes → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_85': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_86: Ensure that Azure Defender is set to On for Container Registries → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_86': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_87: Ensure that Azure Defender is set to On for Key Vault → NIST: SI-4(4), RA-5(2)
  'CKV_AZURE_87': ['CCI-002686', 'CCI-001645'],
  // CKV_AZURE_88: Ensure that app services use Azure Files → NIST: CM-6
  'CKV_AZURE_88': ['CCI-000366'],
  // CKV_AZURE_89: Ensure that Azure Cache for Redis disables public network access → NIST: SC-7(5), AC-3
  'CKV_AZURE_89': ['CCI-001100', 'CCI-000213'],
  // CKV_AZURE_9: Ensure that RDP access is restricted from the internet → NIST: AC-17(2), IA-2(6)
  'CKV_AZURE_9': ['CCI-000069', 'CCI-001941'],
  // CKV_AZURE_91: Ensure that only SSL are enabled for Cache for Redis → NIST: SC-8(1)
  'CKV_AZURE_91': ['CCI-002420'],
  // CKV_AZURE_92: Ensure that Virtual Machines use managed disks → NIST: CM-6
  'CKV_AZURE_92': ['CCI-000366'],
  // CKV_AZURE_93: Ensure that managed disks use a specific set of disk encryption sets for the ... → NIST: SC-28(1), SC-12(1)
  'CKV_AZURE_93': ['CCI-002476', 'CCI-002451'],
  // CKV_AZURE_94: Ensure that My SQL server enables geo-redundant backups → NIST: CP-6(1), CP-9(3)
  'CKV_AZURE_94': ['CCI-000504', 'CCI-000512'],
  // CKV_AZURE_95: Ensure that automatic OS image patching is enabled for Virtual Machine Scale ... → NIST: CM-6
  'CKV_AZURE_95': ['CCI-000366'],
  // CKV_AZURE_96: Ensure that MySQL server enables infrastructure encryption → NIST: SC-13
  'CKV_AZURE_96': ['CCI-002450'],
  // CKV_AZURE_97: Ensure that Virtual machine scale sets have encryption at host enabled → NIST: SC-13
  'CKV_AZURE_97': ['CCI-002450'],
  // CKV_AZURE_98: Ensure that Azure Container group is deployed into virtual network → NIST: CM-6
  'CKV_AZURE_98': ['CCI-000366'],
  // CKV_AZURE_99: Ensure Cosmos DB accounts have restricted access → NIST: CM-6
  'CKV_AZURE_99': ['CCI-000366'],
  // CKV_BCW_1: Ensure no hard coded API token exist in the provider → NIST: CM-6
  'CKV_BCW_1': ['CCI-000366'],
  // CKV_BITBUCKETPIPELINES_1: Ensure the pipeline image uses a non latest version tag → NIST: SI-2(2)
  'CKV_BITBUCKETPIPELINES_1': ['CCI-002607'],
  // CKV_BITBUCKET_1: Merge requests should require at least 2 approvals → NIST: CM-3(2), CM-5(1)
  'CKV_BITBUCKET_1': ['CCI-001501', 'CCI-001510'],
  // CKV_CIRCLECIPIPELINES_1: Ensure the pipeline image uses a non latest version tag → NIST: SI-2(2)
  'CKV_CIRCLECIPIPELINES_1': ['CCI-002607'],
  // CKV_CIRCLECIPIPELINES_2: Ensure the pipeline image version is referenced via hash not arbitrary tag. → NIST: RA-5(5), SI-7(1)
  'CKV_CIRCLECIPIPELINES_2': ['CCI-001648', 'CCI-002700'],
  // CKV_CIRCLECIPIPELINES_3: Ensure mutable development orbs are not used. → NIST: CM-6
  'CKV_CIRCLECIPIPELINES_3': ['CCI-000366'],
  // CKV_CIRCLECIPIPELINES_4: Ensure unversioned volatile orbs are not used. → NIST: CM-6
  'CKV_CIRCLECIPIPELINES_4': ['CCI-000366'],
  // CKV_CIRCLECIPIPELINES_5: Suspicious use of netcat with IP address → NIST: CM-6
  'CKV_CIRCLECIPIPELINES_5': ['CCI-000366'],
  // CKV_CIRCLECIPIPELINES_6: Ensure run commands are not vulnerable to shell injection → NIST: CM-6
  'CKV_CIRCLECIPIPELINES_6': ['CCI-000366'],
  // CKV_CIRCLECIPIPELINES_7: Suspicious use of curl in run task → NIST: CM-6
  'CKV_CIRCLECIPIPELINES_7': ['CCI-000366'],
  // CKV_CIRCLECIPIPELINES_8: Detecting image usages in circleci pipelines → NIST: CM-6
  'CKV_CIRCLECIPIPELINES_8': ['CCI-000366'],
  // CKV_DIO_1: Ensure the Spaces bucket has versioning enabled → NIST: CP-9(1), AU-9(2)
  'CKV_DIO_1': ['CCI-000510', 'CCI-000164'],
  // CKV_DIO_2: Ensure the droplet specifies an SSH key → NIST: AC-17(2), IA-2(6)
  'CKV_DIO_2': ['CCI-000069', 'CCI-001941'],
  // CKV_DIO_3: Ensure the Spaces bucket is private → NIST: CM-6
  'CKV_DIO_3': ['CCI-000366'],
  // CKV_DIO_4: Ensure the firewall ingress is not wide open → NIST: SC-7(5)
  'CKV_DIO_4': ['CCI-001100'],
  // CKV_DOCKER_1: Ensure port 22 is not exposed → NIST: CM-6
  'CKV_DOCKER_1': ['CCI-000366'],
  // CKV_DOCKER_10: Ensure that WORKDIR values are absolute paths → NIST: CM-6
  'CKV_DOCKER_10': ['CCI-000366'],
  // CKV_DOCKER_11: Ensure From Alias are unique for multistage builds. → NIST: CM-6
  'CKV_DOCKER_11': ['CCI-000366'],
  // CKV_DOCKER_2: Ensure that HEALTHCHECK instructions have been added to container images → NIST: CM-6
  'CKV_DOCKER_2': ['CCI-000366'],
  // CKV_DOCKER_3: Ensure that a user for the container has been created → NIST: CM-6
  'CKV_DOCKER_3': ['CCI-000366'],
  // CKV_DOCKER_4: Ensure that COPY is used instead of ADD in Dockerfiles → NIST: CM-6
  'CKV_DOCKER_4': ['CCI-000366'],
  // CKV_DOCKER_5: Ensure update instructions are not use alone in the Dockerfile → NIST: SI-2(2)
  'CKV_DOCKER_5': ['CCI-002607'],
  // CKV_DOCKER_6: Ensure that LABEL maintainer is used instead of MAINTAINER (deprecated) → NIST: CM-6
  'CKV_DOCKER_6': ['CCI-000366'],
  // CKV_DOCKER_7: Ensure the base image uses a non latest version tag → NIST: SI-2(2)
  'CKV_DOCKER_7': ['CCI-002607'],
  // CKV_DOCKER_8: Ensure the last USER is not root → NIST: CM-6
  'CKV_DOCKER_8': ['CCI-000366'],
  // CKV_DOCKER_9: Ensure that APT isn't used → NIST: CM-6
  'CKV_DOCKER_9': ['CCI-000366'],
  // CKV_GCP_1: Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters → NIST: AU-2, AU-12
  'CKV_GCP_1': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_10: Ensure 'Automatic node upgrade' is enabled for Kubernetes Clusters → NIST: SI-2(2)
  'CKV_GCP_10': ['CCI-002607'],
  // CKV_GCP_100: Ensure that BigQuery Tables are not anonymously or publicly accessible → NIST: SC-7(5), AC-3
  'CKV_GCP_100': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_101: Ensure that Artifact Registry repositories are not anonymously or publicly ac... → NIST: SC-7(5), AC-3
  'CKV_GCP_101': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_102: Ensure that GCP Cloud Run services are not anonymously or publicly accessible → NIST: SC-7(5), AC-3
  'CKV_GCP_102': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_103: Ensure Dataproc Clusters do not have public IPs → NIST: SC-7(5), AC-3
  'CKV_GCP_103': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_104: Ensure Datafusion has stack driver logging enabled → NIST: AU-2, AU-12
  'CKV_GCP_104': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_105: Ensure Datafusion has stack driver monitoring enabled → NIST: AU-2, AU-12
  'CKV_GCP_105': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_106: Ensure Google compute firewall ingress does not allow unrestricted http port ... → NIST: SC-8(1)
  'CKV_GCP_106': ['CCI-002420'],
  // CKV_GCP_107: Cloud functions should not be public → NIST: AC-3, SC-7(5)
  'CKV_GCP_107': ['CCI-000213', 'CCI-001100'],
  // CKV_GCP_108: Ensure hostnames are logged for GCP PostgreSQL databases → NIST: CM-6
  'CKV_GCP_108': ['CCI-000366'],
  // CKV_GCP_109: Ensure the GCP PostgreSQL database log levels are set to ERROR or lower → NIST: AU-3(1), AU-12
  'CKV_GCP_109': ['CCI-000135', 'CCI-000169'],
  // CKV_GCP_11: Ensure that Cloud SQL database Instances are not open to the world → NIST: CM-6
  'CKV_GCP_11': ['CCI-000366'],
  // CKV_GCP_110: Ensure pgAudit is enabled for your GCP PostgreSQL database → NIST: CM-6
  'CKV_GCP_110': ['CCI-000366'],
  // CKV_GCP_111: Ensure GCP PostgreSQL logs SQL statements → NIST: AU-3(1), AU-12
  'CKV_GCP_111': ['CCI-000135', 'CCI-000169'],
  // CKV_GCP_112: Ensure KMS policy should not allow public access → NIST: SC-28(1), SC-12(1)
  'CKV_GCP_112': ['CCI-002476', 'CCI-002451'],
  // CKV_GCP_113: Ensure IAM policy should not define public access → NIST: SC-7(5), AC-3
  'CKV_GCP_113': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_114: Ensure public access prevention is enforced on Cloud Storage bucket → NIST: SC-7(5), AC-3
  'CKV_GCP_114': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_115: Ensure basic roles are not used at organization level. → NIST: CM-6
  'CKV_GCP_115': ['CCI-000366'],
  // CKV_GCP_116: Ensure basic roles are not used at folder level. → NIST: CM-6
  'CKV_GCP_116': ['CCI-000366'],
  // CKV_GCP_117: Ensure basic roles are not used at project level. → NIST: CM-6
  'CKV_GCP_117': ['CCI-000366'],
  // CKV_GCP_119: Ensure Spanner Database has deletion protection enabled → NIST: CM-6
  'CKV_GCP_119': ['CCI-000366'],
  // CKV_GCP_12: Ensure Network Policy is enabled on Kubernetes Engine Clusters → NIST: SC-7(3)
  'CKV_GCP_12': ['CCI-001098'],
  // CKV_GCP_120: Ensure Spanner Database has drop protection enabled → NIST: CM-6
  'CKV_GCP_120': ['CCI-000366'],
  // CKV_GCP_121: Ensure BigQuery tables have deletion protection enabled → NIST: CM-6
  'CKV_GCP_121': ['CCI-000366'],
  // CKV_GCP_122: Ensure Big Table Instances have deletion protection enabled → NIST: CM-6
  'CKV_GCP_122': ['CCI-000366'],
  // CKV_GCP_123: GKE Don't Use NodePools in the Cluster configuration → NIST: CM-6
  'CKV_GCP_123': ['CCI-000366'],
  // CKV_GCP_124: Ensure GCP Cloud Function is not configured with overly permissive Ingress se... → NIST: CM-6
  'CKV_GCP_124': ['CCI-000366'],
  // CKV_GCP_125: Ensure GCP GitHub Actions OIDC trust policy is configured securely → NIST: IA-2(12), IA-8(2)
  'CKV_GCP_125': ['CCI-001957', 'CCI-001954'],
  // CKV_GCP_126: Ensure Vertex AI Notebook instances are launched with Shielded VM enabled → NIST: CM-6
  'CKV_GCP_126': ['CCI-000366'],
  // CKV_GCP_127: Ensure Integrity Monitoring for Shielded Vertex AI Notebook Instances is Enabled → NIST: AU-2, AU-12
  'CKV_GCP_127': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_13: Ensure client certificate authentication to Kubernetes Engine Clusters is dis... → NIST: SC-8(1), SC-17
  'CKV_GCP_13': ['CCI-002420', 'CCI-002448'],
  // CKV_GCP_14: Ensure all Cloud SQL database instance have backup configuration enabled → NIST: CP-9(1)
  'CKV_GCP_14': ['CCI-000510'],
  // CKV_GCP_15: Ensure that BigQuery datasets are not anonymously or publicly accessible → NIST: SC-7(5), AC-3
  'CKV_GCP_15': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_16: Ensure that DNSSEC is enabled for Cloud DNS → NIST: CM-6
  'CKV_GCP_16': ['CCI-000366'],
  // CKV_GCP_17: Ensure that RSASHA1 is not used for the zone-signing and key-signing keys in ... → NIST: SC-7(4), SC-20
  'CKV_GCP_17': ['CCI-001099'],
  // CKV_GCP_18: Ensure GKE Control Plane is not public → NIST: AC-3, SC-7(5)
  'CKV_GCP_18': ['CCI-000213', 'CCI-001100'],
  // CKV_GCP_2: Ensure Google compute firewall ingress does not allow unrestricted ssh access → NIST: SC-7(5)
  'CKV_GCP_2': ['CCI-001100'],
  // CKV_GCP_20: Ensure master authorized networks is set to enabled in GKE clusters → NIST: CM-6
  'CKV_GCP_20': ['CCI-000366'],
  // CKV_GCP_21: Ensure Kubernetes Clusters are configured with Labels → NIST: CM-6
  'CKV_GCP_21': ['CCI-000366'],
  // CKV_GCP_22: Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters No... → NIST: CM-6
  'CKV_GCP_22': ['CCI-000366'],
  // CKV_GCP_23: Ensure Kubernetes Cluster is created with Alias IP ranges enabled → NIST: CM-6
  'CKV_GCP_23': ['CCI-000366'],
  // CKV_GCP_24: Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters → NIST: CM-6
  'CKV_GCP_24': ['CCI-000366'],
  // CKV_GCP_25: Ensure Kubernetes Cluster is created with Private cluster enabled → NIST: SC-7(3)
  'CKV_GCP_25': ['CCI-001098'],
  // CKV_GCP_26: Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network → NIST: SC-7(3)
  'CKV_GCP_26': ['CCI-001098'],
  // CKV_GCP_27: Ensure that the default network does not exist in a project → NIST: CM-6
  'CKV_GCP_27': ['CCI-000366'],
  // CKV_GCP_28: Ensure that Cloud Storage bucket is not anonymously or publicly accessible → NIST: SC-7(5), AC-3
  'CKV_GCP_28': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_29: Ensure that Cloud Storage buckets have uniform bucket-level access enabled → NIST: CM-6
  'CKV_GCP_29': ['CCI-000366'],
  // CKV_GCP_3: Ensure Google compute firewall ingress does not allow unrestricted rdp access → NIST: SC-7(5)
  'CKV_GCP_3': ['CCI-001100'],
  // CKV_GCP_30: Ensure that instances are not configured to use the default service account → NIST: AC-6(5), CM-6(1)
  'CKV_GCP_30': ['CCI-000230', 'CCI-001515'],
  // CKV_GCP_31: Ensure that instances are not configured to use the default service account w... → NIST: AC-6(5), CM-6(1)
  'CKV_GCP_31': ['CCI-000230', 'CCI-001515'],
  // CKV_GCP_32: Ensure 'Block Project-wide SSH keys' is enabled for VM instances → NIST: AC-17(2), IA-2(6)
  'CKV_GCP_32': ['CCI-000069', 'CCI-001941'],
  // CKV_GCP_33: Ensure oslogin is enabled for a Project → NIST: CM-6
  'CKV_GCP_33': ['CCI-000366'],
  // CKV_GCP_34: Ensure that no instance in the project overrides the project setting for enab... → NIST: CM-8(1)
  'CKV_GCP_34': ['CCI-000385'],
  // CKV_GCP_35: Ensure 'Enable connecting to serial ports' is not enabled for VM Instance → NIST: CM-6
  'CKV_GCP_35': ['CCI-000366'],
  // CKV_GCP_36: Ensure that IP forwarding is not enabled on Instances → NIST: CM-6
  'CKV_GCP_36': ['CCI-000366'],
  // CKV_GCP_37: Ensure VM disks for critical VMs are encrypted with Customer Supplied Encrypt... → NIST: SC-13
  'CKV_GCP_37': ['CCI-002450'],
  // CKV_GCP_38: Ensure VM disks for critical VMs are encrypted with Customer Supplied Encrypt... → NIST: SC-13
  'CKV_GCP_38': ['CCI-002450'],
  // CKV_GCP_39: Ensure Compute instances are launched with Shielded VM enabled → NIST: CM-6
  'CKV_GCP_39': ['CCI-000366'],
  // CKV_GCP_4: Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cip... → NIST: SC-8(1), SC-13
  'CKV_GCP_4': ['CCI-002420', 'CCI-002450'],
  // CKV_GCP_40: Ensure that Compute instances do not have public IP addresses → NIST: SC-7(5), AC-3
  'CKV_GCP_40': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_41: Ensure that IAM users are not assigned the Service Account User or Service Ac... → NIST: AC-2(1), AC-3
  'CKV_GCP_41': ['CCI-000016', 'CCI-000213'],
  // CKV_GCP_42: Ensure that Service Account has no Admin privileges → NIST: CM-6
  'CKV_GCP_42': ['CCI-000366'],
  // CKV_GCP_43: Ensure KMS encryption keys are rotated within a period of 90 days → NIST: SC-28(1), SC-12(1)
  'CKV_GCP_43': ['CCI-002476', 'CCI-002451'],
  // CKV_GCP_44: Ensure no roles that enable to impersonate and manage all service accounts ar... → NIST: CM-6
  'CKV_GCP_44': ['CCI-000366'],
  // CKV_GCP_45: Ensure no roles that enable to impersonate and manage all service accounts ar... → NIST: CM-6
  'CKV_GCP_45': ['CCI-000366'],
  // CKV_GCP_46: Ensure Default Service account is not used at a project level → NIST: AC-6(5), CM-6(1)
  'CKV_GCP_46': ['CCI-000230', 'CCI-001515'],
  // CKV_GCP_47: Ensure default service account is not used at an organization level → NIST: AC-6(5), CM-6(1)
  'CKV_GCP_47': ['CCI-000230', 'CCI-001515'],
  // CKV_GCP_48: Ensure Default Service account is not used at a folder level → NIST: AC-6(5), CM-6(1)
  'CKV_GCP_48': ['CCI-000230', 'CCI-001515'],
  // CKV_GCP_49: Ensure roles do not impersonate or manage Service Accounts used at project level → NIST: CM-6
  'CKV_GCP_49': ['CCI-000366'],
  // CKV_GCP_50: Ensure MySQL database 'local_infile' flag is set to 'off' → NIST: CM-6
  'CKV_GCP_50': ['CCI-000366'],
  // CKV_GCP_51: Ensure PostgreSQL database 'log_checkpoints' flag is set to 'on' → NIST: CM-6
  'CKV_GCP_51': ['CCI-000366'],
  // CKV_GCP_52: Ensure PostgreSQL database 'log_connections' flag is set to 'on' → NIST: CM-6
  'CKV_GCP_52': ['CCI-000366'],
  // CKV_GCP_53: Ensure PostgreSQL database 'log_disconnections' flag is set to 'on' → NIST: CM-6
  'CKV_GCP_53': ['CCI-000366'],
  // CKV_GCP_54: Ensure PostgreSQL database 'log_lock_waits' flag is set to 'on' → NIST: CM-6
  'CKV_GCP_54': ['CCI-000366'],
  // CKV_GCP_55: Ensure PostgreSQL database 'log_min_messages' flag is set to a valid value → NIST: CM-6
  'CKV_GCP_55': ['CCI-000366'],
  // CKV_GCP_56: Ensure PostgreSQL database 'log_temp_files flag is set to '0' → NIST: CM-6
  'CKV_GCP_56': ['CCI-000366'],
  // CKV_GCP_57: Ensure PostgreSQL database 'log_min_duration_statement' flag is set to '-1' → NIST: CM-6
  'CKV_GCP_57': ['CCI-000366'],
  // CKV_GCP_58: Ensure SQL database 'cross db ownership chaining' flag is set to 'off' → NIST: CM-6
  'CKV_GCP_58': ['CCI-000366'],
  // CKV_GCP_59: Ensure SQL database 'contained database authentication' flag is set to 'off' → NIST: CM-6
  'CKV_GCP_59': ['CCI-000366'],
  // CKV_GCP_6: Ensure all Cloud SQL database instance requires all incoming connections to u... → NIST: CM-6
  'CKV_GCP_6': ['CCI-000366'],
  // CKV_GCP_60: Ensure Cloud SQL database does not have public IP → NIST: SC-7(5), AC-3
  'CKV_GCP_60': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_61: Enable VPC Flow Logs and Intranode Visibility → NIST: SC-7(3)
  'CKV_GCP_61': ['CCI-001098'],
  // CKV_GCP_62: Bucket should log access → NIST: AU-2, AU-12
  'CKV_GCP_62': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_63: Bucket should not log to itself → NIST: AU-2, AU-12
  'CKV_GCP_63': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_64: Ensure clusters are created with Private Nodes → NIST: SC-7(3)
  'CKV_GCP_64': ['CCI-001098'],
  // CKV_GCP_65: Manage Kubernetes RBAC users with Google Groups for GKE → NIST: CM-6
  'CKV_GCP_65': ['CCI-000366'],
  // CKV_GCP_66: Ensure use of Binary Authorization → NIST: CM-6
  'CKV_GCP_66': ['CCI-000366'],
  // CKV_GCP_68: Ensure Secure Boot for Shielded GKE Nodes is Enabled → NIST: CM-6
  'CKV_GCP_68': ['CCI-000366'],
  // CKV_GCP_69: Ensure the GKE Metadata Server is Enabled → NIST: CM-6
  'CKV_GCP_69': ['CCI-000366'],
  // CKV_GCP_7: Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters → NIST: CM-6
  'CKV_GCP_7': ['CCI-000366'],
  // CKV_GCP_70: Ensure the GKE Release Channel is set → NIST: CM-6
  'CKV_GCP_70': ['CCI-000366'],
  // CKV_GCP_71: Ensure Shielded GKE Nodes are Enabled → NIST: CM-6
  'CKV_GCP_71': ['CCI-000366'],
  // CKV_GCP_72: Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled → NIST: AU-2, AU-12
  'CKV_GCP_72': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_73: Ensure Cloud Armor prevents message lookup in Log4j2. See CVE-2021-44228 aka ... → NIST: CM-6
  'CKV_GCP_73': ['CCI-000366'],
  // CKV_GCP_74: Ensure that private_ip_google_access is enabled for Subnet → NIST: SC-7(3)
  'CKV_GCP_74': ['CCI-001098'],
  // CKV_GCP_75: Ensure Google compute firewall ingress does not allow unrestricted FTP access → NIST: SC-7(5)
  'CKV_GCP_75': ['CCI-001100'],
  // CKV_GCP_76: Ensure that Private google access is enabled for IPV6 → NIST: SC-7(3)
  'CKV_GCP_76': ['CCI-001098'],
  // CKV_GCP_77: Ensure Google compute firewall ingress does not allow on ftp port → NIST: SC-7(5)
  'CKV_GCP_77': ['CCI-001100'],
  // CKV_GCP_78: Ensure Cloud storage has versioning enabled → NIST: CP-9(1), AU-9(2)
  'CKV_GCP_78': ['CCI-000510', 'CCI-000164'],
  // CKV_GCP_79: Ensure SQL database is using latest Major version → NIST: CM-6
  'CKV_GCP_79': ['CCI-000366'],
  // CKV_GCP_8: Ensure Stackdriver Monitoring is set to Enabled on Kubernetes Engine Clusters → NIST: AU-2, AU-12
  'CKV_GCP_8': ['CCI-000130', 'CCI-000169'],
  // CKV_GCP_80: Ensure Big Query Tables are encrypted with Customer Supplied Encryption Keys ... → NIST: SC-13
  'CKV_GCP_80': ['CCI-002450'],
  // CKV_GCP_81: Ensure Big Query Datasets are encrypted with Customer Supplied Encryption Key... → NIST: SC-13
  'CKV_GCP_81': ['CCI-002450'],
  // CKV_GCP_82: Ensure KMS keys are protected from deletion → NIST: SC-28(1), SC-12(1)
  'CKV_GCP_82': ['CCI-002476', 'CCI-002451'],
  // CKV_GCP_83: Ensure PubSub Topics are encrypted with Customer Supplied Encryption Keys (CSEK) → NIST: SC-13
  'CKV_GCP_83': ['CCI-002450'],
  // CKV_GCP_84: Ensure Artifact Registry Repositories are encrypted with Customer Supplied En... → NIST: SC-13
  'CKV_GCP_84': ['CCI-002450'],
  // CKV_GCP_85: Ensure Big Table Instances are encrypted with Customer Supplied Encryption Ke... → NIST: SC-13
  'CKV_GCP_85': ['CCI-002450'],
  // CKV_GCP_86: Ensure Cloud build workers are private → NIST: CM-6
  'CKV_GCP_86': ['CCI-000366'],
  // CKV_GCP_87: Ensure Data fusion instances are private → NIST: CM-6
  'CKV_GCP_87': ['CCI-000366'],
  // CKV_GCP_88: Ensure Google compute firewall ingress does not allow unrestricted mysql access → NIST: SC-7(5)
  'CKV_GCP_88': ['CCI-001100'],
  // CKV_GCP_89: Ensure Vertex AI instances are private → NIST: CM-6
  'CKV_GCP_89': ['CCI-000366'],
  // CKV_GCP_9: Ensure 'Automatic node repair' is enabled for Kubernetes Clusters → NIST: CM-6
  'CKV_GCP_9': ['CCI-000366'],
  // CKV_GCP_90: Ensure data flow jobs are encrypted with Customer Supplied Encryption Keys (C... → NIST: SC-13
  'CKV_GCP_90': ['CCI-002450'],
  // CKV_GCP_91: Ensure Dataproc cluster is encrypted with Customer Supplied Encryption Keys (... → NIST: SC-13
  'CKV_GCP_91': ['CCI-002450'],
  // CKV_GCP_92: Ensure Vertex AI datasets uses a CMK (Customer Managed Key) → NIST: SC-28(1), SC-12(1)
  'CKV_GCP_92': ['CCI-002476', 'CCI-002451'],
  // CKV_GCP_93: Ensure Spanner Database is encrypted with Customer Supplied Encryption Keys (... → NIST: SC-13
  'CKV_GCP_93': ['CCI-002450'],
  // CKV_GCP_94: Ensure Dataflow jobs are private → NIST: CM-6
  'CKV_GCP_94': ['CCI-000366'],
  // CKV_GCP_95: Ensure Memorystore for Redis has AUTH enabled → NIST: CM-6
  'CKV_GCP_95': ['CCI-000366'],
  // CKV_GCP_96: Ensure Vertex AI Metadata Store uses a CMK (Customer Managed Key) → NIST: SC-28(1), SC-12(1)
  'CKV_GCP_96': ['CCI-002476', 'CCI-002451'],
  // CKV_GCP_97: Ensure Memorystore for Redis uses intransit encryption → NIST: SC-13
  'CKV_GCP_97': ['CCI-002450'],
  // CKV_GCP_98: Ensure that Dataproc clusters are not anonymously or publicly accessible → NIST: SC-7(5), AC-3
  'CKV_GCP_98': ['CCI-001100', 'CCI-000213'],
  // CKV_GCP_99: Ensure that Pub/Sub Topics are not anonymously or publicly accessible → NIST: SC-7(5), AC-3
  'CKV_GCP_99': ['CCI-001100', 'CCI-000213'],
  // CKV_GHA_1: Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS isn't true on environment variables → NIST: IA-5(7), SC-28(1)
  'CKV_GHA_1': ['CCI-000190', 'CCI-002476'],
  // CKV_GHA_2: Ensure run commands are not vulnerable to shell injection → NIST: CM-6
  'CKV_GHA_2': ['CCI-000366'],
  // CKV_GHA_3: Suspicious use of curl with secrets → NIST: CM-6
  'CKV_GHA_3': ['CCI-000366'],
  // CKV_GHA_4: Suspicious use of netcat with IP address → NIST: CM-6
  'CKV_GHA_4': ['CCI-000366'],
  // CKV_GHA_5: Found artifact build without evidence of cosign sign execution in pipeline → NIST: CM-6
  'CKV_GHA_5': ['CCI-000366'],
  // CKV_GHA_6: Found artifact build without evidence of cosign sbom attestation in pipeline → NIST: SI-7(6), SR-3
  'CKV_GHA_6': ['CCI-002705', 'CCI-003610'],
  // CKV_GHA_7: The build output cannot be affected by user parameters other than the build e... → NIST: SA-11(1), SI-7(1)
  'CKV_GHA_7': ['CCI-002002', 'CCI-002700'],
  // CKV_GITHUB_1: Ensure GitHub organization security settings require 2FA → NIST: IA-2(1), IA-2(2)
  'CKV_GITHUB_1': ['CCI-000765', 'CCI-000766'],
  // CKV_GITHUB_10: Ensure branch protection rules are enforced on administrators → NIST: CM-6
  'CKV_GITHUB_10': ['CCI-000366'],
  // CKV_GITHUB_11: Ensure GitHub branch protection dismisses stale review on new commit → NIST: CM-3(2), CM-5(1)
  'CKV_GITHUB_11': ['CCI-001501', 'CCI-001510'],
  // CKV_GITHUB_12: Ensure GitHub branch protection restricts who can dismiss PR reviews → NIST: CM-3(2), CM-5(1)
  'CKV_GITHUB_12': ['CCI-001501', 'CCI-001510'],
  // CKV_GITHUB_13: Ensure GitHub branch protection requires CODEOWNER reviews → NIST: CM-3(2), CM-5(1)
  'CKV_GITHUB_13': ['CCI-001501', 'CCI-001510'],
  // CKV_GITHUB_14: Ensure all checks have passed before the merge of new code → NIST: CM-6
  'CKV_GITHUB_14': ['CCI-000366'],
  // CKV_GITHUB_15: Ensure inactive branches are reviewed and removed periodically → NIST: CM-3(2), CM-5(1)
  'CKV_GITHUB_15': ['CCI-001501', 'CCI-001510'],
  // CKV_GITHUB_16: Ensure GitHub branch protection requires conversation resolution → NIST: CM-6
  'CKV_GITHUB_16': ['CCI-000366'],
  // CKV_GITHUB_17: Ensure GitHub branch protection requires push restrictions → NIST: CM-6
  'CKV_GITHUB_17': ['CCI-000366'],
  // CKV_GITHUB_18: Ensure GitHub branch protection rules does not allow deletions → NIST: CM-6
  'CKV_GITHUB_18': ['CCI-000366'],
  // CKV_GITHUB_19: Ensure any change to code receives approval of two strongly authenticated users → NIST: CM-3(2), CM-5(1)
  'CKV_GITHUB_19': ['CCI-001501', 'CCI-001510'],
  // CKV_GITHUB_2: Ensure GitHub organization security settings require SSO → NIST: IA-2(12), IA-8(2)
  'CKV_GITHUB_2': ['CCI-001957', 'CCI-001954'],
  // CKV_GITHUB_20: Ensure open git branches are up to date before they can be merged into codebase → NIST: CM-6
  'CKV_GITHUB_20': ['CCI-000366'],
  // CKV_GITHUB_21: Ensure public repository creation is limited to specific members → NIST: AC-3, SC-7(5)
  'CKV_GITHUB_21': ['CCI-000213', 'CCI-001100'],
  // CKV_GITHUB_22: Ensure private repository creation is limited to specific members → NIST: CM-6
  'CKV_GITHUB_22': ['CCI-000366'],
  // CKV_GITHUB_23: Ensure internal repository creation is limited to specific members → NIST: CM-6
  'CKV_GITHUB_23': ['CCI-000366'],
  // CKV_GITHUB_26: Ensure minimum admins are set for the organization → NIST: AC-2(4), AC-6(5)
  'CKV_GITHUB_26': ['CCI-000019', 'CCI-000230'],
  // CKV_GITHUB_27: Ensure strict base permissions are set for repositories → NIST: CM-6
  'CKV_GITHUB_27': ['CCI-000366'],
  // CKV_GITHUB_28: Ensure an organization's identity is confirmed with a Verified badge Passed → NIST: CM-6
  'CKV_GITHUB_28': ['CCI-000366'],
  // CKV_GITHUB_3: Ensure GitHub organization security settings has IP allow list enabled → NIST: CM-6
  'CKV_GITHUB_3': ['CCI-000366'],
  // CKV_GITHUB_4: Ensure GitHub branch protection rules requires signed commits → NIST: SI-7(6), SR-3
  'CKV_GITHUB_4': ['CCI-002705', 'CCI-003610'],
  // CKV_GITHUB_5: Ensure GitHub branch protection rules does not allow force pushes → NIST: CM-6
  'CKV_GITHUB_5': ['CCI-000366'],
  // CKV_GITHUB_6: Ensure GitHub organization webhooks are using HTTPS → NIST: CM-6
  'CKV_GITHUB_6': ['CCI-000366'],
  // CKV_GITHUB_7: Ensure GitHub repository webhooks are using HTTPS → NIST: CM-6
  'CKV_GITHUB_7': ['CCI-000366'],
  // CKV_GITHUB_8: Ensure GitHub branch protection rules requires linear history → NIST: CM-6
  'CKV_GITHUB_8': ['CCI-000366'],
  // CKV_GITHUB_9: Ensure 2 admins are set for each repository → NIST: CM-6
  'CKV_GITHUB_9': ['CCI-000366'],
  // CKV_GITLABCI_1: Suspicious use of curl with CI environment variables in script → NIST: IA-5(7), SC-28(1)
  'CKV_GITLABCI_1': ['CCI-000190', 'CCI-002476'],
  // CKV_GITLABCI_2: Avoid creating rules that generate double pipelines → NIST: CM-6
  'CKV_GITLABCI_2': ['CCI-000366'],
  // CKV_GITLABCI_3: Detecting image usages in gitlab workflows → NIST: CM-6
  'CKV_GITLABCI_3': ['CCI-000366'],
  // CKV_GITLAB_1: Merge requests should require at least 2 approvals → NIST: CM-3(2), CM-5(1)
  'CKV_GITLAB_1': ['CCI-001501', 'CCI-001510'],
  // CKV_GIT_1: Ensure GitHub repository is Private → NIST: CM-6
  'CKV_GIT_1': ['CCI-000366'],
  // CKV_GIT_2: Ensure GitHub repository webhooks are using HTTPS → NIST: CM-6
  'CKV_GIT_2': ['CCI-000366'],
  // CKV_GIT_3: Ensure GitHub repository has vulnerability alerts enabled → NIST: RA-5(2)
  'CKV_GIT_3': ['CCI-001645'],
  // CKV_GIT_4: Ensure GitHub Actions secrets are encrypted → NIST: SC-13
  'CKV_GIT_4': ['CCI-002450'],
  // CKV_GIT_5: GitHub pull requests should require at least 2 approvals → NIST: CM-3(2), CM-5(1)
  'CKV_GIT_5': ['CCI-001501', 'CCI-001510'],
  // CKV_GIT_6: Ensure GitHub branch protection rules requires signed commits → NIST: SI-7(6), SR-3
  'CKV_GIT_6': ['CCI-002705', 'CCI-003610'],
  // CKV_GLB_1: Ensure at least two approving reviews are required to merge a GitLab MR → NIST: CM-3(2), CM-5(1)
  'CKV_GLB_1': ['CCI-001501', 'CCI-001510'],
  // CKV_GLB_2: Ensure GitLab branch protection rules does not allow force pushes → NIST: CM-6
  'CKV_GLB_2': ['CCI-000366'],
  // CKV_GLB_3: Ensure GitLab prevent secrets is enabled → NIST: CM-6
  'CKV_GLB_3': ['CCI-000366'],
  // CKV_GLB_4: Ensure GitLab commits are signed → NIST: SI-7(6), SR-3
  'CKV_GLB_4': ['CCI-002705', 'CCI-003610'],
  // CKV_K8S_1: Do not admit containers wishing to share the host process ID namespace → NIST: CM-6
  'CKV_K8S_1': ['CCI-000366'],
  // CKV_K8S_10: CPU requests should be set → NIST: SC-5(1), CM-6(1)
  'CKV_K8S_10': ['CCI-002385', 'CCI-001515'],
  // CKV_K8S_100: Ensure that the --tls-cert-file and --tls-private-key-file arguments are set ... → NIST: SC-8(1), SC-12(1)
  'CKV_K8S_100': ['CCI-002420', 'CCI-002451'],
  // CKV_K8S_102: Ensure that the --etcd-cafile argument is set as appropriate → NIST: SC-8(1), SC-12(1)
  'CKV_K8S_102': ['CCI-002420', 'CCI-002451'],
  // CKV_K8S_104: Ensure that encryption providers are appropriately configured → NIST: SC-13
  'CKV_K8S_104': ['CCI-002450'],
  // CKV_K8S_105: Ensure that the API Server only makes use of Strong Cryptographic Ciphers → NIST: SC-8(1), SC-13
  'CKV_K8S_105': ['CCI-002420', 'CCI-002450'],
  // CKV_K8S_106: Ensure that the --terminated-pod-gc-threshold argument is set as appropriate → NIST: CM-6(1)
  'CKV_K8S_106': ['CCI-001515'],
  // CKV_K8S_107: Ensure that the --profiling argument is set to false → NIST: CM-7(1)
  'CKV_K8S_107': ['CCI-000382'],
  // CKV_K8S_108: Ensure that the --use-service-account-credentials argument is set to true → NIST: AC-6(5)
  'CKV_K8S_108': ['CCI-000230'],
  // CKV_K8S_11: CPU limits should be set → NIST: SC-5(1), CM-6(1)
  'CKV_K8S_11': ['CCI-002385', 'CCI-001515'],
  // CKV_K8S_110: Ensure that the --service-account-private-key-file argument is set as appropr... → NIST: CM-6(1)
  'CKV_K8S_110': ['CCI-001515'],
  // CKV_K8S_111: Ensure that the --root-ca-file argument is set as appropriate → NIST: CM-6(1)
  'CKV_K8S_111': ['CCI-001515'],
  // CKV_K8S_112: Ensure that the RotateKubeletServerCertificate argument is set to true → NIST: CM-6(1)
  'CKV_K8S_112': ['CCI-001515'],
  // CKV_K8S_113: Ensure that the --bind-address argument is set to 127.0.0.1 → NIST: CM-6(1)
  'CKV_K8S_113': ['CCI-001515'],
  // CKV_K8S_114: Ensure that the --profiling argument is set to false → NIST: CM-7(1)
  'CKV_K8S_114': ['CCI-000382'],
  // CKV_K8S_115: Ensure that the --bind-address argument is set to 127.0.0.1 → NIST: CM-6(1)
  'CKV_K8S_115': ['CCI-001515'],
  // CKV_K8S_116: Ensure that the --cert-file and --key-file arguments are set as appropriate → NIST: CM-6
  'CKV_K8S_116': ['CCI-000366'],
  // CKV_K8S_117: Ensure that the --client-cert-auth argument is set to true → NIST: CM-6(1)
  'CKV_K8S_117': ['CCI-001515'],
  // CKV_K8S_118: Ensure that the --auto-tls argument is not set to true → NIST: CM-6(1)
  'CKV_K8S_118': ['CCI-001515'],
  // CKV_K8S_119: Ensure that the --peer-cert-file and --peer-key-file arguments are set as app... → NIST: CM-3(2), CM-5(1)
  'CKV_K8S_119': ['CCI-001501', 'CCI-001510'],
  // CKV_K8S_12: Memory requests should be set → NIST: SC-5(1), CM-6(1)
  'CKV_K8S_12': ['CCI-002385', 'CCI-001515'],
  // CKV_K8S_121: Ensure that the --peer-client-cert-auth argument is set to true → NIST: CM-3(2), CM-5(1)
  'CKV_K8S_121': ['CCI-001501', 'CCI-001510'],
  // CKV_K8S_13: Memory limits should be set → NIST: SC-5(1), CM-6(1)
  'CKV_K8S_13': ['CCI-002385', 'CCI-001515'],
  // CKV_K8S_138: Ensure that the --anonymous-auth argument is set to false → NIST: AC-3(7), IA-2
  'CKV_K8S_138': ['CCI-002169', 'CCI-000764'],
  // CKV_K8S_139: Ensure that the --authorization-mode argument is not set to AlwaysAllow → NIST: AC-3(7), IA-2
  'CKV_K8S_139': ['CCI-002169', 'CCI-000764'],
  // CKV_K8S_14: Image Tag should be fixed - not latest or blank → NIST: RA-5(5), SI-7(1)
  'CKV_K8S_14': ['CCI-001648', 'CCI-002700'],
  // CKV_K8S_140: Ensure that the --client-ca-file argument is set as appropriate → NIST: SC-8(1), SC-12(1)
  'CKV_K8S_140': ['CCI-002420', 'CCI-002451'],
  // CKV_K8S_141: Ensure that the --read-only-port argument is set to 0 → NIST: CM-6(1), AU-9(4)
  'CKV_K8S_141': ['CCI-001515', 'CCI-000166'],
  // CKV_K8S_144: Ensure that the --protect-kernel-defaults argument is set to true → NIST: CM-6(1)
  'CKV_K8S_144': ['CCI-001515'],
  // CKV_K8S_145: Ensure that the --make-iptables-util-chains argument is set to true → NIST: CM-6(1)
  'CKV_K8S_145': ['CCI-001515'],
  // CKV_K8S_146: Ensure that the --hostname-override argument is not set → NIST: CM-6(1)
  'CKV_K8S_146': ['CCI-001515'],
  // CKV_K8S_147: Ensure that the --event-qps argument is set to 0 or a level which ensures app... → NIST: SI-4(5), IR-6(1)
  'CKV_K8S_147': ['CCI-002687', 'CCI-000229'],
  // CKV_K8S_148: Ensure that the --tls-cert-file and --tls-private-key-file arguments are set ... → NIST: SC-8(1), SC-12(1)
  'CKV_K8S_148': ['CCI-002420', 'CCI-002451'],
  // CKV_K8S_149: Ensure that the --rotate-certificates argument is not set to false → NIST: CM-6(1)
  'CKV_K8S_149': ['CCI-001515'],
  // CKV_K8S_15: Image Pull Policy should be Always → NIST: CM-6
  'CKV_K8S_15': ['CCI-000366'],
  // CKV_K8S_151: Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers → NIST: SC-8(1), SC-13
  'CKV_K8S_151': ['CCI-002420', 'CCI-002450'],
  // CKV_K8S_152: Prevent NGINX Ingress annotation snippets which contain LUA code execution. S... → NIST: CM-6
  'CKV_K8S_152': ['CCI-000366'],
  // CKV_K8S_153: Prevent All NGINX Ingress annotation snippets. See CVE-2021-25742 → NIST: CM-6
  'CKV_K8S_153': ['CCI-000366'],
  // CKV_K8S_154: Prevent NGINX Ingress annotation snippets which contain alias statements See ... → NIST: CM-6
  'CKV_K8S_154': ['CCI-000366'],
  // CKV_K8S_155: Minimize ClusterRoles that grant control over validating or mutating admissio... → NIST: AC-6(1), AC-6(5)
  'CKV_K8S_155': ['CCI-000226', 'CCI-000230'],
  // CKV_K8S_156: Minimize ClusterRoles that grant permissions to approve CertificateSigningReq... → NIST: AC-6(1), AC-6(5)
  'CKV_K8S_156': ['CCI-000226', 'CCI-000230'],
  // CKV_K8S_157: Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings o... → NIST: AC-6(1), AC-6(5)
  'CKV_K8S_157': ['CCI-000226', 'CCI-000230'],
  // CKV_K8S_158: Minimize Roles and ClusterRoles that grant permissions to escalate Roles or C... → NIST: AC-6(1), AC-6(5)
  'CKV_K8S_158': ['CCI-000226', 'CCI-000230'],
  // CKV_K8S_159: Limit the use of git-sync to prevent code injection → NIST: CM-6
  'CKV_K8S_159': ['CCI-000366'],
  // CKV_K8S_16: Container should not be privileged → NIST: AC-6(1), CM-7(2)
  'CKV_K8S_16': ['CCI-000226', 'CCI-001521'],
  // CKV_K8S_17: Containers should not share the host process ID namespace → NIST: CM-6
  'CKV_K8S_17': ['CCI-000366'],
  // CKV_K8S_18: Containers should not share the host IPC namespace → NIST: CM-6
  'CKV_K8S_18': ['CCI-000366'],
  // CKV_K8S_19: Containers should not share the host network namespace → NIST: CM-6
  'CKV_K8S_19': ['CCI-000366'],
  // CKV_K8S_2: Do not admit privileged containers → NIST: CM-6
  'CKV_K8S_2': ['CCI-000366'],
  // CKV_K8S_20: Containers should not run with allowPrivilegeEscalation → NIST: AC-6(1), AC-6(10)
  'CKV_K8S_20': ['CCI-000226', 'CCI-000235'],
  // CKV_K8S_21: The default namespace should not be used → NIST: AC-6(5), CM-6(1)
  'CKV_K8S_21': ['CCI-000230', 'CCI-001515'],
  // CKV_K8S_22: Use read-only filesystem for containers where possible → NIST: CM-6(1), AU-9(4)
  'CKV_K8S_22': ['CCI-001515', 'CCI-000166'],
  // CKV_K8S_23: Minimize the admission of root containers → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_23': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_24: Do not allow containers with added capability → NIST: CM-6
  'CKV_K8S_24': ['CCI-000366'],
  // CKV_K8S_25: Minimize the admission of containers with added capability → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_25': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_26: Do not specify hostPort unless absolutely necessary → NIST: SC-7(3), CM-7(2)
  'CKV_K8S_26': ['CCI-001098', 'CCI-001521'],
  // CKV_K8S_27: Do not expose the docker daemon socket to containers → NIST: CM-6
  'CKV_K8S_27': ['CCI-000366'],
  // CKV_K8S_28: Minimize the admission of containers with the NET_RAW capability → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_28': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_29: Apply security context to your pods and containers → NIST: CM-6
  'CKV_K8S_29': ['CCI-000366'],
  // CKV_K8S_3: Do not admit containers wishing to share the host IPC namespace → NIST: CM-6
  'CKV_K8S_3': ['CCI-000366'],
  // CKV_K8S_30: Apply security context to your containers → NIST: CM-6
  'CKV_K8S_30': ['CCI-000366'],
  // CKV_K8S_31: Ensure that the seccomp profile is set to docker/default or runtime/default → NIST: CM-6
  'CKV_K8S_31': ['CCI-000366'],
  // CKV_K8S_32: Ensure default seccomp profile set to docker/default or runtime/default → NIST: CM-6
  'CKV_K8S_32': ['CCI-000366'],
  // CKV_K8S_33: Ensure the Kubernetes dashboard is not deployed → NIST: CM-7(2)
  'CKV_K8S_33': ['CCI-001521'],
  // CKV_K8S_34: Ensure that Tiller (Helm v2) is not deployed → NIST: CM-6
  'CKV_K8S_34': ['CCI-000366'],
  // CKV_K8S_35: Prefer using secrets as files over secrets as environment variables → NIST: IA-5(7), SC-28(1)
  'CKV_K8S_35': ['CCI-000190', 'CCI-002476'],
  // CKV_K8S_36: Minimize the admission of containers with capabilities assigned → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_36': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_37: Minimize the admission of containers with capabilities assigned → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_37': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_38: Ensure that Service Account Tokens are only mounted where necessary → NIST: AC-6(5), IA-2(6)
  'CKV_K8S_38': ['CCI-000230', 'CCI-001941'],
  // CKV_K8S_39: Do not use the CAP_SYS_ADMIN linux capability → NIST: CM-6
  'CKV_K8S_39': ['CCI-000366'],
  // CKV_K8S_4: Do not admit containers wishing to share the host network namespace → NIST: CM-6
  'CKV_K8S_4': ['CCI-000366'],
  // CKV_K8S_40: Containers should run as a high UID to avoid host conflict → NIST: CM-6
  'CKV_K8S_40': ['CCI-000366'],
  // CKV_K8S_41: Ensure that default service accounts are not actively used → NIST: AC-6(5), CM-6(1)
  'CKV_K8S_41': ['CCI-000230', 'CCI-001515'],
  // CKV_K8S_42: Ensure that default service accounts are not actively used → NIST: AC-6(5), CM-6(1)
  'CKV_K8S_42': ['CCI-000230', 'CCI-001515'],
  // CKV_K8S_43: Image should use digest → NIST: RA-5(5), SI-7(1)
  'CKV_K8S_43': ['CCI-001648', 'CCI-002700'],
  // CKV_K8S_44: Ensure that the Tiller Service (Helm v2) is deleted → NIST: CM-6
  'CKV_K8S_44': ['CCI-000366'],
  // CKV_K8S_45: Ensure the Tiller Deployment (Helm V2) is not accessible from within the cluster → NIST: CM-6
  'CKV_K8S_45': ['CCI-000366'],
  // CKV_K8S_49: Minimize wildcard use in Roles and ClusterRoles → NIST: AC-6(1), AC-6(5)
  'CKV_K8S_49': ['CCI-000226', 'CCI-000230'],
  // CKV_K8S_5: Containers should not run with allowPrivilegeEscalation → NIST: AC-6(1), AC-6(10)
  'CKV_K8S_5': ['CCI-000226', 'CCI-000235'],
  // CKV_K8S_6: Do not admit root containers → NIST: CM-6
  'CKV_K8S_6': ['CCI-000366'],
  // CKV_K8S_68: Ensure that the --anonymous-auth argument is set to false → NIST: AC-3(7), IA-2
  'CKV_K8S_68': ['CCI-002169', 'CCI-000764'],
  // CKV_K8S_69: Ensure that the --basic-auth-file argument is not set → NIST: CM-6(1)
  'CKV_K8S_69': ['CCI-001515'],
  // CKV_K8S_7: Do not admit containers with the NET_RAW capability → NIST: CM-6
  'CKV_K8S_7': ['CCI-000366'],
  // CKV_K8S_70: Ensure that the --token-auth-file argument is not set → NIST: CM-6(1)
  'CKV_K8S_70': ['CCI-001515'],
  // CKV_K8S_71: Ensure that the --kubelet-https argument is set to true → NIST: CM-6(1)
  'CKV_K8S_71': ['CCI-001515'],
  // CKV_K8S_72: Ensure that the --kubelet-client-certificate and --kubelet-client-key argumen... → NIST: CM-6
  'CKV_K8S_72': ['CCI-000366'],
  // CKV_K8S_73: Ensure that the --kubelet-certificate-authority argument is set as appropriate → NIST: SC-8(1), SC-12(1)
  'CKV_K8S_73': ['CCI-002420', 'CCI-002451'],
  // CKV_K8S_74: Ensure that the --authorization-mode argument is not set to AlwaysAllow → NIST: AC-3(7), IA-2
  'CKV_K8S_74': ['CCI-002169', 'CCI-000764'],
  // CKV_K8S_75: Ensure that the --authorization-mode argument includes Node → NIST: AC-3(7), IA-2
  'CKV_K8S_75': ['CCI-002169', 'CCI-000764'],
  // CKV_K8S_77: Ensure that the --authorization-mode argument includes RBAC → NIST: AC-3(7), IA-2
  'CKV_K8S_77': ['CCI-002169', 'CCI-000764'],
  // CKV_K8S_78: Ensure that the admission control plugin EventRateLimit is set → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_78': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_79: Ensure that the admission control plugin AlwaysAdmit is not set → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_79': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_8: Liveness Probe Should be Configured → NIST: SI-4(5), CP-10(2)
  'CKV_K8S_8': ['CCI-002687', 'CCI-000555'],
  // CKV_K8S_80: Ensure that the admission control plugin AlwaysPullImages is set → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_80': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_81: Ensure that the admission control plugin SecurityContextDeny is set if PodSec... → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_81': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_82: Ensure that the admission control plugin ServiceAccount is set → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_82': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_83: Ensure that the admission control plugin NamespaceLifecycle is set → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_83': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_84: Ensure that the admission control plugin PodSecurityPolicy is set → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_84': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_85: Ensure that the admission control plugin NodeRestriction is set → NIST: CM-6(1), SI-7(1)
  'CKV_K8S_85': ['CCI-001515', 'CCI-002700'],
  // CKV_K8S_86: Ensure that the --insecure-bind-address argument is not set → NIST: AC-3(7), IA-2
  'CKV_K8S_86': ['CCI-002169', 'CCI-000764'],
  // CKV_K8S_88: Ensure that the --insecure-port argument is set to 0 → NIST: SC-8(1)
  'CKV_K8S_88': ['CCI-002420'],
  // CKV_K8S_89: Ensure that the --secure-port argument is not set to 0 → NIST: CM-6(1)
  'CKV_K8S_89': ['CCI-001515'],
  // CKV_K8S_9: Readiness Probe Should be Configured → NIST: SI-4(5), CP-10(2)
  'CKV_K8S_9': ['CCI-002687', 'CCI-000555'],
  // CKV_K8S_90: Ensure that the --profiling argument is set to false → NIST: CM-7(1)
  'CKV_K8S_90': ['CCI-000382'],
  // CKV_K8S_91: Ensure that the --audit-log-path argument is set → NIST: AU-12(1), AU-3(1)
  'CKV_K8S_91': ['CCI-000172', 'CCI-000135'],
  // CKV_K8S_92: Ensure that the --audit-log-maxage argument is set to 30 or as appropriate → NIST: AU-12(1), AU-3(1)
  'CKV_K8S_92': ['CCI-000172', 'CCI-000135'],
  // CKV_K8S_93: Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate → NIST: AU-12(1), AU-3(1)
  'CKV_K8S_93': ['CCI-000172', 'CCI-000135'],
  // CKV_K8S_94: Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate → NIST: AU-12(1), AU-3(1)
  'CKV_K8S_94': ['CCI-000172', 'CCI-000135'],
  // CKV_K8S_95: Ensure that the --request-timeout argument is set as appropriate → NIST: CM-6(1)
  'CKV_K8S_95': ['CCI-001515'],
  // CKV_K8S_96: Ensure that the --service-account-lookup argument is set to true → NIST: CM-6(1)
  'CKV_K8S_96': ['CCI-001515'],
  // CKV_K8S_97: Ensure that the --service-account-key-file argument is set as appropriate → NIST: CM-6(1)
  'CKV_K8S_97': ['CCI-001515'],
  // CKV_K8S_99: Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appro... → NIST: SC-8(1), SC-12(1)
  'CKV_K8S_99': ['CCI-002420', 'CCI-002451'],
  // CKV_LIN_1: Ensure no hard coded Linode tokens exist in provider → NIST: CM-6
  'CKV_LIN_1': ['CCI-000366'],
  // CKV_LIN_2: Ensure SSH key set in authorized_keys → NIST: AC-17(2), IA-2(6)
  'CKV_LIN_2': ['CCI-000069', 'CCI-001941'],
  // CKV_LIN_3: Ensure email is set → NIST: CM-6
  'CKV_LIN_3': ['CCI-000366'],
  // CKV_LIN_4: Ensure username is set → NIST: CM-6
  'CKV_LIN_4': ['CCI-000366'],
  // CKV_LIN_5: Ensure Inbound Firewall Policy is not set to ACCEPT → NIST: CM-6
  'CKV_LIN_5': ['CCI-000366'],
  // CKV_LIN_6: Ensure Outbound Firewall Policy is not set to ACCEPT → NIST: CM-6
  'CKV_LIN_6': ['CCI-000366'],
  // CKV_NCP_1: Ensure HTTP HTTPS Target group defines Healthcheck → NIST: CM-6
  'CKV_NCP_1': ['CCI-000366'],
  // CKV_NCP_10: Ensure no NACL allow inbound from 0.0.0.0:0 to port 22 → NIST: SC-7(5)
  'CKV_NCP_10': ['CCI-001100'],
  // CKV_NCP_11: Ensure no NACL allow inbound from 0.0.0.0:0 to port 3389 → NIST: SC-7(5)
  'CKV_NCP_11': ['CCI-001100'],
  // CKV_NCP_12: An inbound Network ACL rule should not allow ALL ports. → NIST: SC-7(4)
  'CKV_NCP_12': ['CCI-001099'],
  // CKV_NCP_13: Ensure LB Listener uses only secure protocols → NIST: SC-8(1), SC-7(4)
  'CKV_NCP_13': ['CCI-002420', 'CCI-001099'],
  // CKV_NCP_14: Ensure NAS is securely encrypted → NIST: SC-13
  'CKV_NCP_14': ['CCI-002450'],
  // CKV_NCP_15: Ensure Load Balancer Target Group is not using HTTP → NIST: CM-6
  'CKV_NCP_15': ['CCI-000366'],
  // CKV_NCP_16: Ensure Load Balancer isn't exposed to the internet → NIST: CM-6
  'CKV_NCP_16': ['CCI-000366'],
  // CKV_NCP_18: Ensure that auto Scaling groups that are associated with a load balancer, are... → NIST: CP-10(4), SC-5(2)
  'CKV_NCP_18': ['CCI-000557', 'CCI-002386'],
  // CKV_NCP_19: Ensure Naver Kubernetes Service public endpoint disabled → NIST: SC-7(5), AC-3
  'CKV_NCP_19': ['CCI-001100', 'CCI-000213'],
  // CKV_NCP_2: Ensure every access control groups rule has a description → NIST: AC-3(4)
  'CKV_NCP_2': ['CCI-002166'],
  // CKV_NCP_20: Ensure Routing Table associated with Web tier subnet have the default route (... → NIST: SC-7(3)
  'CKV_NCP_20': ['CCI-001098'],
  // CKV_NCP_22: Ensure NKS control plane logging enabled for all log types → NIST: AU-2, AU-12
  'CKV_NCP_22': ['CCI-000130', 'CCI-000169'],
  // CKV_NCP_23: Ensure Server instance should not have public IP. → NIST: SC-7(5), AC-3
  'CKV_NCP_23': ['CCI-001100', 'CCI-000213'],
  // CKV_NCP_24: Ensure Load Balancer Listener Using HTTPS → NIST: SC-8(1), SC-7(4)
  'CKV_NCP_24': ['CCI-002420', 'CCI-001099'],
  // CKV_NCP_25: Ensure no access control groups allow inbound from 0.0.0.0:0 to port 80 → NIST: SC-7(5)
  'CKV_NCP_25': ['CCI-001100'],
  // CKV_NCP_26: Ensure Access Control Group has Access Control Group Rule attached → NIST: AC-3(4)
  'CKV_NCP_26': ['CCI-002166'],
  // CKV_NCP_3: Ensure no security group rules allow outbound traffic to 0.0.0.0/0 → NIST: SC-7(5)
  'CKV_NCP_3': ['CCI-001100'],
  // CKV_NCP_4: Ensure no access control groups allow inbound from 0.0.0.0:0 to port 22 → NIST: SC-7(5)
  'CKV_NCP_4': ['CCI-001100'],
  // CKV_NCP_5: Ensure no access control groups allow inbound from 0.0.0.0:0 to port 3389 → NIST: SC-7(5)
  'CKV_NCP_5': ['CCI-001100'],
  // CKV_NCP_6: Ensure Server instance is encrypted. → NIST: SC-13
  'CKV_NCP_6': ['CCI-002450'],
  // CKV_NCP_7: Ensure Basic Block storage is encrypted. → NIST: SC-13
  'CKV_NCP_7': ['CCI-002450'],
  // CKV_NCP_8: Ensure no NACL allow inbound from 0.0.0.0:0 to port 20 → NIST: SC-7(5)
  'CKV_NCP_8': ['CCI-001100'],
  // CKV_NCP_9: Ensure no NACL allow inbound from 0.0.0.0:0 to port 21 → NIST: SC-7(5)
  'CKV_NCP_9': ['CCI-001100'],
  // CKV_OCI_1: Ensure no hard coded OCI private key in provider → NIST: IA-5(7), CM-6(1)
  'CKV_OCI_1': ['CCI-000190', 'CCI-001515'],
  // CKV_OCI_10: Ensure OCI Object Storage is not Public → NIST: AC-3, SC-7(5)
  'CKV_OCI_10': ['CCI-000213', 'CCI-001100'],
  // CKV_OCI_11: OCI IAM password policy - must contain lower case → NIST: IA-5(1)
  'CKV_OCI_11': ['CCI-000192'],
  // CKV_OCI_12: OCI IAM password policy - must contain Numeric characters → NIST: IA-5(1)
  'CKV_OCI_12': ['CCI-000192'],
  // CKV_OCI_13: OCI IAM password policy - must contain Special characters → NIST: IA-5(1)
  'CKV_OCI_13': ['CCI-000192'],
  // CKV_OCI_14: OCI IAM password policy - must contain Uppercase characters → NIST: IA-5(1)
  'CKV_OCI_14': ['CCI-000192'],
  // CKV_OCI_15: Ensure OCI File System is Encrypted with a customer Managed Key → NIST: SC-28(1), SC-12(1)
  'CKV_OCI_15': ['CCI-002476', 'CCI-002451'],
  // CKV_OCI_16: Ensure VCN has an inbound security list → NIST: CM-6
  'CKV_OCI_16': ['CCI-000366'],
  // CKV_OCI_17: Ensure VCN inbound security lists are stateless → NIST: CM-6
  'CKV_OCI_17': ['CCI-000366'],
  // CKV_OCI_18: OCI IAM password policy for local (non-federated) users has a minimum length ... → NIST: IA-5(1)
  'CKV_OCI_18': ['CCI-000192'],
  // CKV_OCI_19: Ensure no security list allow ingress from 0.0.0.0:0 to port 22. → NIST: SC-7(5)
  'CKV_OCI_19': ['CCI-001100'],
  // CKV_OCI_2: Ensure OCI Block Storage Block Volume has backup enabled → NIST: CP-9(1)
  'CKV_OCI_2': ['CCI-000510'],
  // CKV_OCI_20: Ensure no security list allow ingress from 0.0.0.0:0 to port 3389. → NIST: SC-7(5)
  'CKV_OCI_20': ['CCI-001100'],
  // CKV_OCI_21: Ensure security group has stateless ingress security rules → NIST: SC-7(4)
  'CKV_OCI_21': ['CCI-001099'],
  // CKV_OCI_22: Ensure no security groups rules allow ingress from 0.0.0.0/0 to port 22 → NIST: SC-7(5)
  'CKV_OCI_22': ['CCI-001100'],
  // CKV_OCI_23: Ensure OCI Data Catalog is configured without overly permissive network access → NIST: CM-6
  'CKV_OCI_23': ['CCI-000366'],
  // CKV_OCI_3: OCI Block Storage Block Volumes are not encrypted with a Customer Managed Key... → NIST: SC-28(1), SC-12(1)
  'CKV_OCI_3': ['CCI-002476', 'CCI-002451'],
  // CKV_OCI_4: Ensure OCI Compute Instance boot volume has in-transit data encryption enabled → NIST: SC-13
  'CKV_OCI_4': ['CCI-002450'],
  // CKV_OCI_5: Ensure OCI Compute Instance has Legacy MetaData service endpoint disabled → NIST: SC-7(3)
  'CKV_OCI_5': ['CCI-001098'],
  // CKV_OCI_6: Ensure OCI Compute Instance has monitoring enabled → NIST: AU-2, AU-12
  'CKV_OCI_6': ['CCI-000130', 'CCI-000169'],
  // CKV_OCI_7: Ensure OCI Object Storage bucket can emit object events → NIST: CM-6
  'CKV_OCI_7': ['CCI-000366'],
  // CKV_OCI_8: Ensure OCI Object Storage has versioning enabled → NIST: CP-9(1), AU-9(2)
  'CKV_OCI_8': ['CCI-000510', 'CCI-000164'],
  // CKV_OCI_9: Ensure OCI Object Storage is encrypted with Customer Managed Key → NIST: SC-28(1), SC-12(1)
  'CKV_OCI_9': ['CCI-002476', 'CCI-002451'],
  // CKV_OPENAPI_1: Ensure that securityDefinitions is defined and not empty - version 2.0 files → NIST: CM-6
  'CKV_OPENAPI_1': ['CCI-000366'],
  // CKV_OPENAPI_10: Ensure that operation object does not use 'password' flow in OAuth2 authentic... → NIST: CM-6
  'CKV_OPENAPI_10': ['CCI-000366'],
  // CKV_OPENAPI_11: Ensure that operation object does not use 'password' flow in OAuth2 authentic... → NIST: CM-6
  'CKV_OPENAPI_11': ['CCI-000366'],
  // CKV_OPENAPI_12: Ensure no security definition is using implicit flow on OAuth2, which is depr... → NIST: CM-6
  'CKV_OPENAPI_12': ['CCI-000366'],
  // CKV_OPENAPI_13: Ensure security definitions do not use basic auth - version 2.0 files → NIST: CM-6
  'CKV_OPENAPI_13': ['CCI-000366'],
  // CKV_OPENAPI_14: Ensure that operation objects do not use 'implicit' flow, which is deprecated... → NIST: CM-6
  'CKV_OPENAPI_14': ['CCI-000366'],
  // CKV_OPENAPI_15: Ensure that operation objects do not use basic auth - version 2.0 files → NIST: CM-6
  'CKV_OPENAPI_15': ['CCI-000366'],
  // CKV_OPENAPI_16: Ensure that operation objects have 'produces' field defined for GET operation... → NIST: CM-6
  'CKV_OPENAPI_16': ['CCI-000366'],
  // CKV_OPENAPI_17: Ensure that operation objects have 'consumes' field defined for PUT, POST and... → NIST: SI-2(2)
  'CKV_OPENAPI_17': ['CCI-002607'],
  // CKV_OPENAPI_18: Ensure that global schemes use 'https' protocol instead of 'http'- version 2.... → NIST: SC-8(1)
  'CKV_OPENAPI_18': ['CCI-002420'],
  // CKV_OPENAPI_19: Ensure that global security scope is defined in securityDefinitions - version... → NIST: CM-6
  'CKV_OPENAPI_19': ['CCI-000366'],
  // CKV_OPENAPI_2: Ensure that if the security scheme is not of type 'oauth2', the array value m... → NIST: CM-6
  'CKV_OPENAPI_2': ['CCI-000366'],
  // CKV_OPENAPI_20: Ensure that API keys are not sent over cleartext → NIST: CM-6
  'CKV_OPENAPI_20': ['CCI-000366'],
  // CKV_OPENAPI_21: Ensure that arrays have a maximum number of items → NIST: CM-6
  'CKV_OPENAPI_21': ['CCI-000366'],
  // CKV_OPENAPI_3: Ensure that security schemes don't allow cleartext credentials over unencrypt... → NIST: CM-6
  'CKV_OPENAPI_3': ['CCI-000366'],
  // CKV_OPENAPI_4: Ensure that the global security field has rules defined → NIST: CM-6
  'CKV_OPENAPI_4': ['CCI-000366'],
  // CKV_OPENAPI_5: Ensure that security operations is not empty. → NIST: CM-6
  'CKV_OPENAPI_5': ['CCI-000366'],
  // CKV_OPENAPI_6: Ensure that security requirement defined in securityDefinitions - version 2.0... → NIST: CM-6
  'CKV_OPENAPI_6': ['CCI-000366'],
  // CKV_OPENAPI_7: Ensure that the path scheme does not support unencrypted HTTP connection wher... → NIST: SC-8(1)
  'CKV_OPENAPI_7': ['CCI-002420'],
  // CKV_OPENAPI_8: Ensure that security is not using 'password' flow in OAuth2 authentication - ... → NIST: CM-6
  'CKV_OPENAPI_8': ['CCI-000366'],
  // CKV_OPENAPI_9: Ensure that security scopes of operations are defined in securityDefinitions ... → NIST: CM-6
  'CKV_OPENAPI_9': ['CCI-000366'],
  // CKV_OPENSTACK_1: Ensure no hard coded OpenStack password, token, or application_credential_sec... → NIST: IA-5(7), CM-6(1)
  'CKV_OPENSTACK_1': ['CCI-000190', 'CCI-001515'],
  // CKV_OPENSTACK_2: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 (tcp / udp) → NIST: SC-7(5)
  'CKV_OPENSTACK_2': ['CCI-001100'],
  // CKV_OPENSTACK_3: Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 (tcp / udp) → NIST: SC-7(5)
  'CKV_OPENSTACK_3': ['CCI-001100'],
  // CKV_OPENSTACK_4: Ensure that instance does not use basic credentials → NIST: CM-6
  'CKV_OPENSTACK_4': ['CCI-000366'],
  // CKV_OPENSTACK_5: Ensure firewall rule set a destination IP → NIST: SC-7(4)
  'CKV_OPENSTACK_5': ['CCI-001099'],
  // CKV_PAN_1: Ensure no hard coded PAN-OS credentials exist in provider → NIST: IA-5(7), CM-6(1)
  'CKV_PAN_1': ['CCI-000190', 'CCI-001515'],
  // CKV_PAN_10: Ensure logging at session end is enabled within security policies → NIST: AU-2, AU-12
  'CKV_PAN_10': ['CCI-000130', 'CCI-000169'],
  // CKV_PAN_11: Ensure IPsec profiles do not specify use of insecure encryption algorithms → NIST: SC-13
  'CKV_PAN_11': ['CCI-002450'],
  // CKV_PAN_12: Ensure IPsec profiles do not specify use of insecure authentication algorithms → NIST: CM-6
  'CKV_PAN_12': ['CCI-000366'],
  // CKV_PAN_13: Ensure IPsec profiles do not specify use of insecure protocols → NIST: SC-8(1)
  'CKV_PAN_13': ['CCI-002420'],
  // CKV_PAN_14: Ensure a Zone Protection Profile is defined within Security Zones → NIST: CM-6
  'CKV_PAN_14': ['CCI-000366'],
  // CKV_PAN_15: Ensure an Include ACL is defined for a Zone when User-ID is enabled → NIST: CM-6
  'CKV_PAN_15': ['CCI-000366'],
  // CKV_PAN_16: Ensure logging at session start is disabled within security policies except f... → NIST: AU-2, AU-12
  'CKV_PAN_16': ['CCI-000130', 'CCI-000169'],
  // CKV_PAN_17: Ensure security rules do not have 'source_zone' and 'destination_zone' both c... → NIST: CM-6
  'CKV_PAN_17': ['CCI-000366'],
  // CKV_PAN_2: Ensure plain-text management HTTP is not enabled for an Interface Management ... → NIST: CM-6
  'CKV_PAN_2': ['CCI-000366'],
  // CKV_PAN_3: Ensure plain-text management Telnet is not enabled for an Interface Managemen... → NIST: CM-6
  'CKV_PAN_3': ['CCI-000366'],
  // CKV_PAN_4: Ensure DSRI is not enabled within security policies → NIST: CM-6
  'CKV_PAN_4': ['CCI-000366'],
  // CKV_PAN_5: Ensure security rules do not have 'applications' set to 'any' → NIST: CM-6
  'CKV_PAN_5': ['CCI-000366'],
  // CKV_PAN_6: Ensure security rules do not have 'services' set to 'any' → NIST: CM-6
  'CKV_PAN_6': ['CCI-000366'],
  // CKV_PAN_7: Ensure security rules do not have 'source_addresses' and 'destination_address... → NIST: CM-6
  'CKV_PAN_7': ['CCI-000366'],
  // CKV_PAN_8: Ensure description is populated within security policies → NIST: CM-6
  'CKV_PAN_8': ['CCI-000366'],
  // CKV_PAN_9: Ensure a Log Forwarding Profile is selected for each security policy rule → NIST: AU-2, AU-12
  'CKV_PAN_9': ['CCI-000130', 'CCI-000169'],
  // CKV_SECRET_1: Artifactory Credentials → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_1': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_11: Mailchimp Access Key → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_11': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_12: NPM tokens → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_12': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_13: Private Key → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_13': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_14: Slack Token → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_14': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_15: SoftLayer Credentials → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_15': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_16: Square OAuth Secret → NIST: IA-2(12), IA-8(2)
  'CKV_SECRET_16': ['CCI-001957', 'CCI-001954'],
  // CKV_SECRET_17: Stripe Access Key → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_17': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_18: Twilio API Key → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_18': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_19: Hex High Entropy String → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_19': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_2: AWS Access Key → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_2': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_3: Azure Storage Account access key → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_3': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_4: Basic Auth Credentials → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_4': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_5: Cloudant Credentials → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_5': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_6: Base64 High Entropy String → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_6': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_7: IBM Cloud IAM Key → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_7': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_8: IBM COS HMAC Credentials → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_8': ['CCI-000190', 'CCI-002476'],
  // CKV_SECRET_9: JSON Web Token → NIST: IA-5(7), SC-28(1)
  'CKV_SECRET_9': ['CCI-000190', 'CCI-002476'],
  // CKV_TC_1: Ensure Tencent Cloud CBS is encrypted → NIST: SC-13
  'CKV_TC_1': ['CCI-002450'],
  // CKV_TC_10: Ensure Tencent Cloud MySQL instances intranet ports are not set to the defaul... → NIST: CM-6
  'CKV_TC_10': ['CCI-000366'],
  // CKV_TC_11: Ensure Tencent Cloud CLB has a logging ID and topic → NIST: AU-2, AU-12
  'CKV_TC_11': ['CCI-000130', 'CCI-000169'],
  // CKV_TC_12: Ensure Tencent Cloud CLBs use modern, encrypted protocols → NIST: SC-13
  'CKV_TC_12': ['CCI-002450'],
  // CKV_TC_13: Ensure Tencent Cloud CVM user data does not contain sensitive information → NIST: SC-28(1), MP-4
  'CKV_TC_13': ['CCI-002476', 'CCI-001821'],
  // CKV_TC_14: Ensure Tencent Cloud VPC flow logs are enabled → NIST: SC-7(3)
  'CKV_TC_14': ['CCI-001098'],
  // CKV_TC_2: Ensure Tencent Cloud CVM instance does not allocate a public IP → NIST: SC-7(5), AC-3
  'CKV_TC_2': ['CCI-001100', 'CCI-000213'],
  // CKV_TC_3: Ensure Tencent Cloud CVM monitor service is enabled → NIST: AU-2, AU-12
  'CKV_TC_3': ['CCI-000130', 'CCI-000169'],
  // CKV_TC_4: Ensure Tencent Cloud CVM instances do not use the default security group → NIST: CM-6
  'CKV_TC_4': ['CCI-000366'],
  // CKV_TC_5: Ensure Tencent Cloud CVM instances do not use the default VPC → NIST: SC-7(3)
  'CKV_TC_5': ['CCI-001098'],
  // CKV_TC_6: Ensure Tencent Cloud TKE clusters enable log agent → NIST: AU-2, AU-12
  'CKV_TC_6': ['CCI-000130', 'CCI-000169'],
  // CKV_TC_7: Ensure Tencent Cloud TKE cluster is not assigned a public IP address → NIST: SC-7(5), AC-3
  'CKV_TC_7': ['CCI-001100', 'CCI-000213'],
  // CKV_TC_8: Ensure Tencent Cloud VPC security group rules do not accept all traffic → NIST: SC-7(4)
  'CKV_TC_8': ['CCI-001099'],
  // CKV_TC_9: Ensure Tencent Cloud mysql instances do not enable access from public networks → NIST: AC-3, SC-7(5)
  'CKV_TC_9': ['CCI-000213', 'CCI-001100'],
  // CKV_TF_1: Ensure Terraform module sources use a commit hash → NIST: SI-7(6), SR-3
  'CKV_TF_1': ['CCI-002705', 'CCI-003610'],
  // CKV_TF_2: Ensure Terraform module sources use a tag with a version number → NIST: CM-6
  'CKV_TF_2': ['CCI-000366'],
  // CKV_YC_1: Ensure security group is assigned to database cluster. → NIST: SC-7(4)
  'CKV_YC_1': ['CCI-001099'],
  // CKV_YC_10: Ensure etcd database is encrypted with KMS key. → NIST: SC-28(1), SC-12(1)
  'CKV_YC_10': ['CCI-002476', 'CCI-002451'],
  // CKV_YC_11: Ensure security group is assigned to network interface. → NIST: SC-7(4)
  'CKV_YC_11': ['CCI-001099'],
  // CKV_YC_12: Ensure public IP is not assigned to database cluster. → NIST: SC-7(5), AC-3
  'CKV_YC_12': ['CCI-001100', 'CCI-000213'],
  // CKV_YC_13: Ensure cloud member does not have elevated access. → NIST: CM-6
  'CKV_YC_13': ['CCI-000366'],
  // CKV_YC_14: Ensure security group is assigned to Kubernetes cluster. → NIST: SC-7(4)
  'CKV_YC_14': ['CCI-001099'],
  // CKV_YC_15: Ensure security group is assigned to Kubernetes node group. → NIST: SC-7(4)
  'CKV_YC_15': ['CCI-001099'],
  // CKV_YC_16: Ensure network policy is assigned to Kubernetes cluster. → NIST: SC-7(3)
  'CKV_YC_16': ['CCI-001098'],
  // CKV_YC_17: Ensure storage bucket does not have public access permissions. → NIST: SC-7(5), AC-3
  'CKV_YC_17': ['CCI-001100', 'CCI-000213'],
  // CKV_YC_18: Ensure compute instance group does not have public IP. → NIST: SC-7(5), AC-3
  'CKV_YC_18': ['CCI-001100', 'CCI-000213'],
  // CKV_YC_19: Ensure security group does not contain allow-all rules. → NIST: SC-7(4)
  'CKV_YC_19': ['CCI-001099'],
  // CKV_YC_2: Ensure compute instance does not have public IP. → NIST: SC-7(5), AC-3
  'CKV_YC_2': ['CCI-001100', 'CCI-000213'],
  // CKV_YC_20: Ensure security group rule is not allow-all. → NIST: SC-7(4)
  'CKV_YC_20': ['CCI-001099'],
  // CKV_YC_21: Ensure organization member does not have elevated access. → NIST: CM-6
  'CKV_YC_21': ['CCI-000366'],
  // CKV_YC_22: Ensure compute instance group has security group assigned. → NIST: SC-7(4)
  'CKV_YC_22': ['CCI-001099'],
  // CKV_YC_23: Ensure folder member does not have elevated access. → NIST: CM-6
  'CKV_YC_23': ['CCI-000366'],
  // CKV_YC_24: Ensure passport account is not used for assignment. Use service accounts and ... → NIST: CM-6
  'CKV_YC_24': ['CCI-000366'],
  // CKV_YC_3: Ensure storage bucket is encrypted. → NIST: SC-13
  'CKV_YC_3': ['CCI-002450'],
  // CKV_YC_4: Ensure compute instance does not have serial console enabled. → NIST: CM-6
  'CKV_YC_4': ['CCI-000366'],
  // CKV_YC_5: Ensure Kubernetes cluster does not have public IP address. → NIST: SC-7(5), AC-3
  'CKV_YC_5': ['CCI-001100', 'CCI-000213'],
  // CKV_YC_6: Ensure Kubernetes cluster node group does not have public IP addresses. → NIST: SC-7(5), AC-3
  'CKV_YC_6': ['CCI-001100', 'CCI-000213'],
  // CKV_YC_7: Ensure Kubernetes cluster auto-upgrade is enabled. → NIST: SI-2(2)
  'CKV_YC_7': ['CCI-002607'],
  // CKV_YC_8: Ensure Kubernetes node group auto-upgrade is enabled. → NIST: SI-2(2)
  'CKV_YC_8': ['CCI-002607'],
  // CKV_YC_9: Ensure KMS symmetric key is rotated. → NIST: SC-28(1), SC-12(1)
  'CKV_YC_9': ['CCI-002476', 'CCI-002451'],
};
