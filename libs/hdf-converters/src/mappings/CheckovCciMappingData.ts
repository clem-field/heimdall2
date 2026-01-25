// CCI mappings for Checkov/Bridgecrew rules
// Maps Checkov rule IDs to their corresponding CCI (Control Correlation Identifier) values
export const data: Record<string, string[]> = {
  // Encryption at Rest
  'CKV_AWS_136': ['CCI-001199', 'CCI-002475'], // SC-28, SC-28(1) - ECR KMS
  'CKV_AWS_18': ['CCI-000068', 'CCI-001453'], // SC-28 - S3 encryption
  'CKV_AWS_19': ['CCI-001199', 'CCI-002475'], // SC-28(1) - S3 SSE-KMS

  // Access Control
  'CKV_AWS_20': ['CCI-000213', 'CCI-001813'], // AC-3, AC-6 - S3 bucket ACLs
  'CKV_AWS_21': ['CCI-000186'], // AC-3(7) - S3 versioning

  // Add more Checkov rule to CCI mappings here as needed
};
