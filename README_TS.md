# Checkov to Heimdall Mapper

## Overview

This implementation integrates Checkov/Bridgecrew security scanning results into the Heimdall2 platform. The mapper converts Checkov SARIF output into HDF (Heimdall Data Format), enabling visualization and compliance analysis in Heimdall.

## Features

- **CCI/NIST Mapping**: Automatically maps Checkov rule IDs to CCI (Control Correlation Identifier) and derives corresponding NIST 800-53 controls
- **Severity Handling**: Maps Checkov severity levels (error, warning, note) to appropriate impact scores and status values
- **Rich Metadata**: Captures file locations, line numbers, code snippets, and resource types
- **Documentation Links**: Automatically generates Bridgecrew documentation URLs for each finding
- **Default Fallback**: Uses default static analysis NIST tags (SA-11, RA-5) for unmapped rules

## Implementation Files

### 1. CCI Mappings
**Location**: [libs/hdf-converters/src/mappings/CheckovCciMappingData.ts](libs/hdf-converters/src/mappings/CheckovCciMappingData.ts)

Maps Checkov rule IDs to CCI identifiers. Easily extensible to add more mappings.

```typescript
export const data: Record<string, string[]> = {
  'CKV_AWS_136': ['CCI-001199', 'CCI-002475'], // ECR KMS encryption
  'CKV_AWS_18': ['CCI-000068', 'CCI-001453'],  // S3 encryption
  'CKV_AWS_19': ['CCI-001199', 'CCI-002475'],  // S3 SSE-KMS
  'CKV_AWS_20': ['CCI-000213', 'CCI-001813'],  // S3 bucket ACLs
  'CKV_AWS_21': ['CCI-000186'],                // S3 versioning
};
```

### 2. Mapper Class
**Location**: [libs/hdf-converters/src/checkov-mapper.ts](libs/hdf-converters/src/checkov-mapper.ts)

Main converter class that extends `BaseConverter` and processes Checkov SARIF output into HDF format.

### 3. Test Suite
**Location**: [libs/hdf-converters/test/mappers/forward/checkov_mapper.spec.ts](libs/hdf-converters/test/mappers/forward/checkov_mapper.spec.ts)

Comprehensive test suite covering control mapping, status assignment, CCI/NIST derivation, and more.

### 4. Export Configuration
**Location**: [libs/hdf-converters/index.ts](libs/hdf-converters/index.ts)

Exports the CheckovMapper and CheckovCciMappingData for use in applications.

## Usage

### Basic Usage

```typescript
import {CheckovMapper} from '@mitre/hdf-converters';
import * as fs from 'fs';

// Read Checkov SARIF output
const checkovSarif = fs.readFileSync('checkov-output.json', 'utf8');

// Convert to HDF
const mapper = new CheckovMapper(checkovSarif);
const hdf = mapper.toHdf();

// Save as Heimdall-compatible JSON
fs.writeFileSync('heimdall-output.json', JSON.stringify(hdf, null, 2));
```

### With Raw Data Passthrough

```typescript
// Include raw Checkov data in the output
const mapper = new CheckovMapper(checkovSarif, true);
const hdf = mapper.toHdf();
```

## Running Checkov to Generate SARIF

To generate Checkov output in SARIF format:

```bash
# Scan Terraform files and output SARIF
checkov -d /path/to/terraform --output sarif --output-file checkov-output.json

# Scan specific file types
checkov -f main.tf --output sarif --output-file checkov-output.json

# Scan with specific framework
checkov --framework terraform --output sarif --output-file checkov-output.json
```

## Complete Workflow Example

```bash
# 1. Run Checkov scan on your infrastructure code
checkov -d ./terraform --output sarif --output-file checkov-results.json

# 2. Convert to HDF using the mapper (Node.js script)
node convert-to-hdf.js

# 3. Upload to Heimdall or view in Heimdall Lite
```

### Sample Conversion Script (`convert-to-hdf.js`)

```javascript
const {CheckovMapper} = require('@mitre/hdf-converters');
const fs = require('fs');

// Read Checkov SARIF output
const checkovSarif = fs.readFileSync('checkov-results.json', 'utf8');

// Convert to HDF
const mapper = new CheckovMapper(checkovSarif);
const hdf = mapper.toHdf();

// Save output
fs.writeFileSync('heimdall-output.json', JSON.stringify(hdf, null, 2));
console.log('Conversion complete! Output saved to heimdall-output.json');
```

## Running Tests

```bash
# Run all tests
npm test

# Run only Checkov mapper tests
npm test -- checkov_mapper.spec.ts
```

## Mapping Severity Levels

| Checkov Level | Impact Score | HDF Status |
|--------------|--------------|------------|
| error        | 0.7 (High)   | Failed     |
| warning      | 0.5 (Medium) | Failed     |
| note         | 0.3 (Low)    | Skipped    |

## Output Structure

The mapper generates HDF output with the following structure:

```json
{
  "platform": {
    "name": "Heimdall Tools",
    "release": "x.x.x",
    "target_id": "Checkov (Bridgecrew)"
  },
  "profiles": [
    {
      "name": "Checkov",
      "title": "Checkov Infrastructure Security Checks",
      "controls": [
        {
          "id": "CKV_AWS_136",
          "title": "Ensure that ECR repositories are encrypted using KMS",
          "desc": "...",
          "impact": 0.7,
          "tags": {
            "cci": ["CCI-001199", "CCI-002475"],
            "nist": ["SC-28", "SC-28(1)"],
            "severity": "error",
            "checkov_id": "CKV_AWS_136",
            "resource_type": "aws_ecr_repository"
          },
          "refs": [
            {"url": "https://docs.bridgecrew.io/docs/ckv_aws_136"}
          ],
          "source_location": {
            "ref": "main.tf",
            "line": 13
          },
          "results": [
            {
              "status": "failed",
              "code_desc": "File: main.tf Line: 13 - 17...",
              "message": "...",
              "start_time": "2026-01-25T..."
            }
          ]
        }
      ]
    }
  ]
}
```

## Extending CCI Mappings

To add more Checkov rule mappings, edit [CheckovCciMappingData.ts](libs/hdf-converters/src/mappings/CheckovCciMappingData.ts):

```typescript
export const data: Record<string, string[]> = {
  // Existing mappings...

  // Add new mappings
  'CKV_AWS_NEW_RULE': ['CCI-XXXXX', 'CCI-YYYYY'],
};
```

The mapper will automatically derive NIST controls from the CCI identifiers using the existing `CciNistMappingData`.

## Integration with Heimdall

Once converted to HDF format, the output can be:

1. **Uploaded to Heimdall Server** for centralized compliance management
2. **Viewed in Heimdall Lite** for local analysis
3. **Processed by other HDF-compatible tools** in the MITRE SAF ecosystem

## Architecture

The CheckovMapper follows the same architecture pattern as other Heimdall converters:

- Extends `BaseConverter` from `base-converter.ts`
- Uses declarative mapping configuration
- Leverages existing CCI/NIST mapping utilities
- Supports passthrough data for audit trails
- Generates consistent HDF output format

## Support

For issues or questions:
- File an issue in the Heimdall2 repository
- Refer to the [Heimdall documentation](https://github.com/mitre/heimdall2)
- Check the [Checkov documentation](https://www.checkov.io/5.Policy%20Index/terraform.html) for rule details
