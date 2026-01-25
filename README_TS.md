Here's the implementation approach:
1. Create Type Definitions File
src/types/heimdall.ts


export interface Control {
  id: string;
  title: string;
  desc: string;
  impact: number;
  refs: Reference[];
  tags: {
    cci: string[];
    nist: string[];
    [key: string]: any;
  };
  results: Result[];
}

export interface Reference {
  url?: string;
  ref?: string;
}

export interface Result {
  status: 'passed' | 'failed' | 'skipped';
  code_desc: string;
  message: string;
  start_time: string;
  run_time?: number;
}

export interface CheckovResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: {
    text: string;
  };
  locations: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
      };
      region: {
        startLine: number;
        endLine: number;
        snippet: {
          text: string;
        };
      };
    };
  }>;
}


2. Create CCI Mappings File
src/mappings/cci-mappings.ts

export const cciMappings: Record<string, string[]> = {
  // Encryption at Rest
  "CKV_AWS_136": ["CCI-001199", "CCI-002475"], // SC-28, SC-28(1) - ECR KMS
  "CKV_AWS_18": ["CCI-000068", "CCI-001453"],  // SC-28 - S3 encryption
  "CKV_AWS_19": ["CCI-001199", "CCI-002475"],  // SC-28(1) - S3 SSE-KMS
  
  // Access Control
  "CKV_AWS_20": ["CCI-000213", "CCI-001813"],  // AC-3, AC-6 - S3 bucket ACLs
  "CKV_AWS_21": ["CCI-000186"],                // AC-3(7) - S3 versioning
  
  // Add more as you map them...
};

// CCI to NIST control mapping
export const cciToNist: Record<string, string> = {
  "CCI-001199": "SC-28",
  "CCI-002475": "SC-28(1)",
  "CCI-000068": "SC-28",
  "CCI-001453": "SC-13",
  "CCI-000213": "AC-3",
  "CCI-001813": "AC-6(9)",
  "CCI-000186": "AC-3(7)",
  // Add more mappings...
};

export function deriveNistFromCCI(ccis: string[] = []): string[] {
  return [...new Set(ccis.map(cci => cciToNist[cci]).filter(Boolean))];
}

3. Create Mapper Function
src/mappers/checkov-to-heimdall.ts

import { Control, CheckovResult } from '../types/heimdall';
import { cciMappings, deriveNistFromCCI } from '../mappings/cci-mappings';

export function mapCheckovToHeimdall(checkovResults: CheckovResult[]): Control[] {
  return checkovResults.map(result => {
    const ccis = cciMappings[result.ruleId] || [];
    
    return {
      id: result.ruleId,
      title: result.message.text,
      desc: result.message.text,
      impact: calculateImpact(result.level),
      refs: [
        {
          url: `https://docs.bridgecrew.io/docs/${result.ruleId.toLowerCase()}`
        }
      ],
      tags: {
        cci: ccis,
        nist: deriveNistFromCCI(ccis),
        severity: result.level,
        checkov_id: result.ruleId,
        resource_type: extractResourceType(result)
      },
      results: [
        {
          status: result.level === "error" ? "failed" : "skipped",
          code_desc: extractCodeDesc(result),
          message: result.message.text,
          start_time: new Date().toISOString()
        }
      ]
    };
  });
}

function calculateImpact(level: string): number {
  const impactMap: Record<string, number> = {
    'error': 0.7,
    'warning': 0.5,
    'note': 0.3
  };
  return impactMap[level] || 0.5;
}

function extractResourceType(result: CheckovResult): string {
  const snippet = result.locations[0]?.physicalLocation?.region?.snippet?.text || '';
  const match = snippet.match(/resource\s+"([^"]+)"/);
  return match ? match[1] : 'unknown';
}

function extractCodeDesc(result: CheckovResult): string {
  return result.locations[0]?.physicalLocation?.region?.snippet?.text || 
         `${result.ruleId} check`;
}

4. Usage Example
src/index.ts or wherever you're processing results:

import { mapCheckovToHeimdall } from './mappers/checkov-to-heimdall';
import * as fs from 'fs';

// Read your Checkov SARIF output
const checkovOutput = JSON.parse(fs.readFileSync('tf_checkov.json', 'utf8'));

// Extract results from SARIF format
const checkovResults = checkovOutput.runs[0].results;

// Map to Heimdall format
const heimdallControls = mapCheckovToHeimdall(checkovResults);

// Output as Heimdall JSON
const heimdallOutput = {
  platform: {
    name: "Checkov",
    release: "2.0.0"
  },
  version: "1.0",
  statistics: {},
  profiles: [
    {
      name: "AWS Security Checks",
      version: "1.0.0",
      title: "Checkov AWS Security Baseline",
      summary: "Security checks for AWS infrastructure",
      supports: [],
      attributes: [],
      groups: [],
      controls: heimdallControls
    }
  ]
};

fs.writeFileSync('heimdall-output.json', JSON.stringify(heimdallOutput, null, 2));


5. Quick Test

// test.ts
import { mapCheckovToHeimdall } from './mappers/checkov-to-heimdall';

const sampleResult = {
  ruleId: "CKV_AWS_136",
  ruleIndex: 4,
  level: "error",
  message: {
    text: "Ensure that ECR repositories are encrypted using KMS"
  },
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri: "tf_checkov.json" },
        region: {
          startLine: 13,
          endLine: 17,
          snippet: {
            text: 'resource "aws_ecr_repository" "heimdall"'
          }
        }
      }
    }
  ]
};

const result = mapCheckovToHeimdall([sampleResult]);
console.log(JSON.stringify(result, null, 2));