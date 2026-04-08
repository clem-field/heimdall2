import * as _ from 'lodash';
import {ExecJSON} from 'inspecjs';
import {version as HeimdallToolsVersion} from '../package.json';
import {BaseConverter, ILookupPath, MappedTransform} from './base-converter';
import {data as MappingData} from './mappings/CheckovToCciAndNistMappingData';
import {
  conditionallyProvideAttribute,
  DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS
} from './utils/global';

type CheckovCheckResult = {
  result: 'PASSED' | 'FAILED' | 'SKIPPED' | 'UNKNOWN';
  evaluated_keys: string[];
  [property: string]: unknown;
};

type CheckovCheck = {
  // Always present, never null
  check_id: string;
  check_name: string;
  check_result: CheckovCheckResult;
  file_path: string;
  file_line_range: number[];
  resource: string;
  code_block: Array<[number, string]>;
  check_class: string;
  file_abs_path: string;
  repo_file_path: string;
  definition_context_file_path: string;
  details: unknown[];
  // Always present but can be null
  severity: string | null;
  guideline: string | null;
  bc_check_id: string | null;
  resource_address: string | null;
  entity_tags: Record<string, string> | null;
  caller_file_path: string | null;
  caller_file_line_range: number[] | null;
  description: string | null;
  benchmarks: Record<string, unknown> | null;
  bc_category: string | null;
  short_description: string | null;
  connected_node: unknown;
  fixed_definition: unknown;
  evaluations: unknown;
  check_len: unknown;
  vulnerability_details: unknown;
  // Catch-all for remaining optional fields
  [property: string]: unknown;
};

type CheckovSummary = {
  passed: number;
  failed: number;
  skipped: number;
  parsing_errors: number;
  resource_count: number;
  checkov_version: string;
};

type CheckovReport = {
  check_type: string;
  results: {
    passed_checks: CheckovCheck[];
    failed_checks: CheckovCheck[];
    skipped_checks: CheckovCheck[];
    parsing_errors: unknown[];
  };
  summary: CheckovSummary;
  url: string;
};

// https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/severities.py
// severity scale (score → HDF impact):
//   CRITICAL: 5 → 1.0
//   HIGH/IMPORTANT: 4 → 0.8
//   MEDIUM/MODERATE: 3 → 0.6
//   LOW: 2 → 0.4
//   INFO: 1 → 0.2
//   NONE: -999 → 0.0
//   OFF: 999 -> MEDIUM
//   null (no API Key) → MEDIUM
// Severity is only populated when passing in an API key via --bc-api-key, otherwise it is null
// Default to medium - treat null/unknown risk as moderate until a formal risk assessment is performed.
const MEDIUM_SEVERITY = 0.6;
const IMPACT_MAPPING: Map<string, number> = new Map([
  ['critical', 1.0],
  ['high', 0.8],
  ['important', 0.8],
  ['medium', MEDIUM_SEVERITY],
  ['moderate', 0.6],
  ['low', 0.4],
  ['info', 0.2],
  ['none', 0]
]);

function impactMapping(severity: CheckovCheck['severity']): number {
  if (_.isString(severity)) {
    return IMPACT_MAPPING.get(severity.toLowerCase()) ?? MEDIUM_SEVERITY;
  }
  // Checkov native JSON default severity is null (no API key) → default to medium
  return MEDIUM_SEVERITY;
}

function statusMapper(result: CheckovCheckResult['result']): ExecJSON.ControlResultStatus {
  if (result === 'PASSED') {
    return ExecJSON.ControlResultStatus.Passed;
  } else if (result === 'FAILED') {
    return ExecJSON.ControlResultStatus.Failed;
  }
  return ExecJSON.ControlResultStatus.Skipped;
}

function formatCodeDesc(check: CheckovCheck): string {
  const resource = `Resource: ${check.resource}`;
  const fileLocation = `File: ${check.file_path}:${check.file_line_range[0]}-${check.file_line_range[1]}`;
  const codeBlock = `<pre>${check.code_block.map(([line, code]) => `${line}: ${code}`).join('').trim()}</pre>`
  return `${resource}\n${fileLocation}\n${check.code_block.length === 0 ? '' : codeBlock}`;
}

// Code tab — dumping ground for unmapped check attributes
function formatCode(check: CheckovCheck): string {
  const unmapped: Record<string, unknown> = {};

  const mappedFields = new Set([
    'check_id', 'check_name', 'check_result', 'file_path',
    'file_line_range', 'resource', 'code_block', 'severity',
    'guideline', 'bc_check_id', 'resource_address'
  ]);

  for (const [key, value] of Object.entries(check)) {
    if (!mappedFields.has(key) && value !== null && value !== undefined) {
      unmapped[key] = value;
    }
  }

  return Object.keys(unmapped).length > 0
    ? JSON.stringify(unmapped, null, 2)
    : '';
}

// =========================================================================
// Control mapping — shared across passed/failed/skipped controls arrays
// Follows veracode mapper pattern: function returns MappedTransform
// =========================================================================

function controlMapping(): MappedTransform<
  ExecJSON.Control & ILookupPath,
  ILookupPath
> {
  return {
    key: 'id',
    tags: {
      cci: {
        path: 'check_id',
        transformer: (checkId: CheckovCheck['check_id']): string[] => {
          const mapping = MappingData[checkId];
          return mapping ? mapping.cci : [];
        }
      },
      nist: {
        path: 'check_id',
        transformer: (checkId: CheckovCheck['check_id']): string[] => {
          const mapping = MappingData[checkId];
          return mapping && mapping.nist.length > 0
            ? mapping.nist
            : DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
        }
      },
      ...conditionallyProvideAttribute('severity', {path: 'severity'}, true),
      checkov_id: {path: 'check_id'},
      ...conditionallyProvideAttribute('resource', {path: 'resource'}, true),
      ...conditionallyProvideAttribute(
        'resource_address',
        {path: 'resource_address'},
        true
      )
    },
    refs: [
      {
        path:"guideline",
        transformer: (guideline: CheckovCheck["guideline"]) => {
          if (_.isString(guideline) && guideline.length > 0) {
            return {url: guideline};
          }
          return {};
        }
      }
    ],
    source_location: {
      transformer: (check: CheckovCheck) => ({
        ...conditionallyProvideAttribute('ref', check.file_path, !!check.file_path),
        ...conditionallyProvideAttribute('line', check.file_line_range?.[0], !!check.file_line_range)
      })
    },
    title: {path: 'check_name'},
    id: {transformer: (check: CheckovCheck): string => `${check.check_id}\n${check.resource}`},
    impact: {path: 'severity', transformer: impactMapping},
    code: {transformer: formatCode},
    results: [
      {
        status: {path: 'check_result.result', transformer: statusMapper},
        code_desc: {transformer: formatCodeDesc},
        message: {
          transformer: (check: CheckovCheck): string => {
            const parts: string[] = [
              `${check.check_result.result}: ${check.check_name}`
            ];
            const evaluatedKeys = check.check_result.evaluated_keys;
            if (evaluatedKeys && evaluatedKeys.length > 0) {
              parts.push(`Evaluated: ${evaluatedKeys.join(', ')}`);
            }
            if (_.isString(check.guideline) && check.guideline.length > 0) {
              parts.push(`Guideline: ${check.guideline}`);
            }
            if (check.fixed_definition) {
              const fix: string = _.isString(check.fixed_definition) ? check.fixed_definition : JSON.stringify(check.fixed_definition);
              parts.push(`Fix: ${fix}`);
            }
            return parts.join('\n');
          }
        },
        start_time: ""
      }
    ]
  };
}

// =========================================================================
// CheckovMapper — extends BaseConverter<CheckovReport>
// =========================================================================

export class CheckovMapper extends BaseConverter<CheckovReport> {
  withRaw: boolean;

  mappings: MappedTransform<
    ExecJSON.Execution & {passthrough: unknown},
    ILookupPath
  > = {
    platform: {
      name: 'Heimdall Tools',
      release: HeimdallToolsVersion
    },
    version: HeimdallToolsVersion,
    statistics: {},
    profiles: [
      {
        name: 'Checkov',
        version: {path: 'summary.checkov_version'},
        title: {
          path: 'check_type',
          transformer: (checkType: CheckovReport["check_type"]): string => {
            if (_.isString(checkType)) {
              return `Bridgecrew (by Prisma Cloud) Checkov ${checkType} Security Scan`;
            }
            return 'Bridgecrew (by Prisma Cloud) Checkov Infrastructure Security Checks';
          }
        },
        supports: [],
        attributes: [],
        groups: [],
        status: 'loaded',
        controls: [
          {
            path: 'results.passed_checks',
            ...controlMapping()
          },
          {
            path: 'results.failed_checks',
            ...controlMapping()
          },
          {
            path: 'results.skipped_checks',
            ...controlMapping()
          }
        ],
        sha256: ''
      }
    ],
    passthrough: {
      transformer: (
        data: CheckovReport
      ): Record<string, unknown> => {
        return {
          auxiliary_data: [
            {
              name: 'Checkov',
              data: {
                summary: data.summary,
                url: data.url,
                results:{
                  parsing_errors:data.results.parsing_errors
                }
              }
            }
          ],
          ...conditionallyProvideAttribute('raw', data, this.withRaw)
        };
      }
    }
  };

  constructor(checkovJson: string, withRaw = false) {
    super(JSON.parse(checkovJson) as CheckovReport);
    this.withRaw = withRaw;
  }
}
