import * as _ from 'lodash';
import {ExecJSON} from 'inspecjs';
import {version as HeimdallToolsVersion} from '../package.json';
import {BaseConverter, ILookupPath, MappedTransform} from './base-converter';
import {data as CheckovCciMappingData} from './mappings/CheckovCciMappingData';
import {
  conditionallyProvideAttribute,
  DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS
} from './utils/global';

// =========================================================================
// Types — derived from Checkov native JSON output
// https://github.com/bridgecrewio/checkov
// Empirical analysis: 14 result files, 2846 checks (see docs/dev/checkov-field-analysis.md)
// =========================================================================

// Control result status
type CheckovCheckResult = {
  result: 'PASSED' | 'FAILED' | 'SKIPPED' | 'UNKNOWN';
  evaluated_keys: string[];
  entity: Record<string, unknown>;
  [property: string]: unknown;
};

// Individual check (passed, failed, or skipped)
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
  // Nullable (present but can be null)
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
  // Catch-all for unmapped fields
  [property: string]: unknown;
};

// Summary — all fields always present, never null
type CheckovSummary = {
  passed: number;
  failed: number;
  skipped: number;
  parsing_errors: number;
  resource_count: number;
  checkov_version: string;
};

// Top-level report
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

// =========================================================================
// Severity mapping — aligned with Checkov SARIF reporter
// https://github.com/bridgecrewio/checkov/blob/main/checkov/common/output/sarif.py#L17-L23
// Checkov uses 'none' (not 'info'). Scaled to [0,1].
// =========================================================================

const IMPACT_MAPPING: Map<string, number> = new Map([
  ['critical', 1.0], // NOSONAR - explicit decimal matches Checkov SARIF scale (10.0/10) and MITRE impact patterns
  ['high', 0.89],
  ['medium', 0.69],
  ['low', 0.39],
  ['none', 0.0] // NOSONAR - explicit decimal matches Checkov SARIF scale (0.0/10) and MITRE impact patterns
]);

function impactMapping(severity: unknown): number {
  if (_.isString(severity)) {
    return IMPACT_MAPPING.get(severity.toLowerCase()) ?? IMPACT_MAPPING.get('none')!; // NOSONAR - 'none' is defined in map; Checkov default severity is null → mapped to none
  }
  // Checkov native JSON default severity is null → mapped to none (0)
  return IMPACT_MAPPING.get('none')!; // NOSONAR - 'none' is defined in map
}

function statusMapper(result: unknown): ExecJSON.ControlResultStatus {
  if (result === 'PASSED') {
    return ExecJSON.ControlResultStatus.Passed;
  } else if (result === 'FAILED') {
    return ExecJSON.ControlResultStatus.Failed;
  }
  return ExecJSON.ControlResultStatus.Skipped;
}

// Results tab — finding info: resource, file, line range, code snippet
function formatCodeDesc(check: CheckovCheck): string {
  const parts: string[] = [];
  if (check.resource) {
    parts.push(`Resource: ${check.resource}`);
  }
  if (check.file_path) {
    const location = check.file_line_range && check.file_line_range.length >= 2
      ? `${check.file_path}:${check.file_line_range[0]}-${check.file_line_range[1]}`
      : check.file_path;
    parts.push(`File: ${location}`);
  }
  if (Array.isArray(check.code_block) && check.code_block.length > 0) {
    const snippet = check.code_block.map(([line, code]) => `${line}: ${code}`).join('');
    parts.push(`<pre>\n${snippet}</pre>`);
  }

  return parts.length > 0 ? parts.join('\n') : 'Checkov security check';
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
          const mapping = CheckovCciMappingData[checkId];
          return mapping ? mapping.cci : [];
        }
      },
      nist: {
        path: 'check_id',
        transformer: (checkId: CheckovCheck['check_id']): string[] => {
          const mapping = CheckovCciMappingData[checkId];
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
    id: {path: 'check_id'},
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
              parts.push(`Fix: ${_.isString(check.fixed_definition) ? check.fixed_definition : JSON.stringify(check.fixed_definition)}`); // NOSONAR - ternary handles string vs object; JSON.stringify prevents [object Object]
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
              return `Checkov ${checkType} Security Scan`; // NOSONAR - checkType verified as string above
            }
            return 'Checkov Infrastructure Security Checks';
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
