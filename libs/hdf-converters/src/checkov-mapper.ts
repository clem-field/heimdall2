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
// =========================================================================

type CheckovCheckResult = {
  result: 'PASSED' | 'FAILED' | 'SKIPPED' | 'UNKNOWN';
  evaluated_keys?: string[];
  [property: string]: unknown;
};

type CheckovCheck = {
  check_id: string;
  check_name: string;
  check_result: CheckovCheckResult;
  file_path?: string;
  file_line_range?: number[];
  resource?: string;
  resource_address?: string;
  severity?: string | null;
  guideline?: string;
  bc_check_id?: string;
  code_block?: Array<[number, string]>;
  [property: string]: unknown;
};

type CheckovSummary = {
  passed?: number;
  failed?: number;
  skipped?: number;
  parsing_errors?: number;
  resource_count?: number;
  checkov_version?: string;
  [property: string]: unknown;
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
  url?: string;
  [property: string]: unknown;
};

// =========================================================================
// Severity mapping — aligned with Checkov SARIF reporter
// https://github.com/bridgecrewio/checkov/blob/main/checkov/common/output/sarif.py#L17-L23
// Checkov uses 'none' (not 'info'). Scaled to [0,1].
// =========================================================================

const IMPACT_MAPPING: Map<string, number> = new Map([
  ['critical', 0.9],
  ['high', 0.7],
  ['medium', 0.5],
  ['low', 0.3],
  ['none', 0]
]);

function impactMapping(severity: unknown): number {
  if (_.isString(severity)) {
    return IMPACT_MAPPING.get(severity.toLowerCase()) ?? 0.5;
  }
  // Native JSON often has null severity — default to medium
  return 0.5;
}

function statusMapper(result: unknown): ExecJSON.ControlResultStatus {
  if (result === 'PASSED') {
    return ExecJSON.ControlResultStatus.Passed;
  } else if (result === 'FAILED') {
    return ExecJSON.ControlResultStatus.Failed;
  }
  return ExecJSON.ControlResultStatus.Skipped;
}

function formatCodeDesc(check: Record<string, unknown>): string {
  const filePath = _.get(check, 'file_path') as string | undefined;
  const lineRange = _.get(check, 'file_line_range') as number[] | undefined;
  const resource = _.get(check, 'resource') as string | undefined;

  const parts: string[] = [];
  if (resource) {
    parts.push(`Resource: ${resource}`);
  }
  if (filePath) {
    parts.push(`File: ${filePath}`);
  }
  if (lineRange && Array.isArray(lineRange) && lineRange.length >= 2) {
    parts.push(`Line: ${lineRange[0]}-${lineRange[1]}`);
  }

  return parts.length > 0 ? parts.join(' | ') : 'Checkov security check';
}

function formatCode(check: Record<string, unknown>): string {
  const codeBlock = _.get(check, 'code_block') as
    | Array<[number, string]>
    | undefined;
  if (Array.isArray(codeBlock)) {
    return codeBlock.map(([line, code]) => `${line}: ${code}`).join('');
  }
  const resourceAddress = _.get(check, 'resource_address') as
    | string
    | undefined;
  if (resourceAddress) {
    return `Resource: ${resourceAddress}`;
  }
  return JSON.stringify(check, null, 2);
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
        transformer: (checkId: unknown): string[] => {
          if (_.isString(checkId)) {
            const mapping = CheckovCciMappingData[checkId];
            return mapping ? mapping.cci : [];
          }
          return [];
        }
      },
      nist: {
        path: 'check_id',
        transformer: (checkId: unknown): string[] => {
          if (_.isString(checkId)) {
            const mapping = CheckovCciMappingData[checkId];
            if (mapping && mapping.nist.length > 0) {
              return mapping.nist;
            }
          }
          return DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
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
        transformer: (check: unknown) => {
          const guideline = _.get(check, 'guideline') as
            | string
            | null
            | undefined;
          if (_.isString(guideline) && guideline.length > 0) {
            return {url: guideline};
          }
          return {};
        }
      }
    ],
    source_location: {
      transformer: (check: unknown) => {
        const filePath = _.get(check, 'file_path') as string | undefined;
        const lineRange = _.get(check, 'file_line_range') as
          | number[]
          | undefined;
        return _.omitBy(
          {
            ref: filePath,
            line: lineRange?.[0]
          },
          (value) => value === undefined || value === null
        );
      }
    },
    title: {path: 'check_name'},
    id: {path: 'check_id'},
    desc: {
      transformer: (check: Record<string, unknown>): string => {
        const name = _.get(check, 'check_name') as string | undefined;
        const guideline = _.get(check, 'guideline') as string | undefined;
        if (guideline) {
          return `${name} — ${guideline}`;
        }
        return name || '';
      }
    },
    impact: {path: 'severity', transformer: impactMapping},
    code: {transformer: formatCode},
    results: [
      {
        status: {path: 'check_result.result', transformer: statusMapper},
        code_desc: {transformer: formatCodeDesc},
        message: {
          transformer: (check: Record<string, unknown>): string => {
            const result = _.get(check, 'check_result.result');
            const name = _.get(check, 'check_name');
            return `${result}: ${name}`;
          }
        },
        start_time: {
          transformer: (): string => new Date().toISOString()
        }
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
      release: HeimdallToolsVersion,
      target_id: 'Checkov (Bridgecrew)'
    },
    version: HeimdallToolsVersion,
    statistics: {},
    profiles: [
      {
        name: 'Checkov',
        version: {path: 'summary.checkov_version'},
        title: {
          path: 'check_type',
          transformer: (checkType: unknown): string => {
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
        data: Record<string, unknown>
      ): Record<string, unknown> => {
        return {
          auxiliary_data: [
            {
              name: 'Checkov',
              data: {
                check_type: _.get(data, 'check_type'),
                summary: _.get(data, 'summary'),
                url: _.get(data, 'url'),
                parsing_errors: _.get(data, 'results.parsing_errors')
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
