import {ExecJSON} from 'inspecjs';
import * as _ from 'lodash';
import {version as HeimdallToolsVersion} from '../package.json';
import {BaseConverter, ILookupPath, MappedTransform} from './base-converter';
import {data as CheckovCciMappingData} from './mappings/CheckovCciMappingData';
import {data as CciNistMappingData} from './mappings/CciNistMappingData';
import {
  DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS,
  getCCIsForNISTTags
} from './utils/global';

const IMPACT_MAPPING: Map<string, number> = new Map([
  ['critical', 0.9],
  ['high', 0.7],
  ['medium', 0.5],
  ['low', 0.3],
  ['info', 0.0]
]);

function impactMapping(severity: unknown): number {
  if (typeof severity === 'string') {
    return IMPACT_MAPPING.get(severity.toLowerCase()) ?? 0.5;
  }
  return 0.5;
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

function deriveNistFromCCI(ccis: string[]): string[] {
  const nistTags: string[] = [];
  for (const cci of ccis) {
    const nistControl = (CciNistMappingData as Record<string, string>)[cci];
    if (nistControl) {
      const baseControl = nistControl.match(/[A-Z]{2}-\d+/);
      if (baseControl) {
        nistTags.push(baseControl[0]);
      }
    }
  }
  const uniqueTags = [...new Set(nistTags)];
  return uniqueTags.length > 0
    ? uniqueTags
    : DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
}

interface CheckovCheck {
  check_id: string;
  check_name: string;
  check_result: {result: string};
  file_path?: string;
  file_line_range?: number[];
  resource?: string;
  resource_address?: string;
  severity?: string;
  guideline?: string;
  bc_check_id?: string;
  code_block?: Array<[number, string]>;
}

function preprocessCheckovJson(
  data: Record<string, unknown>
): Record<string, unknown> {
  const results = _.get(data, 'results') as Record<string, unknown>;
  const passedChecks = (_.get(results, 'passed_checks') || []) as CheckovCheck[];
  const failedChecks = (_.get(results, 'failed_checks') || []) as CheckovCheck[];
  const skippedChecks = (_.get(results, 'skipped_checks') || []) as CheckovCheck[];

  const allChecks = [...passedChecks, ...failedChecks, ...skippedChecks];

  return {
    ...data,
    all_checks: allChecks
  };
}

export class CheckovMapper extends BaseConverter {
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
        version: {path: '$.summary.checkov_version'},
        title: {
          path: '$.check_type',
          transformer: (checkType: unknown): string => {
            if (typeof checkType === 'string') {
              return `Checkov ${checkType} Security Scan`;
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
            path: 'all_checks',
            key: 'id',
            tags: {
              cci: {
                path: 'check_id',
                transformer: (checkId: unknown): string[] => {
                  if (typeof checkId === 'string') {
                    return CheckovCciMappingData[checkId] || [];
                  }
                  return [];
                }
              },
              nist: {
                path: 'check_id',
                transformer: (checkId: unknown): string[] => {
                  if (typeof checkId === 'string') {
                    const ccis = CheckovCciMappingData[checkId] || [];
                    return ccis.length > 0
                      ? deriveNistFromCCI(ccis)
                      : DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
                  }
                  return DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
                }
              },
              severity: {path: 'severity'},
              checkov_id: {path: 'check_id'},
              resource: {path: 'resource'}
            },
            refs: [
              {
                transformer: (check: unknown) => {
                  const guideline = _.get(check, 'guideline') as
                    | string
                    | null
                    | undefined;
                  if (
                    typeof guideline === 'string' &&
                    guideline.length > 0
                  ) {
                    return {url: guideline};
                  }
                  const checkId = _.get(check, 'check_id') as
                    | string
                    | undefined;
                  if (typeof checkId === 'string') {
                    return {
                      url: `https://docs.bridgecrew.io/docs/${checkId.toLowerCase()}`
                    };
                  }
                  return {};
                }
              }
            ],
            source_location: {
              transformer: (check: unknown) => {
                const filePath = _.get(check, 'file_path') as
                  | string
                  | undefined;
                const lineRange = _.get(check, 'file_line_range') as
                  | number[]
                  | undefined;
                return _.omitBy(
                  {
                    ref: filePath,
                    line: lineRange?.[0]
                  },
                  (value) =>
                    value === undefined || value === null
                );
              }
            },
            title: {path: 'check_name'},
            id: {path: 'check_id'},
            desc: {path: 'check_name'},
            impact: {path: 'severity', transformer: impactMapping},
            code: {
              transformer: (check: Record<string, unknown>): string => {
                const codeBlock = _.get(check, 'code_block') as
                  | Array<[number, string]>
                  | undefined;
                if (Array.isArray(codeBlock)) {
                  return codeBlock
                    .map(([line, code]) => `${line}: ${code}`)
                    .join('');
                }
                return JSON.stringify(check, null, 2);
              }
            },
            results: [
              {
                status: {
                  path: 'check_result.result',
                  transformer: (
                    result: unknown
                  ): ExecJSON.ControlResultStatus => {
                    if (result === 'PASSED') {
                      return ExecJSON.ControlResultStatus.Passed;
                    } else if (result === 'FAILED') {
                      return ExecJSON.ControlResultStatus.Failed;
                    } else {
                      return ExecJSON.ControlResultStatus.Skipped;
                    }
                  }
                },
                code_desc: {
                  transformer: (check: Record<string, unknown>): string =>
                    formatCodeDesc(check)
                },
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
          }
        ],
        sha256: ''
      }
    ],
    passthrough: {
      transformer: (data: Record<string, unknown>): Record<string, unknown> => {
        return {
          auxiliary_data: [
            {
              name: 'Checkov',
              data: {
                check_type: _.get(data, 'check_type'),
                summary: _.get(data, 'summary')
              }
            }
          ],
          ...(this.withRaw && {raw: data})
        };
      }
    }
  };

  constructor(checkovJson: string, withRaw = false) {
    super(preprocessCheckovJson(JSON.parse(checkovJson)));
    this.withRaw = withRaw;
  }
}
