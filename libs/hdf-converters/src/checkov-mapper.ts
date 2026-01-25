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
  ['error', 0.7],
  ['warning', 0.5],
  ['note', 0.3]
]);

const MESSAGE_TEXT = 'message.text';

function impactMapping(severity: unknown): number {
  if (typeof severity === 'string' || typeof severity === 'number') {
    return IMPACT_MAPPING.get(severity.toString().toLowerCase()) || 0.5;
  } else {
    return 0.5;
  }
}

function formatCodeDesc(input: unknown): string {
  const output = [];
  const uri = _.get(input, 'artifactLocation.uri');
  const startLine = _.get(input, 'region.startLine');
  const endLine = _.get(input, 'region.endLine');
  const snippet = _.get(input, 'region.snippet.text');

  if (uri) {
    output.push(`File: ${uri}`);
  }
  if (startLine) {
    output.push(`Line: ${startLine}`);
    if (endLine && endLine !== startLine) {
      output.push(`- ${endLine}`);
    }
  }
  if (snippet) {
    output.push(`\nCode: ${snippet}`);
  }

  return output.length > 0 ? output.join(' ') : 'Checkov security check';
}

function extractResourceType(result: unknown): string {
  const snippet =
    _.get(result, 'locations[0].physicalLocation.region.snippet.text') || '';
  if (typeof snippet === 'string') {
    const match = snippet.match(/resource\s+"([^"]+)"/);
    return match ? match[1] : 'unknown';
  }
  return 'unknown';
}

function deriveNistFromCCI(ccis: string[]): string[] {
  const nistTags: string[] = [];
  for (const cci of ccis) {
    // Find the NIST tag that corresponds to this CCI
    for (const [nistTag, cciList] of Object.entries(CciNistMappingData)) {
      if (Array.isArray(cciList) && cciList.includes(cci)) {
        nistTags.push(nistTag);
      }
    }
  }
  // Return unique NIST tags, or default if none found
  const uniqueTags = [...new Set(nistTags)];
  return uniqueTags.length > 0
    ? uniqueTags
    : DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
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
        path: 'runs',
        name: 'Checkov',
        version: {path: '$.version'},
        title: 'Checkov Infrastructure Security Checks',
        supports: [],
        attributes: [],
        groups: [],
        status: 'loaded',
        controls: [
          {
            path: 'results',
            key: 'id',
            tags: {
              cci: {
                path: 'ruleId',
                transformer: (ruleId: unknown): string[] => {
                  if (typeof ruleId === 'string') {
                    return CheckovCciMappingData[ruleId] || [];
                  }
                  return [];
                }
              },
              nist: {
                path: 'ruleId',
                transformer: (ruleId: unknown): string[] => {
                  if (typeof ruleId === 'string') {
                    const ccis = CheckovCciMappingData[ruleId] || [];
                    return ccis.length > 0
                      ? deriveNistFromCCI(ccis)
                      : DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
                  }
                  return DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
                }
              },
              severity: {path: 'level'},
              checkov_id: {path: 'ruleId'},
              resource_type: {
                transformer: (control: unknown) => extractResourceType(control)
              }
            },
            refs: [
              {
                transformer: (control: unknown) => {
                  const ruleId = _.get(control, 'ruleId');
                  if (typeof ruleId === 'string') {
                    return {
                      url: `https://docs.bridgecrew.io/docs/${ruleId.toLowerCase()}`
                    };
                  }
                  return {};
                }
              }
            ],
            source_location: {
              transformer: (control: unknown) => {
                return _.omitBy(
                  {
                    ref: _.get(
                      control,
                      'locations[0].physicalLocation.artifactLocation.uri'
                    ),
                    line: _.get(
                      control,
                      'locations[0].physicalLocation.region.startLine'
                    )
                  },
                  (value) => value === '' || value === undefined
                );
              }
            },
            title: {
              path: MESSAGE_TEXT,
              transformer: (text: unknown): string => {
                if (typeof text === 'string') {
                  // Extract just the title part if it contains a colon
                  return text.split(': ')[0] || text;
                } else {
                  return '';
                }
              }
            },
            id: {path: 'ruleId'},
            desc: {
              path: MESSAGE_TEXT,
              transformer: (text: unknown): string => {
                if (typeof text === 'string') {
                  // If there's a colon, use the part after it as description
                  // Otherwise use the whole text
                  const parts = text.split(': ');
                  return parts.length > 1 ? parts.slice(1).join(': ') : text;
                } else {
                  return '';
                }
              }
            },
            impact: {path: 'level', transformer: impactMapping},
            code: {
              transformer: (vulnerability: Record<string, unknown>): string =>
                JSON.stringify(vulnerability, null, 2)
            },
            results: [
              {
                status: {
                  path: 'level',
                  transformer: (level: unknown): ExecJSON.ControlResultStatus => {
                    if (level === 'error') {
                      return ExecJSON.ControlResultStatus.Failed;
                    } else if (level === 'warning') {
                      return ExecJSON.ControlResultStatus.Failed;
                    } else {
                      return ExecJSON.ControlResultStatus.Skipped;
                    }
                  }
                },
                code_desc: {
                  path: 'locations[0].physicalLocation',
                  transformer: formatCodeDesc
                },
                message: {path: MESSAGE_TEXT},
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
        let runsData = _.get(data, 'runs');
        if (Array.isArray(runsData)) {
          runsData = runsData.map((run: Record<string, unknown>) =>
            _.omit(run, ['results'])
          );
        }
        return {
          auxiliary_data: [
            {
              name: 'Checkov',
              data: {
                $schema: _.get(data, '$schema'),
                runs: runsData
              }
            }
          ],
          ...(this.withRaw && {raw: data})
        };
      }
    }
  };

  constructor(checkovJson: string, withRaw = false) {
    super(JSON.parse(checkovJson));
    this.withRaw = withRaw;
  }
}
