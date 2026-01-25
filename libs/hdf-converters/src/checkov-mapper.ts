import { ExecJSON } from "inspecjs";
import _ from "lodash";
import { version as HeimdallToolsVersion } from "../package.json";
import {
  BaseConverter,
  ILookupPath,
  impactMapping,
  MappedTransform,
} from "./base-converter";

export interface CheckovCheck {
  check_id: string;
  bc_check_id?: string;
  check_name: string;
  check_result: { result: "PASSED" | "FAILED" };
  code_block: [number, string][];
  file_path: string;
  file_abs_path: string;
  repo_file_path: string;
  file_line_range: [number, number];
  resource: string;
  resource_address: string;
  evaluations?: any;
  check_class: string;
  fixed_definition?: any;
  entity_tags?: Record<string, any>;
  caller_file_path?: string | null;
  caller_file_line_range?: [number, number] | null;
  severity?: string | null;
  bc_category?: string | null;
  benchmarks?: any;
  description?: string | null;
  short_description?: string | null;
  vulnerability_details?: any;
  connected_node?: any;
  guideline?: string;
  details: string[];
  check_len?: number | null;
  definition_context_file_path: string;
}

export interface CheckovSummary {
  passed: number;
  failed: number;
  skipped: number;
  parsing_errors: number;
  resource_count: number;
  checkov_version: string;
}

export interface CheckovData {
  check_type: string;
  results: {
    passed_checks: CheckovCheck[];
    failed_checks: CheckovCheck[];
    skipped_checks: CheckovCheck[];
    parsing_errors: string[];
  };
  summary: CheckovSummary;
  url: string;
}

export class CheckovMapper extends BaseConverter {
  withRaw: boolean;

  mappings: MappedTransform<
    ExecJSON.Execution & { passthrough: unknown },
    ILookupPath
  > = {
      platform: {
        name: "Heimdall Tools",
        release: HeimdallToolsVersion,
        target_id: null, //Insert data
      },
      version: HeimdallToolsVersion,
      statistics: {
        duration: null, //Insert data
      },
      profiles: [
        {
          name: {
            path: "check_type",
            transformer: (type: string) => `Checkov ${type} Scan`
          },
          title: {
            path: "check_type",
            transformer: (type: string) => `Checkov Scan Results - ${type}`
          },
          version: {
            path: "summary.checkov_version",
            transformer: (version: string) => `Checkov - (v${version})`,
          },
          maintainer: null, //Insert data
          summary: {
            transformer: (data: CheckovData) => {
              const { passed, failed, skipped, parsing_errors } = data.summary;
              const totalChecks = passed + failed + skipped + parsing_errors;

              const parts = [
                `Checkov ${data.check_type || "scan"} results`,
                `Total Checks: ${totalChecks}`,
                `Passed: ${passed}`,
                `Failed: ${failed}`,
                `Skipped: ${skipped}`,
              ];

              if (parsing_errors > 0) {
                parts.push(`Parsing Errors: ${parsing_errors}`);
              }

              return parts.join(" • ");
            }
          },
          license: null, //Insert data
          copyright: null, //Insert data
          copyright_email: null, //Insert data
          supports: [], //Insert data
          attributes: [], //Insert data
          depends: [], //Insert data
          groups: [], //Insert data
          status: "loaded", //Insert data
          controls: [
            {
              key: "id",
              tags: {}, //Insert data
              descriptions: [], //Insert data
              refs: [], //Insert data
              source_location: {}, //Insert data
              title: null, //Insert data
              id: "", //Insert data
              desc: null, //Insert data
              impact: 0, //Insert data
              code: null, //Insert data
              results: [
                {
                  status: ExecJSON.ControlResultStatus.Failed, //Insert data
                  code_desc: "", //Insert data
                  message: null, //Insert data
                  run_time: null, //Insert data
                  start_time: "", //Insert data
                },
              ],
            },
          ],
          sha256: "",
        },
      ],
      passthrough: {
        transformer: (data: Record<string, any>): Record<string, unknown> => {
          return {
            auxiliary_data: [{ name: "", data: _.omit([]) }], //Insert service name and mapped fields to be removed
            ...(this.withRaw && { raw: data }),
          };
        },
      },
    };
    
  constructor(exportJson: string, withRaw = false) {
    super(JSON.parse(exportJson), true);
    this.withRaw = withRaw;
  }
}