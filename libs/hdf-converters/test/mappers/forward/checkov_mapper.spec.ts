<<<<<<< HEAD
import fs from 'fs';
import {SkeletonMapper} from '../../../src/skeleton-mapper';
import {omitVersions} from '../../utils';

describe('skeleton_mapper', () => {
  it('Successfully converts Skeleton targeted at a local/cloned repository data', () => {
    const mapper = new SkeletonMapper(
      fs.readFileSync(
        'sample_jsons/skeleton_mapper/sample_input_report/skeleton.json',
        {encoding: 'utf-8'}
      )
    );

    // fs.writeFileSync(
    //   'sample_jsons/skeleton_mapper/skeleton-hdf.json',
    //   JSON.stringify(mapper.toHdf(), null, 2)
    // );

    expect(omitVersions(mapper.toHdf())).toEqual(
      omitVersions(
        JSON.parse(
          fs.readFileSync(
            'sample_jsons/skeleton_mapper/skeleton-hdf.json',
            {
              encoding: 'utf-8'
            }
          )
        )
      )
    );
  });
});

describe('skeleton_mapper_withraw', () => {
  it('Successfully converts withraw flagged Skeleton targeted at a local/cloned repository data', () => {
    const mapper = new SkeletonMapper(
      fs.readFileSync(
        'sample_jsons/skeleton_mapper/sample_input_report/skeleton.json',
        {encoding: 'utf-8'}
      ),
      true
    );

    // fs.writeFileSync(
    //   'sample_jsons/skeleton_mapper/skeleton-hdf-withraw.json',
    //   JSON.stringify(mapper.toHdf(), null, 2)
    // );

    expect(omitVersions(mapper.toHdf())).toEqual(
      omitVersions(
        JSON.parse(
          fs.readFileSync(
            'sample_jsons/skeleton_mapper/skeleton-hdf-withraw.json',
            {
              encoding: 'utf-8'
            }
          )
        )
      )
    );
  });
});
=======
import {expect} from 'chai';
import {CheckovMapper} from '../../../src/checkov-mapper';
import {ExecJSON} from 'inspecjs';

describe('CheckovMapper', () => {
  const sampleCheckovSarif = JSON.stringify({
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Checkov',
            version: '2.0.0',
            informationUri: 'https://checkov.io'
          }
        },
        results: [
          {
            ruleId: 'CKV_AWS_136',
            ruleIndex: 0,
            level: 'error',
            message: {
              text: 'Ensure that ECR repositories are encrypted using KMS'
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: 'main.tf'
                  },
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
          },
          {
            ruleId: 'CKV_AWS_18',
            ruleIndex: 1,
            level: 'warning',
            message: {
              text: 'Ensure the S3 bucket has server side encryption enabled'
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: 'main.tf'
                  },
                  region: {
                    startLine: 25,
                    endLine: 30,
                    snippet: {
                      text: 'resource "aws_s3_bucket" "data_bucket"'
                    }
                  }
                }
              }
            ]
          },
          {
            ruleId: 'CKV_UNKNOWN',
            ruleIndex: 2,
            level: 'note',
            message: {
              text: 'Unknown security check'
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: 'main.tf'
                  },
                  region: {
                    startLine: 40,
                    endLine: 45,
                    snippet: {
                      text: 'resource "aws_instance" "test"'
                    }
                  }
                }
              }
            ]
          }
        ]
      }
    ]
  });

  it('should convert Checkov SARIF to HDF', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();

    expect(hdf).to.be.an('object');
    expect(hdf.platform.name).to.equal('Heimdall Tools');
    expect(hdf.platform.target_id).to.equal('Checkov (Bridgecrew)');
    expect(hdf.profiles).to.be.an('array').with.lengthOf(1);
  });

  it('should properly map controls', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    expect(controls).to.be.an('array').with.lengthOf(3);

    // Check first control (CKV_AWS_136)
    const ecr_control = controls[0];
    expect(ecr_control.id).to.equal('CKV_AWS_136');
    expect(ecr_control.title).to.include('ECR repositories');
    expect(ecr_control.impact).to.equal(0.7); // error level
    expect(ecr_control.tags.cci).to.deep.equal(['CCI-001199', 'CCI-002475']);
    expect(ecr_control.tags.nist).to.be.an('array');
    expect(ecr_control.tags.severity).to.equal('error');
    expect(ecr_control.tags.checkov_id).to.equal('CKV_AWS_136');
  });

  it('should correctly derive NIST controls from CCI mappings', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    // CKV_AWS_136 has CCIs: CCI-001199 (SC-28), CCI-002475 (SC-28(1))
    // Should derive NIST control: SC-28
    const ecr_control = controls[0];
    expect(ecr_control.tags.nist).to.include('SC-28');

    // CKV_AWS_18 has CCIs: CCI-000068 (AC-17(2)), CCI-001453 (AC-17(2))
    // Should derive NIST control: AC-17
    const s3_control = controls[1];
    expect(s3_control.tags.cci).to.deep.equal(['CCI-000068', 'CCI-001453']);
    expect(s3_control.tags.nist).to.include('AC-17');
  });

  it('should set correct status based on severity level', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    // error level should be Failed
    expect(controls[0].results[0].status).to.equal(
      ExecJSON.ControlResultStatus.Failed
    );

    // warning level should be Failed
    expect(controls[1].results[0].status).to.equal(
      ExecJSON.ControlResultStatus.Failed
    );

    // note level should be Skipped
    expect(controls[2].results[0].status).to.equal(
      ExecJSON.ControlResultStatus.Skipped
    );
  });

  it('should include source location information', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();
    const control = hdf.profiles[0].controls[0];

    expect(control.source_location).to.be.an('object');
    expect(control.source_location.ref).to.equal('main.tf');
    expect(control.source_location.line).to.equal(13);
  });

  it('should include Bridgecrew documentation reference', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();
    const control = hdf.profiles[0].controls[0];

    expect(control.refs).to.be.an('array').with.lengthOf(1);
    expect(control.refs[0].url).to.equal(
      'https://docs.bridgecrew.io/docs/ckv_aws_136'
    );
  });

  it('should use default NIST tags for unmapped controls', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();
    const unmappedControl = hdf.profiles[0].controls[2]; // CKV_UNKNOWN

    expect(unmappedControl.tags.cci).to.be.an('array').with.lengthOf(0);
    expect(unmappedControl.tags.nist).to.deep.equal(['SA-11', 'RA-5']);
  });

  it('should format code descriptions properly', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();
    const control = hdf.profiles[0].controls[0];

    expect(control.results[0].code_desc).to.include('main.tf');
    expect(control.results[0].code_desc).to.include('Line: 13');
  });

  it('should include passthrough data', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif);
    const hdf = mapper.toHdf();

    expect(hdf.passthrough).to.be.an('object');
    expect(hdf.passthrough.auxiliary_data).to.be.an('array').with.lengthOf(1);
    expect(hdf.passthrough.auxiliary_data[0].name).to.equal('Checkov');
  });

  it('should optionally include raw data when withRaw is true', () => {
    const mapper = new CheckovMapper(sampleCheckovSarif, true);
    const hdf = mapper.toHdf();

    expect(hdf.passthrough.raw).to.be.an('object');
  });
});
>>>>>>> 20e7c5761ebb1f9552bae72117849bcfd009e670
