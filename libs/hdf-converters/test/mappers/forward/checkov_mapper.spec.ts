import {expect} from 'chai';
import {CheckovMapper} from '../../../src/checkov-mapper';
import {ExecJSON} from 'inspecjs';

describe('CheckovMapper', () => {
  const sampleCheckovJson = JSON.stringify({
    check_type: 'terraform',
    results: {
      passed_checks: [
        {
          check_id: 'CKV_AWS_41',
          bc_check_id: 'BC_AWS_SECRETS_5',
          check_name:
            'Ensure no hard coded AWS access key and secret key exists in provider',
          check_result: {result: 'PASSED', evaluated_keys: []},
          file_path: '/main.tf',
          file_line_range: [1, 10],
          resource: 'aws_provider.default',
          severity: null,
          guideline:
            'https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-general-policies/bc-aws-secrets-5'
        }
      ],
      failed_checks: [
        {
          check_id: 'CKV_AWS_150',
          bc_check_id: 'BC_AWS_NETWORKING_62',
          check_name:
            'Ensure that Load Balancer has deletion protection enabled',
          check_result: {
            result: 'FAILED',
            evaluated_keys: ['enable_deletion_protection']
          },
          file_path: '/alb/main.tf',
          file_line_range: [1, 8],
          resource: 'module.alb.aws_lb.main',
          resource_address: 'module.alb.aws_lb.main',
          severity: 'HIGH',
          guideline:
            'https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-general-policies/bc-aws-150',
          code_block: [
            [1, 'resource "aws_lb" "main" {\n'],
            [2, '  name               = "ecs-alb"\n'],
            [3, '  internal           = false\n']
          ]
        },
        {
          check_id: 'CKV_AWS_136',
          bc_check_id: 'BC_AWS_GENERAL_140',
          check_name:
            'Ensure that ECR repositories are encrypted using KMS',
          check_result: {
            result: 'FAILED',
            evaluated_keys: ['encryption_configuration']
          },
          file_path: '/ecr/main.tf',
          file_line_range: [13, 17],
          resource: 'aws_ecr_repository.heimdall',
          resource_address: 'aws_ecr_repository.heimdall',
          severity: 'MEDIUM',
          guideline: null,
          code_block: [
            [13, 'resource "aws_ecr_repository" "heimdall" {\n'],
            [14, '  name = "heimdall"\n']
          ]
        }
      ],
      skipped_checks: [],
      parsing_errors: []
    },
    summary: {
      passed: 1,
      failed: 2,
      skipped: 0,
      parsing_errors: 0,
      resource_count: 3,
      checkov_version: '3.2.497'
    }
  });

  it('should convert Checkov native JSON to HDF', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();

    expect(hdf).to.be.an('object');
    expect(hdf.platform.name).to.equal('Heimdall Tools');
    expect(hdf.platform.target_id).to.equal('Checkov (Bridgecrew)');
    expect(hdf.profiles).to.be.an('array').with.lengthOf(1);
  });

  it('should map profile metadata from summary', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const profile = hdf.profiles[0];

    expect(profile.name).to.equal('Checkov');
    expect(profile.version).to.equal('3.2.497');
    expect(profile.title).to.equal('Checkov terraform Security Scan');
  });

  it('should combine passed and failed checks into controls', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    // 1 passed + 2 failed = 3 controls
    expect(controls).to.be.an('array').with.lengthOf(3);
  });

  it('should properly map control IDs and titles', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    const passedControl = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_41'
    );
    expect(passedControl).to.exist;
    expect(passedControl!.title).to.include('hard coded AWS access key');

    const failedControl = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_150'
    );
    expect(failedControl).to.exist;
    expect(failedControl!.title).to.include('deletion protection');
  });

  it('should set correct status from check_result', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    const passedControl = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_41'
    );
    expect(passedControl!.results[0].status).to.equal(
      ExecJSON.ControlResultStatus.Passed
    );

    const failedControl = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_150'
    );
    expect(failedControl!.results[0].status).to.equal(
      ExecJSON.ControlResultStatus.Failed
    );
  });

  it('should map severity to impact', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    const highControl = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_150'
    );
    expect(highControl!.impact).to.equal(0.7); // HIGH

    const mediumControl = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_136'
    );
    expect(mediumControl!.impact).to.equal(0.5); // MEDIUM

    // null severity defaults to 0.5
    const nullSeverityControl = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_41'
    );
    expect(nullSeverityControl!.impact).to.equal(0.5);
  });

  it('should include source location information', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    const control = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_150'
    );
    expect(control!.source_location).to.be.an('object');
    expect(control!.source_location!.ref).to.equal('/alb/main.tf');
    expect(control!.source_location!.line).to.equal(1);
  });

  it('should include guideline as reference URL', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    const control = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_150'
    );
    expect(control!.refs).to.be.an('array').with.lengthOf(1);
    expect(control!.refs![0].url).to.include('prismacloud.io');
  });

  it('should fallback to Bridgecrew URL when guideline is null', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    const control = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_136'
    );
    expect(control!.refs![0].url).to.equal(
      'https://docs.bridgecrew.io/docs/ckv_aws_136'
    );
  });

  it('should derive NIST tags from CCI mappings', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    // CKV_AWS_150 maps to CCI-000366 (CM-6) per enriched checkov data
    const control = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_150'
    );
    expect(control!.tags.nist).to.include('CM-6');
  });

  it('should format code descriptions with resource and file info', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf();
    const controls = hdf.profiles[0].controls;

    const control = controls.find(
      (c: ExecJSON.Control) => c.id === 'CKV_AWS_150'
    );
    expect(control!.results[0].code_desc).to.include('/alb/main.tf');
    expect(control!.results[0].code_desc).to.include(
      'module.alb.aws_lb.main'
    );
  });

  it('should include passthrough data', () => {
    const mapper = new CheckovMapper(sampleCheckovJson);
    const hdf = mapper.toHdf() as ExecJSON.Execution & {
      passthrough: Record<string, unknown>;
    };

    expect(hdf.passthrough).to.be.an('object');
    expect(hdf.passthrough.auxiliary_data).to.be.an('array').with.lengthOf(1);
    expect(
      (hdf.passthrough.auxiliary_data as Array<{name: string}>)[0].name
    ).to.equal('Checkov');
  });

  it('should optionally include raw data when withRaw is true', () => {
    const mapper = new CheckovMapper(sampleCheckovJson, true);
    const hdf = mapper.toHdf() as ExecJSON.Execution & {
      passthrough: Record<string, unknown>;
    };

    expect(hdf.passthrough.raw).to.be.an('object');
  });
});
