import fs from 'fs';
import {ExecJSON} from 'inspecjs';
import {describe, expect, it} from 'vitest';
import {CheckovMapper} from '../../../src/checkov-mapper';
import {omitHDFTimes, omitVersions} from '../../utils';

describe('checkov_mapper', () => {
  describe('checkov_json', () => {
    const mapper = new CheckovMapper(
      fs.readFileSync(
        'sample_jsons/checkov-mapper/sample_input_report/checkov_json.json',
        {encoding: 'utf-8'}
      )
    );

    // Uncomment to regenerate baseline: // NOSONAR
    // fs.writeFileSync(
    //   'sample_jsons/checkov-mapper/checkov_json-hdf.json',
    //   JSON.stringify(mapper.toHdf(), null, 2)
    // );

    it('should produce a valid HDF matching the regression baseline', () => {
      const expected = JSON.parse(
        fs.readFileSync(
          'sample_jsons/checkov-mapper/checkov_json-hdf.json',
          {encoding: 'utf-8'}
        )
      );
      expect(omitHDFTimes(omitVersions(mapper.toHdf()))).to.eql(
        omitHDFTimes(omitVersions(expected))
      );
    });
  });

  describe('checkov_sample', () => {
    const mapper = new CheckovMapper(
      fs.readFileSync(
        'sample_jsons/checkov-mapper/sample_input_report/checkov_sample.json',
        {encoding: 'utf-8'}
      )
    );

    // Uncomment to regenerate baseline: // NOSONAR
    // fs.writeFileSync(
    //   'sample_jsons/checkov-mapper/checkov_sample-hdf.json',
    //   JSON.stringify(mapper.toHdf(), null, 2)
    // );

    it('should produce a valid HDF output', () => {
      const hdf = mapper.toHdf();
      expect(hdf).to.be.an('object');
      expect(hdf.platform.name).to.equal('Heimdall Tools');
      expect(hdf.profiles).to.be.an('array').with.lengthOf(1);
      expect(hdf.profiles[0].controls.length).to.be.greaterThan(0);
    });
  });

  describe('checkov_json withRaw', () => {
    const mapper = new CheckovMapper(
      fs.readFileSync(
        'sample_jsons/checkov-mapper/sample_input_report/checkov_json.json',
        {encoding: 'utf-8'}
      ),
      true
    );

    // Uncomment to regenerate baseline: // NOSONAR
    // fs.writeFileSync(
    //   'sample_jsons/checkov-mapper/checkov_json-withraw-hdf.json',
    //   JSON.stringify(mapper.toHdf(), null, 2)
    // );

    it('should include raw data in passthrough', () => {
      const hdf = mapper.toHdf() as ExecJSON.Execution & {
        passthrough: Record<string, unknown>;
      };
      expect(hdf.passthrough).to.have.property('raw');
      expect(hdf.passthrough).to.have.property('auxiliary_data');
    });
  });

  describe('checkov_with_skips (skipped checks + parsing errors)', () => {
    const mapper = new CheckovMapper(
      fs.readFileSync(
        'sample_jsons/checkov-mapper/sample_input_report/checkov_with_skips.json',
        {encoding: 'utf-8'}
      )
    );

    // Uncomment to regenerate baseline: // NOSONAR
    // fs.writeFileSync(
    //   'sample_jsons/checkov-mapper/checkov_with_skips-hdf.json',
    //   JSON.stringify(mapper.toHdf(), null, 2)
    // );

    it('should produce a valid HDF matching the regression baseline', () => {
      const expected = JSON.parse(
        fs.readFileSync(
          'sample_jsons/checkov-mapper/checkov_with_skips-hdf.json',
          {encoding: 'utf-8'}
        )
      );
      expect(omitHDFTimes(omitVersions(mapper.toHdf()))).to.eql(
        omitHDFTimes(omitVersions(expected))
      );
    });

    it('should include skipped controls', () => {
      const hdf = mapper.toHdf();
      const controls = hdf.profiles[0].controls;
      const skipped = controls.filter(
        (c) => c.results.some((r) => r.status === ExecJSON.ControlResultStatus.Skipped)
      );
      expect(skipped.length).to.be.greaterThan(0);
    });

    it('should include parsing errors in passthrough', () => {
      const hdf = mapper.toHdf() as ExecJSON.Execution & {
        passthrough: {auxiliary_data: Array<{data: {results: {parsing_errors: unknown[]}}}>};
      };
      const auxData = hdf.passthrough.auxiliary_data[0].data;
      expect(auxData.results.parsing_errors).to.be.an('array');
      expect(auxData.results.parsing_errors.length).to.be.greaterThan(0);
    });
  });

  describe('checkov_synthetic (all code paths — severity, skipped, parsing errors)', () => {
    const mapper = new CheckovMapper(
      fs.readFileSync(
        'sample_jsons/checkov-mapper/sample_input_report/checkov_synthetic.json',
        {encoding: 'utf-8'}
      )
    );

    // Uncomment to regenerate baseline: // NOSONAR
    // fs.writeFileSync(
    //   'sample_jsons/checkov-mapper/checkov_synthetic-hdf.json',
    //   JSON.stringify(mapper.toHdf(), null, 2)
    // );

    it('should produce a valid HDF matching the regression baseline', () => {
      const expected = JSON.parse(
        fs.readFileSync(
          'sample_jsons/checkov-mapper/checkov_synthetic-hdf.json',
          {encoding: 'utf-8'}
        )
      );
      expect(omitHDFTimes(omitVersions(mapper.toHdf()))).to.eql(
        omitHDFTimes(omitVersions(expected))
      );
    });

    it('should map all three check types', () => {
      const hdf = mapper.toHdf();
      const controls = hdf.profiles[0].controls;
      const statuses = controls.flatMap((c) => c.results.map((r) => r.status));
      expect(statuses).to.include(ExecJSON.ControlResultStatus.Passed);
      expect(statuses).to.include(ExecJSON.ControlResultStatus.Failed);
      expect(statuses).to.include(ExecJSON.ControlResultStatus.Skipped);
    });

    it('should map severity to correct impact', () => {
      const hdf = mapper.toHdf();
      const controls = hdf.profiles[0].controls;
      const highControl = controls.find((c) => c.id === 'CKV_AWS_150');
      expect(highControl!.impact).to.equal(0.89);
      const nullSevControl = controls.find((c) => c.id === 'CKV_AWS_41');
      expect(nullSevControl!.impact).to.equal(0);
    });

    it('should include evaluated_keys and guideline in message', () => {
      const hdf = mapper.toHdf();
      const controls = hdf.profiles[0].controls;
      const failed = controls.find((c) => c.id === 'CKV_AWS_150');
      expect(failed!.results[0].message).to.include('enable_deletion_protection');
      expect(failed!.results[0].message).to.include('prismacloud.io');
    });

    it('should include code_block in code_desc with pre tags', () => {
      const hdf = mapper.toHdf();
      const controls = hdf.profiles[0].controls;
      const control = controls.find((c) => c.id === 'CKV_AWS_150');
      expect(control!.results[0].code_desc).to.include('<pre>');
      expect(control!.results[0].code_desc).to.include('resource "aws_lb"');
    });

    it('should put unmapped attributes in code tab', () => {
      const hdf = mapper.toHdf();
      const controls = hdf.profiles[0].controls;
      const control = controls.find((c) => c.id === 'CKV_AWS_150');
      expect(control!.code).to.include('entity_tags');
      expect(control!.code).to.include('benchmarks');
    });

    it('should include parsing errors in passthrough', () => {
      const hdf = mapper.toHdf() as ExecJSON.Execution & {
        passthrough: {auxiliary_data: Array<{data: {results: {parsing_errors: unknown[]}}}>};
      };
      const errors = hdf.passthrough.auxiliary_data[0].data.results.parsing_errors;
      expect(errors).to.include('/broken.tf');
    });
  });
});
