import fs from 'node:fs';
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
      expect(hdf.platform.target_id).to.equal('Checkov (Bridgecrew)');
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
});
