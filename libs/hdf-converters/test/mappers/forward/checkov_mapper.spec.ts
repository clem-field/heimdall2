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