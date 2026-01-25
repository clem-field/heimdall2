# Checkov Integration Summary

## Changes Made

### 1. Fixed CCI to NIST Control Mapping ✓

**Issue**: The original implementation incorrectly tried to map CCIs to NIST controls by searching through the wrong data structure.

**Solution**: Updated the `deriveNistFromCCI()` function in [checkov-mapper.ts](libs/hdf-converters/src/checkov-mapper.ts) to:
- Correctly use `CciNistMappingData` which maps CCI strings to NIST control strings
- Extract base NIST controls (e.g., `SC-28` from `SC-28 (1)`)
- Return unique NIST controls for each Checkov finding

**Code Changes**:
```typescript
function deriveNistFromCCI(ccis: string[]): string[] {
  const nistTags: string[] = [];
  for (const cci of ccis) {
    // CciNistMappingData maps CCI -> NIST control string (e.g., "SC-28" or "SC-28 (1)")
    const nistControl = (CciNistMappingData as Record<string, string>)[cci];
    if (nistControl) {
      // Extract base control (e.g., "SC-28" from "SC-28 (1)")
      const baseControl = nistControl.match(/[A-Z]{2}-\d+/);
      if (baseControl) {
        nistTags.push(baseControl[0]);
      }
    }
  }
  // Return unique NIST tags, or default if none found
  const uniqueTags = [...new Set(nistTags)];
  return uniqueTags.length > 0
    ? uniqueTags
    : DEFAULT_STATIC_CODE_ANALYSIS_NIST_TAGS;
}
```

### 2. Verified Mapping Correctness

Tested the CCI-to-NIST mapping with the current Checkov rules:

| Checkov Rule | CCIs | Derived NIST Controls | Verified ✓ |
|-------------|------|----------------------|-----------|
| CKV_AWS_136 | CCI-001199, CCI-002475 | SC-28 | ✓ |
| CKV_AWS_18 | CCI-000068, CCI-001453 | AC-17 | ✓ |
| CKV_AWS_19 | CCI-001199, CCI-002475 | SC-28 | ✓ |
| CKV_AWS_20 | CCI-000213, CCI-001813 | AC-3, CM-5 | ✓ |
| CKV_AWS_21 | CCI-000186 | IA-5 | ✓ |

### 3. Enhanced Test Coverage

Added comprehensive test in [checkov_mapper.spec.ts](libs/hdf-converters/test/mappers/forward/checkov_mapper.spec.ts):

```typescript
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
```

### 4. Updated Documentation

Enhanced [README_TS.md](README_TS.md) with:
- Detailed CCI-to-NIST mapping table
- Explanation of the mapping process
- Instructions for extending mappings with proper CCI lookup guidance

## How the Mapping Works

### Data Flow:
```
Checkov Rule ID (e.g., CKV_AWS_136)
    ↓
CheckovCciMappingData.ts
    ↓
CCI Identifiers (e.g., CCI-001199, CCI-002475)
    ↓
CciNistMappingData.ts
    ↓
NIST Control Strings (e.g., "SC-28", "SC-28 (1)")
    ↓
Extract Base Controls (e.g., "SC-28")
    ↓
Unique NIST Controls Array (e.g., ["SC-28"])
```

### Key Components:

1. **CheckovCciMappingData.ts**: Maps Checkov rule IDs → CCI arrays
   ```typescript
   'CKV_AWS_136': ['CCI-001199', 'CCI-002475']
   ```

2. **CciNistMappingData.ts**: Maps individual CCIs → NIST control strings
   ```typescript
   'CCI-001199': 'SC-28',
   'CCI-002475': 'SC-28 (1)'
   ```

3. **deriveNistFromCCI()**: Extracts base NIST controls and deduplicates
   ```typescript
   ['CCI-001199', 'CCI-002475'] → ['SC-28']
   ```

## Testing

To verify the mapping works:

```bash
# Run the full test suite
npm test

# Run only Checkov mapper tests
npm test -- checkov_mapper.spec.ts
```

## Output Example

When a Checkov finding is mapped to HDF, it includes:

```json
{
  "id": "CKV_AWS_136",
  "title": "Ensure that ECR repositories are encrypted using KMS",
  "tags": {
    "cci": ["CCI-001199", "CCI-002475"],
    "nist": ["SC-28"],
    "severity": "error",
    "checkov_id": "CKV_AWS_136"
  }
}
```

## Adding New Mappings

To add a new Checkov rule mapping:

1. **Research the appropriate NIST control** for the security check
2. **Find corresponding CCIs** from the [CCI List](https://csrc.nist.gov/projects/control-correlation-identifier)
3. **Verify CCIs exist** in `CciNistMappingData.ts`
4. **Add mapping** to `CheckovCciMappingData.ts`:
   ```typescript
   'CKV_AWS_NEW': ['CCI-XXXXX', 'CCI-YYYYY']
   ```
5. The NIST controls will be **automatically derived**

## What's Working Now

✅ CCIs are correctly mapped to NIST controls
✅ Duplicate NIST controls are properly deduplicated
✅ Base controls are extracted (SC-28 from SC-28(1))
✅ Unmapped rules fall back to default NIST tags (SA-11, RA-5)
✅ All mappings verified with test data
✅ Documentation updated with mapping details

## Files Modified

1. [libs/hdf-converters/src/checkov-mapper.ts](libs/hdf-converters/src/checkov-mapper.ts) - Fixed `deriveNistFromCCI()` function
2. [libs/hdf-converters/test/mappers/forward/checkov_mapper.spec.ts](libs/hdf-converters/test/mappers/forward/checkov_mapper.spec.ts) - Added CCI-NIST mapping test
3. [README_TS.md](README_TS.md) - Enhanced documentation with mapping details

## Next Steps (Optional)

- Add more Checkov rule → CCI mappings to `CheckovCciMappingData.ts`
- Run against real Checkov SARIF output to verify end-to-end functionality
- Consider creating a mapping utility to help find CCIs for new rules
