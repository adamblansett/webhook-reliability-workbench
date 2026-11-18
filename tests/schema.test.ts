import { describe, it, expect } from 'vitest';
import { validateJsonSchema, detectSchemaDrift } from '../src/schema/validator.js';

describe('JSON Schema Validation & Drift Detection', () => {
  const userSchema = {
    type: 'object',
    required: ['id', 'email', 'tier'],
    properties: {
      id: { type: 'string' },
      email: { type: 'string', pattern: '^[^@]+@[^@]+$' },
      tier: { type: 'string', enum: ['free', 'pro', 'enterprise'] },
      age: { type: 'integer', minimum: 18 },
      tags: {
        type: 'array',
        items: { type: 'string' },
        minItems: 1,
      },
    },
    additionalProperties: false,
  };

  it('validates a conformant payload successfully', () => {
    const validData = {
      id: 'usr_123',
      email: 'alice@example.com',
      tier: 'pro',
      age: 25,
      tags: ['developer', 'typescript'],
    };

    const result = validateJsonSchema(validData, userSchema);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('flags missing required properties', () => {
    const invalidData = {
      id: 'usr_123',
      // missing email
      tier: 'pro',
    };

    const result = validateJsonSchema(invalidData, userSchema);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('$: Missing required property "email"');
  });

  it('flags type mismatches and enum violations', () => {
    const invalidData = {
      id: 12345, // should be string
      email: 'bad-email-format',
      tier: 'god-mode', // invalid enum
      age: 15, // below minimum 18
      tags: [], // violates minItems: 1
    };

    const result = validateJsonSchema(invalidData, userSchema);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Expected type "string"'))).toBe(true);
    expect(result.errors.some((e) => e.includes('does not match allowed enum'))).toBe(
      true,
    );
    expect(result.errors.some((e) => e.includes('less than minimum 18'))).toBe(true);
    expect(result.errors.some((e) => e.includes('less than minItems 1'))).toBe(true);
  });

  it('flags unexpected additional properties when disallowed', () => {
    const invalidData = {
      id: 'usr_123',
      email: 'alice@example.com',
      tier: 'pro',
      unexpectedField: 'intruder',
    };

    const result = validateJsonSchema(invalidData, userSchema);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      '$: Disallowed additional property "unexpectedField"',
    );
  });

  describe('detectSchemaDrift', () => {
    it('detects type shifts, removed fields, and added fields', () => {
      const baseline = {
        id: 'usr_100',
        metadata: {
          role: 'admin',
          active: true,
        },
        items: [{ id: 1, name: 'Item A' }],
      };

      const candidate = {
        id: 100, // type shift string -> number
        metadata: {
          // role removed
          active: true,
          newField: 'fresh',
        },
        items: [{ id: 2, name: 'Item B' }],
      };

      const drift = detectSchemaDrift(baseline, candidate);
      expect(drift.driftDetected).toBe(true);
      expect(
        drift.differences.some((d) =>
          d.includes('Type changed from "string" in baseline to "number"'),
        ),
      ).toBe(true);
      expect(
        drift.differences.some((d) =>
          d.includes('Removed field (present in baseline, missing in candidate)'),
        ),
      ).toBe(true);
      expect(
        drift.differences.some((d) => d.includes('Added new field with type "string"')),
      ).toBe(true);
    });

    it('returns no drift when schemas match identically', () => {
      const a = { a: 'foo', b: 123, c: [true, false] };
      const b = { a: 'bar', b: 456, c: [false] };

      const drift = detectSchemaDrift(a, b);
      expect(drift.driftDetected).toBe(false);
      expect(drift.differences).toHaveLength(0);
    });
  });
});
