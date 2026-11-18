import fs from 'node:fs/promises';
import path from 'node:path';

export interface SchemaValidationResult {
  valid: boolean;
  errors: string[];
}

export interface SchemaDriftResult {
  driftDetected: boolean;
  differences: string[];
}

/**
 * Validates a JavaScript/JSON value against a JSON Schema structure.
 * Native zero-dependency implementation covering standard JSON Schema / OpenAPI schema constraints.
 */
export function validateJsonSchema(
  data: unknown,
  schema: Record<string, unknown> | boolean,
  currentPath = '$',
): SchemaValidationResult {
  const errors: string[] = [];

  if (typeof schema === 'boolean') {
    if (schema) return { valid: true, errors: [] };
    return { valid: false, errors: [`${currentPath}: Schema disallows all values`] };
  }

  // 1. Type validation
  if (schema.type) {
    const expectedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actualType = getJsonType(data);
    const typeMatches = expectedTypes.some((t) => {
      if (t === 'integer') return Number.isInteger(data);
      if (t === 'number') return typeof data === 'number' && !Number.isNaN(data);
      return t === actualType;
    });

    if (!typeMatches) {
      errors.push(
        `${currentPath}: Expected type "${expectedTypes.join(' | ')}", but received "${actualType}"`,
      );
      // If type fails, skip nested property checks for mismatched types
      return { valid: false, errors };
    }
  }

  // 2. Enum validation
  if (Array.isArray(schema.enum)) {
    const enumMatched = schema.enum.some(
      (val) => JSON.stringify(val) === JSON.stringify(data),
    );
    if (!enumMatched) {
      errors.push(
        `${currentPath}: Value ${JSON.stringify(data)} does not match allowed enum [${schema.enum.map((e) => JSON.stringify(e)).join(', ')}]`,
      );
    }
  }

  // 3. String constraints
  if (typeof data === 'string') {
    if (typeof schema.minLength === 'number' && data.length < schema.minLength) {
      errors.push(
        `${currentPath}: String length ${data.length} is less than minLength ${schema.minLength}`,
      );
    }
    if (typeof schema.maxLength === 'number' && data.length > schema.maxLength) {
      errors.push(
        `${currentPath}: String length ${data.length} exceeds maxLength ${schema.maxLength}`,
      );
    }
    if (typeof schema.pattern === 'string') {
      try {
        const regex = new RegExp(schema.pattern);
        if (!regex.test(data)) {
          errors.push(
            `${currentPath}: String does not match pattern "${schema.pattern}"`,
          );
        }
      } catch {
        // Ignore invalid regex in schema
      }
    }
  }

  // 4. Number constraints
  if (typeof data === 'number' && !Number.isNaN(data)) {
    if (typeof schema.minimum === 'number' && data < schema.minimum) {
      errors.push(`${currentPath}: Value ${data} is less than minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === 'number' && data > schema.maximum) {
      errors.push(`${currentPath}: Value ${data} exceeds maximum ${schema.maximum}`);
    }
  }

  // 5. Object constraints (properties & required)
  if (data !== null && typeof data === 'object' && !Array.isArray(data)) {
    const dataObj = data as Record<string, unknown>;

    // Required fields check
    if (Array.isArray(schema.required)) {
      for (const reqKey of schema.required) {
        if (typeof reqKey === 'string' && !(reqKey in dataObj)) {
          errors.push(`${currentPath}: Missing required property "${reqKey}"`);
        }
      }
    }

    // Properties validation
    if (schema.properties && typeof schema.properties === 'object') {
      const properties = schema.properties as Record<string, Record<string, unknown>>;
      for (const [propName, propSchema] of Object.entries(properties)) {
        if (propName in dataObj) {
          const propRes = validateJsonSchema(
            dataObj[propName],
            propSchema,
            `${currentPath}.${propName}`,
          );
          errors.push(...propRes.errors);
        }
      }
    }

    // AdditionalProperties check
    if (
      schema.additionalProperties === false &&
      schema.properties &&
      typeof schema.properties === 'object'
    ) {
      const allowedKeys = new Set(Object.keys(schema.properties as object));
      for (const key of Object.keys(dataObj)) {
        if (!allowedKeys.has(key)) {
          errors.push(`${currentPath}: Disallowed additional property "${key}"`);
        }
      }
    }
  }

  // 6. Array constraints (items)
  if (Array.isArray(data)) {
    if (typeof schema.minItems === 'number' && data.length < schema.minItems) {
      errors.push(
        `${currentPath}: Array length ${data.length} is less than minItems ${schema.minItems}`,
      );
    }
    if (typeof schema.maxItems === 'number' && data.length > schema.maxItems) {
      errors.push(
        `${currentPath}: Array length ${data.length} exceeds maxItems ${schema.maxItems}`,
      );
    }
    if (schema.items && typeof schema.items === 'object') {
      data.forEach((item, index) => {
        const itemRes = validateJsonSchema(
          item,
          schema.items as Record<string, unknown>,
          `${currentPath}[${index}]`,
        );
        errors.push(...itemRes.errors);
      });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Loads and parses a JSON Schema file from disk.
 */
export async function loadSchemaFromFile(
  filePath: string,
): Promise<Record<string, unknown>> {
  const resolved = path.resolve(process.cwd(), filePath);
  const raw = await fs.readFile(resolved, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`Invalid schema file at ${filePath}: content must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

/**
 * Compares two JSON structures or captured event payloads and detects structural differences / schema drift.
 */
export function detectSchemaDrift(
  baseline: unknown,
  candidate: unknown,
  currentPath = '$',
): SchemaDriftResult {
  const differences: string[] = [];

  const baseType = getJsonType(baseline);
  const candType = getJsonType(candidate);

  if (baseType !== candType) {
    differences.push(
      `${currentPath}: Type changed from "${baseType}" in baseline to "${candType}" in candidate`,
    );
    return { driftDetected: true, differences };
  }

  if (baseType === 'object' && baseline !== null && candidate !== null) {
    const baseObj = baseline as Record<string, unknown>;
    const candObj = candidate as Record<string, unknown>;

    // Keys present in baseline but missing in candidate
    for (const key of Object.keys(baseObj)) {
      if (!(key in candObj)) {
        differences.push(
          `${currentPath}.${key}: Removed field (present in baseline, missing in candidate)`,
        );
      } else {
        const subResult = detectSchemaDrift(
          baseObj[key],
          candObj[key],
          `${currentPath}.${key}`,
        );
        differences.push(...subResult.differences);
      }
    }

    // New keys in candidate not in baseline
    for (const key of Object.keys(candObj)) {
      if (!(key in baseObj)) {
        differences.push(
          `${currentPath}.${key}: Added new field with type "${getJsonType(candObj[key])}"`,
        );
      }
    }
  } else if (
    baseType === 'array' &&
    Array.isArray(baseline) &&
    Array.isArray(candidate)
  ) {
    if (baseline.length > 0 && candidate.length > 0) {
      // Check first item structure
      const itemResult = detectSchemaDrift(
        baseline[0],
        candidate[0],
        `${currentPath}[*]`,
      );
      differences.push(...itemResult.differences);
    }
  }

  return {
    driftDetected: differences.length > 0,
    differences,
  };
}

function getJsonType(val: unknown): string {
  if (val === null) return 'null';
  if (Array.isArray(val)) return 'array';
  return typeof val;
}
