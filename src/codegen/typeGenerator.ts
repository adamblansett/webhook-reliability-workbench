export interface TypeGenerationOptions {
  rootName?: string;
  format?: 'ts' | 'zod';
  exportKeyword?: boolean;
}

/**
 * Recursively infers TypeScript interface definitions from a JSON data structure.
 */
export function generateTypeScriptTypes(
  data: unknown,
  rootName = 'WebhookPayload',
): string {
  const interfaces: Map<string, string> = new Map();

  function toPascalCase(str: string): string {
    return str
      .replace(/[^a-zA-Z0-9]+(.)/g, (_, chr) => chr.toUpperCase())
      .replace(/^[a-z]/, (chr) => chr.toUpperCase());
  }

  function inferType(val: unknown, propertyName: string): string {
    if (val === null) return 'null | unknown';
    if (typeof val === 'string') return 'string';
    if (typeof val === 'number') return 'number';
    if (typeof val === 'boolean') return 'boolean';

    if (Array.isArray(val)) {
      if (val.length === 0) return 'unknown[]';
      const itemType = inferType(val[0], `${propertyName}Item`);
      return itemType.includes(' ') ? `(${itemType})[]` : `${itemType}[]`;
    }

    if (typeof val === 'object') {
      const typeName = toPascalCase(propertyName);
      const obj = val as Record<string, unknown>;
      const fields: string[] = [];

      for (const [key, propVal] of Object.entries(obj)) {
        const safeKey = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key)
          ? key
          : JSON.stringify(key);
        const childType = inferType(propVal, `${propertyName}_${key}`);
        fields.push(`  ${safeKey}: ${childType};`);
      }

      const body = `export interface ${typeName} {\n${fields.join('\n')}\n}`;
      interfaces.set(typeName, body);
      return typeName;
    }

    return 'unknown';
  }

  inferType(data, rootName);

  return Array.from(interfaces.values()).reverse().join('\n\n');
}

/**
 * Recursively infers a Zod schema from a JSON data structure.
 */
export function generateZodSchema(data: unknown, rootName = 'WebhookPayload'): string {
  const schemas: Map<string, string> = new Map();

  function toPascalCase(str: string): string {
    return str
      .replace(/[^a-zA-Z0-9]+(.)/g, (_, chr) => chr.toUpperCase())
      .replace(/^[a-z]/, (chr) => chr.toUpperCase());
  }

  function inferZod(val: unknown, propertyName: string): string {
    if (val === null) return 'z.null()';
    if (typeof val === 'string') return 'z.string()';
    if (typeof val === 'number') return 'z.number()';
    if (typeof val === 'boolean') return 'z.boolean()';

    if (Array.isArray(val)) {
      if (val.length === 0) return 'z.array(z.unknown())';
      const itemZod = inferZod(val[0], `${propertyName}Item`);
      return `z.array(${itemZod})`;
    }

    if (typeof val === 'object') {
      const schemaName = `${toPascalCase(propertyName)}Schema`;
      const obj = val as Record<string, unknown>;
      const fields: string[] = [];

      for (const [key, propVal] of Object.entries(obj)) {
        const safeKey = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key)
          ? key
          : JSON.stringify(key);
        const childZod = inferZod(propVal, `${propertyName}_${key}`);
        fields.push(`  ${safeKey}: ${childZod},`);
      }

      const body = `export const ${schemaName} = z.object({\n${fields.join('\n')}\n});`;
      schemas.set(schemaName, body);
      return schemaName;
    }

    return 'z.unknown()';
  }

  inferZod(data, rootName);

  const schemaBodies = Array.from(schemas.values()).reverse().join('\n\n');
  const typeInference = `export type ${toPascalCase(rootName)} = z.infer<typeof ${toPascalCase(rootName)}Schema>;`;

  return `import { z } from 'zod';\n\n${schemaBodies}\n\n${typeInference}`;
}
