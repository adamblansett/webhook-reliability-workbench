import { z } from 'zod';

export const WebhookFixtureSchema = z.object({
  schemaVersion: z.literal('1.0.0'),
  metadata: z.object({
    name: z.string().optional(),
    description: z.string().optional(),
    exportedAt: z.string().datetime(),
    originalEventId: z.string(),
    generator: z.literal('webhook-reliability-workbench'),
  }),
  request: z.object({
    method: z.string().min(1),
    path: z.string().min(1),
    headers: z.record(z.union([z.string(), z.array(z.string())])),
    query: z.record(z.union([z.string(), z.array(z.string())])),
    contentType: z.string().nullable(),
    contentLength: z.number().nonnegative(),
    rawBody: z.string(),
    body: z.unknown().nullable(),
    isJson: z.boolean(),
  }),
});

export type WebhookFixture = z.infer<typeof WebhookFixtureSchema>;
