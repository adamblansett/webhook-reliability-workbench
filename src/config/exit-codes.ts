/**
 * Standard process exit codes for Webhook Reliability Workbench.
 */
export const ExitCode = {
  SUCCESS: 0,
  INVALID_ARGUMENT: 1,
  CONFIG_ERROR: 2,
  SECURITY_ERROR: 3,
  NOT_FOUND: 4,
  REPLAY_FAILED: 5,
  RECEIVER_ERROR: 6,
  GENERAL_ERROR: 7,
} as const;

export type ExitCodeType = (typeof ExitCode)[keyof typeof ExitCode];
