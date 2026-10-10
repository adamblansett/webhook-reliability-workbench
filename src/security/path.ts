import path from 'node:path';
import fs from 'node:fs/promises';

export class PathSecurityError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
    public readonly targetPath?: string,
  ) {
    super(message);
    this.name = 'PathSecurityError';
  }
}

/**
 * Validates a file path to prevent directory traversal and unsafe filenames.
 *
 * @param filePath User-supplied target file path.
 * @param baseDir Optional directory to constrain writes within.
 * @returns Normalized absolute path.
 */
export function resolveSafePath(
  filePath: string,
  baseDir: string = process.cwd(),
  enforceWithinBase = false,
): string {
  if (!filePath || typeof filePath !== 'string' || filePath.trim() === '') {
    throw new PathSecurityError('File path cannot be empty.', 'EMPTY_PATH', filePath);
  }

  // Prevent null bytes
  if (filePath.includes('\0')) {
    throw new PathSecurityError(
      'File path contains forbidden null bytes.',
      'NULL_BYTE_DETECTED',
      filePath,
    );
  }

  const normalizedBase = path.resolve(baseDir);
  const resolved = path.isAbsolute(filePath)
    ? path.resolve(filePath)
    : path.resolve(normalizedBase, filePath);

  if (enforceWithinBase) {
    const isInside =
      resolved === normalizedBase || resolved.startsWith(normalizedBase + path.sep);
    if (!isInside) {
      throw new PathSecurityError(
        `File path "${filePath}" resolves outside allowed base directory "${normalizedBase}". Directory traversal is forbidden.`,
        'DIRECTORY_TRAVERSAL_DETECTED',
        filePath,
      );
    }
  }

  return resolved;
}

/**
 * Ensures that writing to targetPath does not unintentionally overwrite an existing file or follow symlinks.
 */
export async function assertFileWriteSafety(
  targetPath: string,
  allowOverwrite: boolean,
): Promise<void> {
  try {
    const lstats = await fs.lstat(targetPath);
    if (lstats.isSymbolicLink()) {
      throw new PathSecurityError(
        `Target path "${targetPath}" is a symbolic link. Writing to symlinks is prohibited.`,
        'SYMLINK_DETECTED',
        targetPath,
      );
    }
    const stats = await fs.stat(targetPath);
    if (stats.isDirectory()) {
      throw new PathSecurityError(
        `Target path "${targetPath}" is a directory, not a file.`,
        'IS_DIRECTORY',
        targetPath,
      );
    }
    if (!allowOverwrite) {
      throw new PathSecurityError(
        `File already exists at "${targetPath}". Pass --overwrite to replace it.`,
        'FILE_ALREADY_EXISTS',
        targetPath,
      );
    }
  } catch (err: unknown) {
    if (
      err &&
      typeof err === 'object' &&
      'code' in err &&
      (err as { code: string }).code === 'ENOENT'
    ) {
      // File does not exist: safe to write
      return;
    }
    throw err;
  }
}
