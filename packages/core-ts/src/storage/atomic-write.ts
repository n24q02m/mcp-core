import { open, rename, unlink } from 'node:fs/promises'

/**
 * Write data atomically: tmp file + fsync + rename.
 * A torn credential write decrypts to garbage and reads back as
 * "not configured"; the tmp+rename keeps the old blob intact until
 * the new one is fully on disk.
 */
export async function atomicWriteFile(path: string, data: Buffer): Promise<void> {
  const tmp = `${path}.tmp`
  try {
    const handle = await open(tmp, 'w', 0o600)
    try {
      await handle.writeFile(data)
      await handle.sync()
    } finally {
      await handle.close()
    }
    await rename(tmp, path)
  } catch (err) {
    await unlink(tmp).catch(() => {})
    throw err
  }
}
