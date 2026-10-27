import { configure, ZipReader, BlobReader, Uint8ArrayWriter } from "@zip.js/zip.js"
import { authTokenFromCredentials } from "@/runtime/server/api"

// Disable web workers to ensure compatibility across all environments (Vite, Electron, tests, HappyDOM)
configure({ useWebWorkers: false })

export type ZipToastOptions = {
  title: string
  description?: string
  variant?: "default" | "loading" | "success" | "error"
  persistent?: boolean
}

export function isZipFile(file?: { name?: string; type?: string } | null): boolean {
  if (!file || typeof file !== "object") return false
  const name = file.name?.toLowerCase() ?? ""
  const type = file.type?.toLowerCase() ?? ""

  return (
    name.endsWith(".zip") ||
    type === "application/zip" ||
    type === "application/x-zip-compressed" ||
    type === "application/x-zip" ||
    type === "multipart/x-zip"
  )
}

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$|clock\$)(\..*)?$/i

/**
 * Safely sanitizes zip entry paths and prevents directory traversal attacks (e.g. "../"),
 * NTFS Alternate Data Streams (ADS), Windows reserved device names, control characters,
 * trailing dots, and invalid characters.
 * Returns null if the path attempts to escape the root directory or is invalid.
 */
export function sanitizeZipPath(rawPath: string): string | null {
  if (!rawPath || typeof rawPath !== "string" || rawPath.length > 4096) return null

  // Strip control characters (including null bytes and newlines)
  let cleaned = rawPath.replace(/[\x00-\x1f\x7f]/g, "")

  // Normalize backslashes to forward slashes
  cleaned = cleaned.replace(/\\/g, "/")

  // Remove Windows drive letters (e.g. "C:") and leading slashes
  cleaned = cleaned.replace(/^[a-zA-Z]:\/?/, "").replace(/^\/+/, "")

  const segments = cleaned.split("/")
  const safe: string[] = []

  for (const segment of segments) {
    const trimmed = segment.trim()
    if (!trimmed || trimmed === ".") continue
    if (trimmed === "..") {
      if (safe.length === 0) {
        // Traversal above root is prevented
        return null
      }
      safe.pop()
      continue
    }

    // Block trailing dots, invalid multiple dots, illegal Windows characters (< > " | ? * :), and reserved device names
    if (trimmed.endsWith(".") || /[<>:"|?*]/.test(trimmed) || WINDOWS_RESERVED.test(trimmed)) {
      return null
    }

    safe.push(trimmed)
  }

  if (safe.length === 0) return null

  return safe.join("/")
}

/**
 * Formats a structured markdown context note detailing the archive manifest.
 */
export function formatArchiveManifest(archiveName: string, targetDirectory: string, extractedFiles: string[]): string {
  const count = extractedFiles.length
  let fileList: string

  if (count === 0) {
    fileList = "- (empty archive)"
  } else if (count <= 50) {
    fileList = extractedFiles.map((file) => `- \`${file}\``).join("\n")
  } else {
    const preview = extractedFiles.slice(0, 50).map((file) => `- \`${file}\``).join("\n")
    fileList = `${preview}\n- ... and ${count - 50} more files`
  }

  const destination = targetDirectory || "(workspace root)"

  return [
    `### Extracted Archive: ${archiveName}`,
    `- **Archive:** \`${archiveName}\``,
    `- **Destination:** \`${destination}\``,
    `- **Extracted Files (${count}):**`,
    fileList,
  ].join("\n")
}

export async function writeWorkspaceFile(
  serverUrl: string,
  serverPassword: string | undefined,
  targetDirectory: string,
  relativePath: string,
  data: Uint8Array,
  signal?: AbortSignal,
): Promise<void> {
  const url = new URL("/api/experimental/fs/write", serverUrl)
  if (targetDirectory) {
    url.searchParams.set("location[directory]", targetDirectory)
  }
  const normalizedDir = targetDirectory ? targetDirectory.replace(/\\/g, "/").replace(/\/$/, "") : ""
  const fullPath = normalizedDir ? `${normalizedDir}/${relativePath}` : relativePath
  url.searchParams.set("path", fullPath)

  const headers: Record<string, string> = {
    "content-type": "application/octet-stream",
  }

  if (serverPassword) {
    headers["authorization"] = `Basic ${authTokenFromCredentials({ password: serverPassword })}`
  }

  const response = await fetch(url.toString(), {
    method: "POST",
    headers,
    body: data as unknown as BodyInit,
    signal,
  })

  if (!response.ok) {
    throw new Error(`Failed to write ${relativePath}: ${response.statusText || response.status}`)
  }
}

export type ExtractZipOptions = {
  file: File | Blob
  archiveName?: string
  targetDirectory: string
  serverUrl: string
  serverPassword?: string
  onProgress?: (current: number, total: number, path: string) => void
  signal?: AbortSignal
}

export type ExtractZipResult = {
  archiveName: string
  targetDirectory: string
  extractedFiles: string[]
  totalFiles: number
}

export async function extractZipArchive(options: ExtractZipOptions): Promise<ExtractZipResult> {
  configure({ useWebWorkers: false })

  const archiveName = options.archiveName ?? (options.file instanceof File ? options.file.name : "archive.zip")
  const reader = new ZipReader(new BlobReader(options.file))

  try {
    const entries = await reader.getEntries({ filenameValidation: "tolerant" })

    // Abort early if the archive contains encrypted entries before writing anything
    for (const entry of entries) {
      if ("encrypted" in entry && entry.encrypted) {
        throw new Error("Archive contains password-protected or encrypted entries")
      }
    }

    type ZipFileEntry = Extract<(typeof entries)[number], { getData: (...args: any[]) => any }>
    const validFileEntries: { entry: ZipFileEntry; cleanPath: string }[] = []

    for (const entry of entries) {
      if (entry.directory || entry.filename.endsWith("/") || entry.filename.endsWith("\\")) continue
      if (!("getData" in entry) || typeof entry.getData !== "function") continue

      const cleanPath = sanitizeZipPath(entry.filename)
      if (cleanPath) {
        validFileEntries.push({ entry: entry as ZipFileEntry, cleanPath })
      }
    }

    const totalFiles = validFileEntries.length
    const extractedFiles: string[] = []

    let current = 0
    for (const { entry, cleanPath } of validFileEntries) {
      if (options.signal?.aborted) {
        throw new DOMException("Extraction aborted", "AbortError")
      }

      if ("encrypted" in entry && entry.encrypted) {
        throw new Error("Archive contains password-protected or encrypted entries")
      }

      const writer = new Uint8ArrayWriter()
      const data = await entry.getData(writer)

      await writeWorkspaceFile(
        options.serverUrl,
        options.serverPassword,
        options.targetDirectory,
        cleanPath,
        data,
        options.signal,
      )

      extractedFiles.push(cleanPath)
      current++
      options.onProgress?.(current, totalFiles, cleanPath)
    }

    return {
      archiveName,
      targetDirectory: options.targetDirectory,
      extractedFiles,
      totalFiles: extractedFiles.length,
    }
  } finally {
    await reader.close()
  }
}

export type ZipUploadContext = {
  targetDirectory: string
  serverUrl: string
  serverPassword?: string
  onToast: (options: ZipToastOptions) => unknown
  dismissToast?: (id: unknown) => void
  injectManifest: (manifest: string) => void
}

export async function handleZipUpload(file: File | Blob, context: ZipUploadContext): Promise<ExtractZipResult | null> {
  const archiveName = file instanceof File ? file.name : "archive.zip"
  let activeToastId: unknown

  try {
    activeToastId = context.onToast({
      title: "Extracting archive... (0 files)",
      description: archiveName,
      variant: "loading",
      persistent: true,
    })

    const result = await extractZipArchive({
      file,
      archiveName,
      targetDirectory: context.targetDirectory,
      serverUrl: context.serverUrl,
      serverPassword: context.serverPassword,
      onProgress: (current, total) => {
        if (activeToastId !== undefined && context.dismissToast) {
          context.dismissToast(activeToastId)
        }
        activeToastId = context.onToast({
          title: `Extracting archive... (${current}/${total} files)`,
          description: archiveName,
          variant: "loading",
          persistent: true,
        })
      },
    })

    if (activeToastId !== undefined && context.dismissToast) {
      context.dismissToast(activeToastId)
      activeToastId = undefined
    }

    context.onToast({
      title: `Extracted ${archiveName}`,
      description: `Extracted ${result.totalFiles} files to workspace`,
      variant: "success",
    })

    const manifest = formatArchiveManifest(archiveName, context.targetDirectory, result.extractedFiles)
    context.injectManifest(manifest)

    return result
  } catch (error) {
    if (activeToastId !== undefined && context.dismissToast) {
      context.dismissToast(activeToastId)
      activeToastId = undefined
    }

    context.onToast({
      title: `Failed to extract ${archiveName}`,
      description: error instanceof Error ? error.message : String(error),
      variant: "error",
    })

    return null
  }
}
