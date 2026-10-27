import { describe, expect, it, mock } from "bun:test"
import { Uint8ArrayWriter, ZipWriter, TextReader } from "@zip.js/zip.js"
import {
  isZipFile,
  sanitizeZipPath,
  formatArchiveManifest,
  extractZipArchive,
  handleZipUpload,
  type ZipToastOptions,
} from "./zip"

async function createSampleZipBlob(
  entries: { name: string; content?: string; directory?: boolean; password?: string }[],
): Promise<Blob> {
  const uint8Writer = new Uint8ArrayWriter()
  const zipWriter = new ZipWriter(uint8Writer)

  for (const entry of entries) {
    if (entry.directory) {
      await zipWriter.add(entry.name, undefined, { directory: true })
    } else {
      await zipWriter.add(
        entry.name,
        new TextReader(entry.content ?? ""),
        entry.password ? { password: entry.password } : undefined,
      )
    }
  }

  await zipWriter.close()
  const data = await uint8Writer.getData()
  return new Blob([data], { type: "application/zip" })
}

describe("zip utilities", () => {
  describe("isZipFile", () => {
    it("recognizes .zip extension in various cases", () => {
      expect(isZipFile({ name: "archive.zip" })).toBe(true)
      expect(isZipFile({ name: "PROJECT.ZIP" })).toBe(true)
      expect(isZipFile({ name: "bundle.tar.zip" })).toBe(true)
      expect(isZipFile({ name: "test.zip.old" })).toBe(false)
      expect(isZipFile({ name: "zip" })).toBe(false)
    })

    it("recognizes zip mime types", () => {
      expect(isZipFile({ type: "application/zip" })).toBe(true)
      expect(isZipFile({ type: "application/x-zip-compressed" })).toBe(true)
      expect(isZipFile({ type: "application/x-zip" })).toBe(true)
      expect(isZipFile({ type: "multipart/x-zip" })).toBe(true)
      expect(isZipFile({ type: "APPLICATION/ZIP" })).toBe(true)
    })

    it("rejects non-zip files and handles missing properties safely", () => {
      expect(isZipFile({ name: "document.pdf", type: "application/pdf" })).toBe(false)
      expect(isZipFile({ name: "image.png", type: "image/png" })).toBe(false)
      expect(isZipFile({ name: "archive.tar.gz", type: "application/gzip" })).toBe(false)
      expect(isZipFile({})).toBe(false)
      expect(isZipFile({ name: undefined, type: undefined })).toBe(false)
      expect(isZipFile(null)).toBe(false)
      expect(isZipFile(undefined)).toBe(false)
    })
  })

  describe("sanitizeZipPath", () => {
    it("preserves valid relative paths and file names", () => {
      expect(sanitizeZipPath("index.ts")).toBe("index.ts")
      expect(sanitizeZipPath("src/components/button.tsx")).toBe("src/components/button.tsx")
      expect(sanitizeZipPath("a/b/c/d/e.txt")).toBe("a/b/c/d/e.txt")
    })

    it("normalizes Windows backslashes", () => {
      expect(sanitizeZipPath("src\\components\\button.tsx")).toBe("src/components/button.tsx")
      expect(sanitizeZipPath("nested\\dir\\file.txt")).toBe("nested/dir/file.txt")
    })

    it("strips leading slashes and drive letters", () => {
      expect(sanitizeZipPath("/etc/passwd")).toBe("etc/passwd")
      expect(sanitizeZipPath("///root/test.txt")).toBe("root/test.txt")
      expect(sanitizeZipPath("C:\\Windows\\System32\\cmd.exe")).toBe("Windows/System32/cmd.exe")
      expect(sanitizeZipPath("D:/projects/code.ts")).toBe("projects/code.ts")
    })

    it("strips null bytes and control characters", () => {
      expect(sanitizeZipPath("malicious\0path/file.txt")).toBe("maliciouspath/file.txt")
      expect(sanitizeZipPath("evil\r\npath/\tfile.txt")).toBe("evilpath/file.txt")
    })

    it("preserves valid Unicode filenames and paths", () => {
      expect(sanitizeZipPath("src/données/résumé.txt")).toBe("src/données/résumé.txt")
      expect(sanitizeZipPath("日本語/テスト.json")).toBe("日本語/テスト.json")
      expect(sanitizeZipPath("📁/файл.md")).toBe("📁/файл.md")
    })

    it("safely handles valid internal relative navigation", () => {
      expect(sanitizeZipPath("a/b/../c.txt")).toBe("a/c.txt")
      expect(sanitizeZipPath("a/./b/./c.txt")).toBe("a/b/c.txt")
    })

    it("blocks directory traversal attempts by returning null", () => {
      expect(sanitizeZipPath("../secret.txt")).toBeNull()
      expect(sanitizeZipPath("../../passwords.json")).toBeNull()
      expect(sanitizeZipPath("foo/../../bar.txt")).toBeNull()
      expect(sanitizeZipPath("a/b/c/../../../..")).toBeNull()
      expect(sanitizeZipPath("..")).toBeNull()
      expect(sanitizeZipPath(".")).toBeNull()
      expect(sanitizeZipPath("")).toBeNull()
      expect(sanitizeZipPath("   ")).toBeNull()
      expect(sanitizeZipPath("///")).toBeNull()
    })

    it("blocks NTFS Alternate Data Streams and colons in path segments", () => {
      expect(sanitizeZipPath("file.txt:stream")).toBeNull()
      expect(sanitizeZipPath("folder/file.txt:hidden")).toBeNull()
      expect(sanitizeZipPath("foo/C:/bar.txt")).toBeNull()
    })

    it("blocks Windows reserved device names and allows valid names with reserved prefixes", () => {
      expect(sanitizeZipPath("CON")).toBeNull()
      expect(sanitizeZipPath("con.txt")).toBeNull()
      expect(sanitizeZipPath("aux.json")).toBeNull()
      expect(sanitizeZipPath("src/prn/data.ts")).toBeNull()
      expect(sanitizeZipPath("nul")).toBeNull()
      expect(sanitizeZipPath("com0")).toBeNull()
      expect(sanitizeZipPath("com1.txt")).toBeNull()
      expect(sanitizeZipPath("lpt0")).toBeNull()
      expect(sanitizeZipPath("lpt9")).toBeNull()
      expect(sanitizeZipPath("conin$")).toBeNull()
      expect(sanitizeZipPath("conout$.txt")).toBeNull()
      expect(sanitizeZipPath("clock$")).toBeNull()
      expect(sanitizeZipPath("console.ts")).toBe("console.ts")
      expect(sanitizeZipPath("auxiliary.ts")).toBe("auxiliary.ts")
      expect(sanitizeZipPath("context.json")).toBe("context.json")
    })

    it("blocks path segments with trailing dots, multiple dots, and illegal characters", () => {
      expect(sanitizeZipPath("file.txt.")).toBeNull()
      expect(sanitizeZipPath("dir./file.txt")).toBeNull()
      expect(sanitizeZipPath("...")).toBeNull()
      expect(sanitizeZipPath("....")).toBeNull()
      expect(sanitizeZipPath("src/.../file.txt")).toBeNull()
      expect(sanitizeZipPath("<tag>.html")).toBeNull()
      expect(sanitizeZipPath("file*name.txt")).toBeNull()
      expect(sanitizeZipPath("query?param.ts")).toBeNull()
      expect(sanitizeZipPath("pipe|name.txt")).toBeNull()
      expect(sanitizeZipPath('quote"name.txt')).toBeNull()
    })

    it("rejects excessively long paths exceeding 4096 characters", () => {
      const longPath = "a/".repeat(2050) + "file.txt"
      expect(sanitizeZipPath(longPath)).toBeNull()
    })
  })

  describe("formatArchiveManifest", () => {
    it("formats manifest for an empty archive", () => {
      const manifest = formatArchiveManifest("empty.zip", "/workspace", [])
      expect(manifest).toContain("### Extracted Archive: empty.zip")
      expect(manifest).toContain("- **Destination:** `/workspace`")
      expect(manifest).toContain("- **Extracted Files (0):**")
      expect(manifest).toContain("- (empty archive)")
    })

    it("falls back to (workspace root) when targetDirectory is empty or undefined", () => {
      const manifestEmpty = formatArchiveManifest("root.zip", "", ["index.ts"])
      expect(manifestEmpty).toContain("- **Destination:** `(workspace root)`")
      const manifestUndefined = formatArchiveManifest("root.zip", undefined as unknown as string, ["index.ts"])
      expect(manifestUndefined).toContain("- **Destination:** `(workspace root)`")
    })

    it("formats manifest listing files when <= 50", () => {
      const files = ["file1.txt", "src/index.ts", "package.json"]
      const manifest = formatArchiveManifest("project.zip", "/app", files)
      expect(manifest).toContain("### Extracted Archive: project.zip")
      expect(manifest).toContain("- **Destination:** `/app`")
      expect(manifest).toContain("- **Extracted Files (3):**")
      expect(manifest).toContain("- `file1.txt`")
      expect(manifest).toContain("- `src/index.ts`")
      expect(manifest).toContain("- `package.json`")
    })

    it("truncates file listing and shows remainder count when > 50 files", () => {
      const files = Array.from({ length: 65 }, (_, i) => `src/file_${i + 1}.ts`)
      const manifest = formatArchiveManifest("huge.zip", "/root", files)
      expect(manifest).toContain("### Extracted Archive: huge.zip")
      expect(manifest).toContain("- **Extracted Files (65):**")
      expect(manifest).toContain("- `src/file_1.ts`")
      expect(manifest).toContain("- `src/file_50.ts`")
      expect(manifest).not.toContain("- `src/file_51.ts`")
      expect(manifest).toContain("- ... and 15 more files")
    })
  })

  describe("extractZipArchive", () => {
    it("extracts entries, writes files to workspace API, and reports progress", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "folder/", directory: true },
        { name: "folder/hello.txt", content: "Hello World" },
        { name: "config.json", content: '{"active":true}' },
      ])

      const writtenCalls: { url: string; path: string; directory: string; bodyText: string }[] = []
      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
        const urlStr = typeof input === "string" ? input : input.toString()
        const parsed = new URL(urlStr)
        const path = parsed.searchParams.get("path") ?? ""
        const directory = parsed.searchParams.get("location[directory]") ?? ""
        let bodyText = ""
        if (init?.body instanceof Uint8Array) {
          bodyText = new TextDecoder().decode(init.body)
        } else if (init?.body && typeof init.body === "object" && "text" in init.body) {
          bodyText = await (init.body as Blob).text()
        } else if (typeof init?.body === "string") {
          bodyText = init.body
        }
        writtenCalls.push({ url: urlStr, path, directory, bodyText })

        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      const progressHistory: { current: number; total: number; path: string }[] = []

      try {
        const result = await extractZipArchive({
          file: zipBlob,
          archiveName: "sample.zip",
          targetDirectory: "/home/user/project",
          serverUrl: "http://localhost:4096",
          serverPassword: "secret-token",
          onProgress: (current, total, path) => {
            progressHistory.push({ current, total, path })
          },
        })

        expect(result.archiveName).toBe("sample.zip")
        expect(result.targetDirectory).toBe("/home/user/project")
        expect(result.totalFiles).toBe(2)
        expect(result.extractedFiles).toEqual(["folder/hello.txt", "config.json"])

        expect(writtenCalls.length).toBe(2)
        expect(writtenCalls[0].directory).toBe("/home/user/project")
        expect(writtenCalls[0].path).toBe("/home/user/project/folder/hello.txt")
        expect(writtenCalls[0].bodyText).toBe("Hello World")

        expect(writtenCalls[1].directory).toBe("/home/user/project")
        expect(writtenCalls[1].path).toBe("/home/user/project/config.json")
        expect(writtenCalls[1].bodyText).toBe('{"active":true}')

        expect(progressHistory.length).toBe(2)
        expect(progressHistory[0]).toEqual({ current: 1, total: 2, path: "folder/hello.txt" })
        expect(progressHistory[1]).toEqual({ current: 2, total: 2, path: "config.json" })
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("filters out traversal attempts and invalid entries during extraction", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "../outside.txt", content: "evil" },
        { name: "valid.txt", content: "safe" },
      ])

      const writtenCalls: string[] = []
      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async (input: RequestInfo | URL) => {
        const urlStr = typeof input === "string" ? input : input.toString()
        const parsed = new URL(urlStr)
        writtenCalls.push(parsed.searchParams.get("path") ?? "")
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      try {
        const result = await extractZipArchive({
          file: zipBlob,
          targetDirectory: "/home/user/repo",
          serverUrl: "http://localhost:4096",
        })

        expect(result.extractedFiles).toEqual(["valid.txt"])
        expect(writtenCalls).toEqual(["/home/user/repo/valid.txt"])
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("throws when workspace write fails", async () => {
      const zipBlob = await createSampleZipBlob([{ name: "test.txt", content: "data" }])

      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async () => {
        return new Response("Permission denied", { status: 403, statusText: "Forbidden" })
      }) as unknown as typeof fetch

      try {
        await expect(
          extractZipArchive({
            file: zipBlob,
            targetDirectory: "/home/user/repo",
            serverUrl: "http://localhost:4096",
          }),
        ).rejects.toThrow("Failed to write test.txt: Forbidden")
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("pre-filters traversal entries so total count accurately reflects extractable files in progress", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "../outside.txt", content: "evil" },
        { name: "valid.txt", content: "safe" },
      ])

      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(
        async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
      ) as unknown as typeof fetch

      const progressHistory: { current: number; total: number; path: string }[] = []

      try {
        const result = await extractZipArchive({
          file: zipBlob,
          targetDirectory: "/home/user/repo",
          serverUrl: "http://localhost:4096",
          onProgress: (current, total, path) => {
            progressHistory.push({ current, total, path })
          },
        })

        expect(result.extractedFiles).toEqual(["valid.txt"])
        expect(result.totalFiles).toBe(1)
        expect(progressHistory).toEqual([{ current: 1, total: 1, path: "valid.txt" }])
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("rejects password-protected / encrypted zip archives with clear error messaging before any writes occur", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "valid_first.txt", content: "safe unencrypted content" },
        { name: "secret.txt", content: "hidden content", password: "pwd" },
      ])

      let writeCallCount = 0
      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async () => {
        writeCallCount++
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      try {
        await expect(
          extractZipArchive({
            file: zipBlob,
            targetDirectory: "/home/user/repo",
            serverUrl: "http://localhost:4096",
          }),
        ).rejects.toThrow("Archive contains password-protected or encrypted entries")

        // Crucial: no files should have been written to the workspace before aborting
        expect(writeCallCount).toBe(0)
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("skips directory entries ending with backslashes", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "windows\\nested\\folder\\", directory: true },
        { name: "windows\\nested\\folder\\file.txt", content: "nested content" },
      ])

      const writtenPaths: string[] = []
      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async (input: RequestInfo | URL) => {
        const parsed = new URL(typeof input === "string" ? input : input.toString())
        writtenPaths.push(parsed.searchParams.get("path") ?? "")
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      try {
        const result = await extractZipArchive({
          file: zipBlob,
          targetDirectory: "/workspace",
          serverUrl: "http://localhost:4096",
        })

        expect(result.extractedFiles).toEqual(["windows/nested/folder/file.txt"])
        expect(result.totalFiles).toBe(1)
        expect(writtenPaths).toEqual(["/workspace/windows/nested/folder/file.txt"])
      } finally {
        globalThis.fetch = originalFetch
      }
    })
  })

  describe("handleZipUpload", () => {
    it("coordinates extraction, progress toasts, success toast, and manifest prompt injection", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "index.js", content: "console.log('test')" },
      ])
      const file = new File([zipBlob], "my-app.zip", { type: "application/zip" })

      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async () => {
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      const toasts: ZipToastOptions[] = []
      let injectedManifest = ""

      try {
        const result = await handleZipUpload(file, {
          targetDirectory: "/workspace/my-app",
          serverUrl: "http://localhost:4096",
          onToast: (toast) => toasts.push(toast),
          injectManifest: (manifest) => {
            injectedManifest = manifest
          },
        })

        expect(result).not.toBeNull()
        expect(result?.archiveName).toBe("my-app.zip")
        expect(result?.totalFiles).toBe(1)

        // Verifying toast lifecycle
        expect(toasts.length).toBeGreaterThanOrEqual(3)
        expect(toasts[0]).toEqual({
          title: "Extracting archive... (0 files)",
          description: "my-app.zip",
          variant: "loading",
          persistent: true,
        })
        expect(toasts[1]).toEqual({
          title: "Extracting archive... (1/1 files)",
          description: "my-app.zip",
          variant: "loading",
          persistent: true,
        })
        expect(toasts[2]).toEqual({
          title: "Extracted my-app.zip",
          description: "Extracted 1 files to workspace",
          variant: "success",
        })

        // Verifying prompt manifest injection
        expect(injectedManifest).toContain("### Extracted Archive: my-app.zip")
        expect(injectedManifest).toContain("- `index.js`")
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("properly manages toast dismissal lifecycle across progress updates and success", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "file1.txt", content: "one" },
        { name: "file2.txt", content: "two" },
      ])
      const file = new File([zipBlob], "two-files.zip", { type: "application/zip" })

      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async () => {
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      let toastCounter = 0
      const dismissedIds: unknown[] = []
      const toasts: { id: number; toast: ZipToastOptions }[] = []

      try {
        const result = await handleZipUpload(file, {
          targetDirectory: "/workspace",
          serverUrl: "http://localhost:4096",
          onToast: (toast) => {
            const id = ++toastCounter
            toasts.push({ id, toast })
            return id
          },
          dismissToast: (id) => {
            dismissedIds.push(id)
          },
          injectManifest: () => {},
        })

        expect(result).not.toBeNull()
        expect(result?.totalFiles).toBe(2)

        // Initial loading toast (id 1) and progress toasts (id 2, id 3)
        // Check that dismissedIds contains id 1, 2, and 3 before success toast is presented
        expect(dismissedIds).toContain(1)
        expect(dismissedIds).toContain(2)
        expect(dismissedIds).toContain(3)
        expect(toasts.at(-1)?.toast.variant).toBe("success")
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("extracts deep nested directory hierarchies accurately", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "src/nested/deep/level/code.ts", content: "export const x = 42;" },
      ])
      const file = new File([zipBlob], "deep.zip", { type: "application/zip" })

      const writtenPaths: string[] = []
      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async (input: RequestInfo | URL) => {
        const parsed = new URL(typeof input === "string" ? input : input.toString())
        writtenPaths.push(parsed.searchParams.get("path") ?? "")
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      try {
        const result = await handleZipUpload(file, {
          targetDirectory: "/project",
          serverUrl: "http://localhost:4096",
          onToast: () => {},
          injectManifest: () => {},
        })

        expect(result).not.toBeNull()
        expect(result?.extractedFiles).toEqual(["src/nested/deep/level/code.ts"])
        expect(writtenPaths[0]).toBe("/project/src/nested/deep/level/code.ts")
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("gracefully catches 0-byte empty archives and issues error toast while cleaning up active toast", async () => {
      const emptyFile = new File([], "empty.zip", { type: "application/zip" })
      const dismissed: unknown[] = []
      const toasts: ZipToastOptions[] = []

      const result = await handleZipUpload(emptyFile, {
        targetDirectory: "/workspace",
        serverUrl: "http://localhost:4096",
        onToast: (toast) => {
          toasts.push(toast)
          return 999
        },
        dismissToast: (id) => {
          dismissed.push(id)
        },
        injectManifest: () => {},
      })

      expect(result).toBeNull()
      expect(dismissed).toContain(999)
      const errorToast = toasts.find((t) => t.variant === "error")
      expect(errorToast).toBeDefined()
      expect(errorToast?.title).toBe("Failed to extract empty.zip")
    })

    it("gracefully catches corrupt/invalid zip archives without crashing and issues error toast", async () => {
      const corruptFile = new File(["not a valid zip file content at all"], "broken.zip", {
        type: "application/zip",
      })

      const toasts: ZipToastOptions[] = []
      let injected = false

      const result = await handleZipUpload(corruptFile, {
        targetDirectory: "/workspace",
        serverUrl: "http://localhost:4096",
        onToast: (toast) => toasts.push(toast),
        injectManifest: () => {
          injected = true
        },
      })

      expect(result).toBeNull()
      expect(injected).toBe(false)

      const errorToast = toasts.find((t) => t.variant === "error")
      expect(errorToast).toBeDefined()
      expect(errorToast?.title).toBe("Failed to extract broken.zip")
      expect(errorToast?.description).toBeDefined()
    })

    it("gracefully catches encrypted/password-protected archives, cleans up active toast, and issues error toast", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "locked.txt", content: "confidential", password: "secret-key" },
      ])
      const file = new File([zipBlob], "locked.zip", { type: "application/zip" })

      const dismissed: unknown[] = []
      const toasts: ZipToastOptions[] = []
      let manifestInjected = false

      const result = await handleZipUpload(file, {
        targetDirectory: "/workspace",
        serverUrl: "http://localhost:4096",
        onToast: (toast) => {
          toasts.push(toast)
          return 777
        },
        dismissToast: (id) => {
          dismissed.push(id)
        },
        injectManifest: () => {
          manifestInjected = true
        },
      })

      expect(result).toBeNull()
      expect(manifestInjected).toBe(false)
      expect(dismissed).toContain(777)
      const errorToast = toasts.find((t) => t.variant === "error")
      expect(errorToast).toBeDefined()
      expect(errorToast?.title).toBe("Failed to extract locked.zip")
      expect(errorToast?.description).toContain("encrypted")
    })

    it("omits location[directory] query param when targetDirectory is empty", async () => {
      const zipBlob = await createSampleZipBlob([{ name: "root.txt", content: "root content" }])
      const file = new File([zipBlob], "root.zip", { type: "application/zip" })

      let capturedUrl = ""
      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(async (input: RequestInfo | URL) => {
        capturedUrl = typeof input === "string" ? input : input.toString()
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      }) as unknown as typeof fetch

      try {
        const result = await handleZipUpload(file, {
          targetDirectory: "",
          serverUrl: "http://localhost:4096",
          onToast: () => {},
          injectManifest: () => {},
        })

        expect(result).not.toBeNull()
        const parsed = new URL(capturedUrl)
        expect(parsed.searchParams.has("location[directory]")).toBe(false)
        expect(parsed.searchParams.get("path")).toBe("root.txt")
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    it("succeeds cleanly without throwing when dismissToast is omitted from context", async () => {
      const zipBlob = await createSampleZipBlob([
        { name: "a.txt", content: "AAA" },
        { name: "b.txt", content: "BBB" },
      ])
      const file = new File([zipBlob], "no-dismiss.zip", { type: "application/zip" })

      const originalFetch = globalThis.fetch
      globalThis.fetch = mock(
        async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
      ) as unknown as typeof fetch

      const toasts: ZipToastOptions[] = []

      try {
        const result = await handleZipUpload(file, {
          targetDirectory: "/workspace",
          serverUrl: "http://localhost:4096",
          onToast: (toast) => {
            toasts.push(toast)
            return toasts.length
          },
          // dismissToast intentionally omitted
          injectManifest: () => {},
        })

        expect(result).not.toBeNull()
        expect(result?.totalFiles).toBe(2)
        expect(toasts.some((t) => t.variant === "success")).toBe(true)
      } finally {
        globalThis.fetch = originalFetch
      }
    })
  })
})
