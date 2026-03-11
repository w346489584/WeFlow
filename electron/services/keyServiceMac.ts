import { app, shell } from 'electron'
import { join } from 'path'
import { existsSync, readdirSync, readFileSync, statSync } from 'fs'
import { execFile, spawn } from 'child_process'
import { promisify } from 'util'

type DbKeyResult = { success: boolean; key?: string; error?: string; logs?: string[] }
type ImageKeyResult = { success: boolean; xorKey?: number; aesKey?: string; error?: string }
const execFileAsync = promisify(execFile)

export class KeyServiceMac {
  private koffi: any = null
  private lib: any = null
  private initialized = false

  private GetDbKey: any = null
  private ScanMemoryForImageKey: any = null
  private FreeString: any = null
  private ListWeChatProcesses: any = null

  private getHelperPath(): string {
    const isPackaged = app.isPackaged
    const candidates: string[] = []

    if (process.env.WX_KEY_HELPER_PATH) {
      candidates.push(process.env.WX_KEY_HELPER_PATH)
    }

    if (isPackaged) {
      candidates.push(join(process.resourcesPath, 'resources', 'xkey_helper'))
      candidates.push(join(process.resourcesPath, 'xkey_helper'))
    } else {
      const cwd = process.cwd()
      candidates.push(join(cwd, 'resources', 'xkey_helper'))
      candidates.push(join(cwd, 'Xkey', 'build', 'xkey_helper'))
      candidates.push(join(app.getAppPath(), 'resources', 'xkey_helper'))
    }

    for (const path of candidates) {
      if (existsSync(path)) return path
    }

    throw new Error('xkey_helper not found')
  }

  private getDylibPath(): string {
    const isPackaged = app.isPackaged
    const candidates: string[] = []

    if (process.env.WX_KEY_DYLIB_PATH) {
      candidates.push(process.env.WX_KEY_DYLIB_PATH)
    }

    if (isPackaged) {
      candidates.push(join(process.resourcesPath, 'resources', 'libwx_key.dylib'))
      candidates.push(join(process.resourcesPath, 'libwx_key.dylib'))
    } else {
      const cwd = process.cwd()
      candidates.push(join(cwd, 'resources', 'libwx_key.dylib'))
      candidates.push(join(app.getAppPath(), 'resources', 'libwx_key.dylib'))
    }

    for (const path of candidates) {
      if (existsSync(path)) return path
    }

    throw new Error('libwx_key.dylib not found')
  }

  async initialize(): Promise<void> {
    if (this.initialized) return

    try {
      this.koffi = require('koffi')
      const dylibPath = this.getDylibPath()

      if (!existsSync(dylibPath)) {
        throw new Error('libwx_key.dylib not found: ' + dylibPath)
      }

      this.lib = this.koffi.load(dylibPath)

      this.GetDbKey = this.lib.func('const char* GetDbKey()')
      this.ScanMemoryForImageKey = this.lib.func('const char* ScanMemoryForImageKey(int pid, const char* ciphertext)')
      this.FreeString = this.lib.func('void FreeString(const char* str)')
      this.ListWeChatProcesses = this.lib.func('const char* ListWeChatProcesses()')

      this.initialized = true
    } catch (e: any) {
      throw new Error('Failed to initialize KeyServiceMac: ' + e.message)
    }
  }

  async autoGetDbKey(
    timeoutMs = 60_000,
    onStatus?: (message: string, level: number) => void
  ): Promise<DbKeyResult> {
    try {
      onStatus?.('正在获取数据库密钥...', 0)
      let parsed = await this.getDbKeyParsed(timeoutMs, onStatus)
      console.log('[KeyServiceMac] GetDbKey returned:', parsed.raw)

      // ATTACH_FAILED 时自动走图形化授权，再重试一次
      if (!parsed.success && parsed.code === 'ATTACH_FAILED') {
        onStatus?.('检测到调试权限不足，正在请求系统授权...', 0)
        const permissionOk = await this.enableDebugPermissionWithPrompt()
        if (permissionOk) {
          onStatus?.('授权完成，正在重试获取密钥...', 0)
          parsed = await this.getDbKeyParsed(timeoutMs, onStatus)
          console.log('[KeyServiceMac] GetDbKey retry returned:', parsed.raw)
        } else {
          onStatus?.('已取消系统授权', 2)
          return { success: false, error: '已取消系统授权' }
        }
      }

      if (!parsed.success && parsed.code === 'ATTACH_FAILED') {
        // DevToolsSecurity 仍不足时，自动拉起开发者工具权限页面
        await this.openDeveloperToolsPrivacySettings()
        await this.revealCurrentExecutableInFinder()
        const msg = `无法附加到微信进程。已打开“开发者工具”设置，并在访达中定位当前运行程序。\n请在“隐私与安全性 -> 开发者工具”点击“+”添加并允许：${process.execPath}`
        onStatus?.(msg, 2)
        return { success: false, error: msg }
      }

      if (!parsed.success) {
        const errorMsg = this.mapDbKeyErrorMessage(parsed.code, parsed.detail)
        onStatus?.(errorMsg, 2)
        return { success: false, error: errorMsg }
      }

      onStatus?.('密钥获取成功', 1)
      return { success: true, key: parsed.key }
    } catch (e: any) {
      console.error('[KeyServiceMac] Error:', e)
      console.error('[KeyServiceMac] Stack:', e.stack)
      onStatus?.('获取失败: ' + e.message, 2)
      return { success: false, error: e.message }
    }
  }

  private parseDbKeyResult(raw: any): { success: boolean; key?: string; code?: string; detail?: string; raw: string } {
    const text = typeof raw === 'string' ? raw : ''
    if (!text) return { success: false, code: 'UNKNOWN', raw: text }
    if (!text.startsWith('ERROR:')) return { success: true, key: text, raw: text }

    const parts = text.split(':')
    return {
      success: false,
      code: parts[1] || 'UNKNOWN',
      detail: parts.slice(2).join(':') || undefined,
      raw: text
    }
  }

  private async getDbKeyParsed(
    timeoutMs: number,
    onStatus?: (message: string, level: number) => void
  ): Promise<{ success: boolean; key?: string; code?: string; detail?: string; raw: string }> {
    try {
      const helperResult = await this.getDbKeyByHelper(timeoutMs, onStatus)
      return this.parseDbKeyResult(helperResult)
    } catch (e: any) {
      console.warn('[KeyServiceMac] helper unavailable, fallback to dylib:', e?.message || e)
      if (!this.initialized) {
        await this.initialize()
      }
      return this.parseDbKeyResult(this.GetDbKey())
    }
  }

  private async getDbKeyByHelper(
    timeoutMs: number,
    onStatus?: (message: string, level: number) => void
  ): Promise<string> {
    const helperPath = this.getHelperPath()
    const waitMs = Math.max(timeoutMs, 30_000)
    return await new Promise<string>((resolve, reject) => {
      const child = spawn(helperPath, [String(waitMs)], { stdio: ['ignore', 'pipe', 'pipe'] })
      let stdout = ''
      let stderr = ''
      let stdoutBuf = ''
      let stderrBuf = ''
      let settled = false
      let killTimer: ReturnType<typeof setTimeout> | null = null
      let pidNotified = false
      let locatedNotified = false
      let hookNotified = false

      const done = (fn: () => void) => {
        if (settled) return
        settled = true
        if (killTimer) clearTimeout(killTimer)
        fn()
      }

      const processHelperLine = (line: string) => {
        if (!line) return
        console.log('[KeyServiceMac][helper][stderr]', line)
        const pidMatch = line.match(/Selected PID=(\d+)/)
        if (pidMatch && !pidNotified) {
          pidNotified = true
          onStatus?.(`已找到微信进程 PID=${pidMatch[1]}，正在定位目标函数...`, 0)
        }
        if (!locatedNotified && (line.includes('strict hit=') || line.includes('sink matched by strict semantic signature'))) {
          locatedNotified = true
          onStatus?.('已定位到目标函数，正在安装 Hook...', 0)
        }
        if (line.includes('hook installed @')) {
          hookNotified = true
          onStatus?.('Hook 已安装，等待微信触发密钥调用...', 0)
        }
        if (line.includes('[MASTER] hex64=')) {
          onStatus?.('检测到密钥回调，正在回填...', 0)
        }
      }

      child.stdout.on('data', (chunk: Buffer | string) => {
        const data = chunk.toString()
        stdout += data
        stdoutBuf += data
        const parts = stdoutBuf.split(/\r?\n/)
        stdoutBuf = parts.pop() || ''
      })

      child.stderr.on('data', (chunk: Buffer | string) => {
        const data = chunk.toString()
        stderr += data
        stderrBuf += data
        const parts = stderrBuf.split(/\r?\n/)
        stderrBuf = parts.pop() || ''
        for (const line of parts) processHelperLine(line.trim())
      })

      child.on('error', (err) => {
        done(() => reject(err))
      })

      child.on('close', () => {
        if (stderrBuf.trim()) processHelperLine(stderrBuf.trim())

        const lines = stdout.split(/\r?\n/).map(x => x.trim()).filter(Boolean)
        const last = lines[lines.length - 1]
        if (!last) {
          done(() => reject(new Error(stderr.trim() || 'helper returned empty output')))
          return
        }

        let payload: any
        try {
          payload = JSON.parse(last)
        } catch {
          done(() => reject(new Error('helper returned invalid json: ' + last)))
          return
        }

        if (payload?.success === true && typeof payload?.key === 'string') {
          if (!hookNotified) {
            onStatus?.('Hook 已触发，正在回填密钥...', 0)
          }
          done(() => resolve(payload.key))
          return
        }
        if (typeof payload?.result === 'string') {
          done(() => resolve(payload.result))
          return
        }
        done(() => reject(new Error('helper json missing key/result')))
      })

      killTimer = setTimeout(() => {
        try { child.kill('SIGTERM') } catch { }
        done(() => reject(new Error(`helper timeout after ${waitMs}ms`)))
      }, waitMs + 10_000)
    })
  }

  private mapDbKeyErrorMessage(code?: string, detail?: string): string {
    if (code === 'PROCESS_NOT_FOUND') return '微信进程未运行'
    if (code === 'ATTACH_FAILED') {
      const isDevElectron = process.execPath.includes('/node_modules/electron/')
      if ((detail || '').includes('task_for_pid:5')) {
        if (isDevElectron) {
          return `无法附加到微信进程（task_for_pid 被拒绝）。当前为开发环境 Electron：${process.execPath}\n建议使用打包后的 WeFlow.app（已携带调试 entitlements）再重试。`
        }
        return '无法附加到微信进程（task_for_pid 被系统拒绝）。请确认当前运行程序已正确签名并包含调试 entitlements。'
      }
      return `无法附加到进程 (${detail || ''})`
    }
    if (code === 'FRIDA_FAILED') {
      if ((detail || '').includes('FRIDA_TIMEOUT')) {
        return '定位已成功但在等待时间内未捕获到密钥调用。请保持微信前台并进行一次会话/数据库访问后重试。'
      }
      return `Frida 语义定位失败 (${detail || ''})`
    }
    if (code === 'HOOK_FAILED') {
      if ((detail || '').includes('HOOK_TIMEOUT')) {
        return 'Hook 已安装，但在等待时间内未触发目标函数。请保持微信前台并执行一次会话/数据库访问后重试。'
      }
      if ((detail || '').includes('attach_wait_timeout')) {
        return '附加调试器超时，未能进入 Hook 阶段。请确认微信处于可交互状态并重试。'
      }
      return `原生 Hook 失败 (${detail || ''})`
    }
    if (code === 'HOOK_TARGET_ONLY') {
      return `已定位到目标函数地址（${detail || ''}），但当前原生 C++ 仅完成定位，尚未完成远程 Hook 回调取 key 流程。`
    }
    if (code === 'SCAN_FAILED') return '内存扫描失败'
    return '未知错误'
  }

  private async enableDebugPermissionWithPrompt(): Promise<boolean> {
    const script = [
      'do shell script "/usr/sbin/DevToolsSecurity -enable" with administrator privileges'
    ]

    try {
      await execFileAsync('osascript', script.flatMap(line => ['-e', line]), {
        timeout: 30_000
      })
      return true
    } catch (e: any) {
      const msg = `${e?.stderr || ''}\n${e?.message || ''}`
      const cancelled = msg.includes('User canceled') || msg.includes('(-128)')
      if (!cancelled) {
        console.error('[KeyServiceMac] enableDebugPermissionWithPrompt failed:', msg)
      }
      return false
    }
  }

  private async openDeveloperToolsPrivacySettings(): Promise<void> {
    const url = 'x-apple.systempreferences:com.apple.preference.security?Privacy_DevTools'
    try {
      await shell.openExternal(url)
    } catch (e) {
      console.error('[KeyServiceMac] Failed to open settings page:', e)
    }
  }

  private async revealCurrentExecutableInFinder(): Promise<void> {
    try {
      shell.showItemInFolder(process.execPath)
    } catch (e) {
      console.error('[KeyServiceMac] Failed to reveal executable in Finder:', e)
    }
  }

  async autoGetImageKey(
    accountPath?: string,
    onStatus?: (message: string) => void,
    wxid?: string
  ): Promise<ImageKeyResult> {
    onStatus?.('macOS 请使用内存扫描方式')
    return { success: false, error: 'macOS 请使用内存扫描方式' }
  }

  async autoGetImageKeyByMemoryScan(
    userDir: string,
    onProgress?: (message: string) => void
  ): Promise<ImageKeyResult> {
    if (!this.initialized) {
      await this.initialize()
    }

    try {
      // 1. 查找模板文件获取密文和 XOR 密钥
      onProgress?.('正在查找模板文件...')
      let result = await this._findTemplateData(userDir, 32)
      let { ciphertext, xorKey } = result
      
      if (ciphertext && xorKey === null) {
        onProgress?.('未找到有效密钥，尝试扫描更多文件...')
        result = await this._findTemplateData(userDir, 100)
        xorKey = result.xorKey
      }
      
      if (!ciphertext) return { success: false, error: '未找到 V2 模板文件，请先在微信中查看几张图片' }
      if (xorKey === null) return { success: false, error: '未能从模板文件中计算出有效的 XOR 密钥' }

      onProgress?.(`XOR 密钥: 0x${xorKey.toString(16).padStart(2, '0')}，正在查找微信进程...`)

      // 2. 找微信 PID
      const pid = await this.findWeChatPid()
      if (!pid) return { success: false, error: '微信进程未运行，请先启动微信' }

      onProgress?.(`已找到微信进程 PID=${pid}，正在扫描内存...`)

      // 3. 持续轮询内存扫描
      const deadline = Date.now() + 60_000
      let scanCount = 0
      while (Date.now() < deadline) {
        scanCount++
        onProgress?.(`第 ${scanCount} 次扫描内存，请在微信中打开图片大图...`)
        const aesKey = await this._scanMemoryForAesKey(pid, ciphertext)
        if (aesKey) {
          onProgress?.('密钥获取成功')
          return { success: true, xorKey, aesKey }
        }
        await new Promise(r => setTimeout(r, 5000))
      }

      return { success: false, error: '60 秒内未找到 AES 密钥' }
    } catch (e: any) {
      return { success: false, error: `内存扫描失败: ${e.message}` }
    }
  }

  private async _findTemplateData(userDir: string, limit: number = 32): Promise<{ ciphertext: Buffer | null; xorKey: number | null }> {
    const V2_MAGIC = Buffer.from([0x07, 0x08, 0x56, 0x32, 0x08, 0x07])

    const collect = (dir: string, results: string[], maxFiles: number) => {
      if (results.length >= maxFiles) return
      try {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          if (results.length >= maxFiles) break
          const full = join(dir, entry.name)
          if (entry.isDirectory()) collect(full, results, maxFiles)
          else if (entry.isFile() && entry.name.endsWith('_t.dat')) results.push(full)
        }
      } catch { }
    }

    const files: string[] = []
    collect(userDir, files, limit)

    files.sort((a, b) => {
      try { return statSync(b).mtimeMs - statSync(a).mtimeMs } catch { return 0 }
    })

    let ciphertext: Buffer | null = null
    const tailCounts: Record<string, number> = {}

    for (const f of files.slice(0, 32)) {
      try {
        const data = readFileSync(f)
        if (data.length < 8) continue

        if (data.subarray(0, 6).equals(V2_MAGIC) && data.length >= 2) {
          const key = `${data[data.length - 2]}_${data[data.length - 1]}`
          tailCounts[key] = (tailCounts[key] ?? 0) + 1
        }

        if (!ciphertext && data.subarray(0, 6).equals(V2_MAGIC) && data.length >= 0x1F) {
          ciphertext = data.subarray(0xF, 0x1F)
        }
      } catch { }
    }

    let xorKey: number | null = null
    let maxCount = 0
    for (const [key, count] of Object.entries(tailCounts)) {
      if (count > maxCount) { 
        maxCount = count
        const [x, y] = key.split('_').map(Number)
        const k = x ^ 0xFF
        if (k === (y ^ 0xD9)) xorKey = k
      }
    }

    return { ciphertext, xorKey }
  }

  private async _scanMemoryForAesKey(pid: number, ciphertext: Buffer): Promise<string | null> {
    const ciphertextHex = ciphertext.toString('hex')
    const aesKey = this.ScanMemoryForImageKey(pid, ciphertextHex)
    return aesKey || null
  }

  private async findWeChatPid(): Promise<number | null> {
    const { execSync } = await import('child_process')
    try {
      const output = execSync('pgrep -x WeChat', { encoding: 'utf8' })
      const pid = parseInt(output.trim())
      return isNaN(pid) ? null : pid
    } catch {
      return null
    }
  }

  cleanup(): void {
    this.lib = null
    this.initialized = false
  }
}
