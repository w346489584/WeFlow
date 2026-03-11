import { join, dirname, basename } from 'path'
import { appendFileSync, existsSync, mkdirSync, readdirSync, statSync, readFileSync } from 'fs'
import { tmpdir } from 'os'

// DLL 初始化错误信息，用于帮助用户诊断问题
let lastDllInitError: string | null = null

/**
 * 解析 extra_buffer（protobuf）中的免打扰状态
 * - field 12 (tag 0x60): 值非0 = 免打扰
 * 折叠状态通过 contact.flag & 0x10000000 判断
 */
function parseExtraBuffer(raw: Buffer | string | null | undefined): { isMuted: boolean } {
  if (!raw) return { isMuted: false }
  // execQuery 返回的 BLOB 列是十六进制字符串，需要先解码
  const buf: Buffer = typeof raw === 'string' ? Buffer.from(raw, 'hex') : raw
  if (buf.length === 0) return { isMuted: false }
  let isMuted = false
  let i = 0
  const len = buf.length

  const readVarint = (): number => {
    let result = 0, shift = 0
    while (i < len) {
      const b = buf[i++]
      result |= (b & 0x7f) << shift
      shift += 7
      if (!(b & 0x80)) break
    }
    return result
  }

  while (i < len) {
    const tag = readVarint()
    const fieldNum = tag >>> 3
    const wireType = tag & 0x07
    if (wireType === 0) {
      const val = readVarint()
      if (fieldNum === 12 && val !== 0) isMuted = true
    } else if (wireType === 2) {
      const sz = readVarint()
      i += sz
    } else if (wireType === 5) { i += 4
    } else if (wireType === 1) { i += 8
    } else { break }
  }
  return { isMuted }
}
export function getLastDllInitError(): string | null {
  return lastDllInitError
}

export class WcdbCore {
  private resourcesPath: string | null = null
  private userDataPath: string | null = null
  private logEnabled = false
  private lib: any = null
  private koffi: any = null
  private initialized = false
  private handle: number | null = null
  private currentPath: string | null = null
  private currentKey: string | null = null
  private currentWxid: string | null = null
  private currentDbStoragePath: string | null = null

  // 函数引用
  private wcdbInitProtection: any = null
  private wcdbInit: any = null
  private wcdbShutdown: any = null
  private wcdbOpenAccount: any = null
  private wcdbCloseAccount: any = null
  private wcdbSetMyWxid: any = null
  private wcdbFreeString: any = null
  private wcdbUpdateMessage: any = null
  private wcdbDeleteMessage: any = null
  private wcdbGetSessions: any = null
  private wcdbGetMessages: any = null
  private wcdbGetMessageCount: any = null
  private wcdbGetDisplayNames: any = null
  private wcdbGetAvatarUrls: any = null
  private wcdbGetGroupMemberCount: any = null
  private wcdbGetGroupMemberCounts: any = null
  private wcdbGetGroupMembers: any = null
  private wcdbGetGroupNicknames: any = null
  private wcdbGetMessageTables: any = null
  private wcdbGetMessageMeta: any = null
  private wcdbGetContact: any = null
  private wcdbGetContactStatus: any = null
  private wcdbGetMessageTableStats: any = null
  private wcdbGetAggregateStats: any = null
  private wcdbGetAvailableYears: any = null
  private wcdbGetAnnualReportStats: any = null
  private wcdbGetAnnualReportExtras: any = null
  private wcdbGetDualReportStats: any = null
  private wcdbGetGroupStats: any = null
  private wcdbGetMessageDates: any = null
  private wcdbOpenMessageCursor: any = null
  private wcdbOpenMessageCursorLite: any = null
  private wcdbFetchMessageBatch: any = null
  private wcdbCloseMessageCursor: any = null
  private wcdbGetLogs: any = null
  private wcdbExecQuery: any = null
  private wcdbListMessageDbs: any = null
  private wcdbListMediaDbs: any = null
  private wcdbGetMessageById: any = null
  private wcdbGetEmoticonCdnUrl: any = null
  private wcdbGetDbStatus: any = null
  private wcdbGetVoiceData: any = null
  private wcdbGetSnsTimeline: any = null
  private wcdbGetSnsAnnualStats: any = null
  private wcdbInstallSnsBlockDeleteTrigger: any = null
  private wcdbUninstallSnsBlockDeleteTrigger: any = null
  private wcdbCheckSnsBlockDeleteTrigger: any = null
  private wcdbDeleteSnsPost: any = null
  private wcdbVerifyUser: any = null
  private wcdbStartMonitorPipe: any = null
  private wcdbStopMonitorPipe: any = null
  private wcdbGetMonitorPipeName: any = null
  private wcdbCloudInit: any = null
  private wcdbCloudReport: any = null
  private wcdbCloudStop: any = null

  private monitorPipeClient: any = null
  private monitorCallback: ((type: string, json: string) => void) | null = null
  private monitorReconnectTimer: any = null
  private monitorPipePath: string = ''


  private avatarUrlCache: Map<string, { url?: string; updatedAt: number }> = new Map()
  private readonly avatarCacheTtlMs = 10 * 60 * 1000
  private logTimer: NodeJS.Timeout | null = null
  private lastLogTail: string | null = null
  private lastResolvedLogPath: string | null = null

  setPaths(resourcesPath: string, userDataPath: string): void {
    this.resourcesPath = resourcesPath
    this.userDataPath = userDataPath
    this.writeLog(`[bootstrap] setPaths resourcesPath=${resourcesPath} userDataPath=${userDataPath}`, true)
  }

  setLogEnabled(enabled: boolean): void {
    this.logEnabled = enabled
    this.writeLog(`[bootstrap] setLogEnabled=${enabled ? '1' : '0'} env.WCDB_LOG_ENABLED=${process.env.WCDB_LOG_ENABLED || ''}`, true)
    if (this.isLogEnabled() && this.initialized) {
      this.startLogPolling()
    } else {
      this.stopLogPolling()
    }
  }

  // 使用命名管道 IPC (仅 Windows)
  startMonitor(callback: (type: string, json: string) => void): boolean {
    if (process.platform !== 'win32') {
      console.warn('[wcdbCore] Monitor not supported on macOS')
      return false
    }
    
    if (!this.wcdbStartMonitorPipe) {
      return false
    }

    this.monitorCallback = callback

    try {
      const result = this.wcdbStartMonitorPipe()
      if (result !== 0) {
        return false
      }

      // 从 DLL 获取动态管道名（含 PID）
      let pipePath = '\\\\.\\pipe\\weflow_monitor'
      if (this.wcdbGetMonitorPipeName) {
        try {
          const namePtr = [null as any]
          if (this.wcdbGetMonitorPipeName(namePtr) === 0 && namePtr[0]) {
            pipePath = this.koffi.decode(namePtr[0], 'char', -1)
            this.wcdbFreeString(namePtr[0])
          }
        } catch {}
      }

      this.connectMonitorPipe(pipePath)
      return true
    } catch (e) {
      console.error('[wcdbCore] startMonitor exception:', e)
      return false
    }
  }

  // 连接命名管道，支持断开后自动重连
  private connectMonitorPipe(pipePath: string) {
    this.monitorPipePath = pipePath
    const net = require('net')

    setTimeout(() => {
      if (!this.monitorCallback) return

      this.monitorPipeClient = net.createConnection(this.monitorPipePath, () => {
      })

      let buffer = ''
      this.monitorPipeClient.on('data', (data: Buffer) => {
        buffer += data.toString('utf8')
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''
        for (const line of lines) {
          if (line.trim()) {
            try {
              const parsed = JSON.parse(line)
              this.monitorCallback?.(parsed.action || 'update', line)
            } catch {
              this.monitorCallback?.('update', line)
            }
          }
        }
      })

      this.monitorPipeClient.on('error', () => {
      })

      this.monitorPipeClient.on('close', () => {
        this.monitorPipeClient = null
        this.scheduleReconnect()
      })
    }, 100)
  }

  // 定时重连
  private scheduleReconnect() {
    if (this.monitorReconnectTimer || !this.monitorCallback) return
    this.monitorReconnectTimer = setTimeout(() => {
      this.monitorReconnectTimer = null
      if (this.monitorCallback && !this.monitorPipeClient) {
        this.connectMonitorPipe(this.monitorPipePath)
      }
    }, 3000)
  }



  stopMonitor(): void {
    this.monitorCallback = null
    if (this.monitorReconnectTimer) {
      clearTimeout(this.monitorReconnectTimer)
      this.monitorReconnectTimer = null
    }
    if (this.monitorPipeClient) {
      this.monitorPipeClient.destroy()
      this.monitorPipeClient = null
    }
    if (this.wcdbStopMonitorPipe) {
      this.wcdbStopMonitorPipe()
    }
  }

  // 保留旧方法签名以兼容
  setMonitor(callback: (type: string, json: string) => void): boolean {
    return this.startMonitor(callback)
  }



  /**
   * 获取库文件路径（跨平台）
   */
  private getDllPath(): string {
    const isMac = process.platform === 'darwin'
    const libName = isMac ? 'libwcdb_api.dylib' : 'wcdb_api.dll'
    const subDir = isMac ? 'macos' : ''
    
    const envDllPath = process.env.WCDB_DLL_PATH
    if (envDllPath && envDllPath.length > 0) {
      return envDllPath
    }

    // 基础路径探测
    const isPackaged = typeof process['resourcesPath'] !== 'undefined'
    const resourcesPath = isPackaged ? process.resourcesPath : join(process.cwd(), 'resources')

    const candidates = [
      // 环境变量指定 resource 目录
      process.env.WCDB_RESOURCES_PATH ? join(process.env.WCDB_RESOURCES_PATH, subDir, libName) : null,
      // 显式 setPaths 设置的路径
      this.resourcesPath ? join(this.resourcesPath, subDir, libName) : null,
      // resources/macos/libwcdb_api.dylib 或 resources/wcdb_api.dll
      join(resourcesPath, 'resources', subDir, libName),
      // resources/libwcdb_api.dylib 或 resources/wcdb_api.dll (扁平结构)
      join(resourcesPath, subDir, libName),
      // CWD fallback
      join(process.cwd(), 'resources', subDir, libName)
    ].filter(Boolean) as string[]

    for (const path of candidates) {
      if (existsSync(path)) return path
    }

    return candidates[0] || libName
  }

  private isLogEnabled(): boolean {
    // 移除 Worker 线程的日志禁用逻辑，允许在 Worker 中记录日志
    if (process.env.WCDB_LOG_ENABLED === '1') return true
    return this.logEnabled
  }

  private writeLog(message: string, force = false): void {
    if (!force && !this.isLogEnabled()) return
    const line = `[${new Date().toISOString()}] ${message}`

    const candidates: string[] = []
    if (this.userDataPath) candidates.push(join(this.userDataPath, 'logs', 'wcdb.log'))
    if (process.env.WCDB_LOG_DIR) candidates.push(join(process.env.WCDB_LOG_DIR, 'logs', 'wcdb.log'))
    candidates.push(join(process.cwd(), 'logs', 'wcdb.log'))
    candidates.push(join(tmpdir(), 'weflow-wcdb.log'))

    const uniq = Array.from(new Set(candidates))
    for (const filePath of uniq) {
      try {
        const dir = dirname(filePath)
        if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
        appendFileSync(filePath, line + '\n', { encoding: 'utf8' })
        this.lastResolvedLogPath = filePath
        return
      } catch (e) {
        console.error(`[wcdbCore] writeLog failed path=${filePath}:`, e)
      }
    }

    console.error('[wcdbCore] writeLog failed for all candidates:', uniq.join(' | '))
  }

  private formatSqlForLog(sql: string, maxLen = 240): string {
    const compact = String(sql || '').replace(/\s+/g, ' ').trim()
    if (compact.length <= maxLen) return compact
    return compact.slice(0, maxLen) + '...'
  }

  private async dumpDbStatus(tag: string): Promise<void> {
    try {
      if (!this.ensureReady()) {
        this.writeLog(`[diag:${tag}] db_status skipped: not connected`, true)
        return
      }
      if (!this.wcdbGetDbStatus) {
        this.writeLog(`[diag:${tag}] db_status skipped: api not supported`, true)
        return
      }
      const outPtr = [null as any]
      const rc = this.wcdbGetDbStatus(this.handle, outPtr)
      if (rc !== 0 || !outPtr[0]) {
        this.writeLog(`[diag:${tag}] db_status failed rc=${rc} outPtr=${outPtr[0] ? 'set' : 'null'}`, true)
        return
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) {
        this.writeLog(`[diag:${tag}] db_status decode failed`, true)
        return
      }
      this.writeLog(`[diag:${tag}] db_status=${jsonStr}`, true)
    } catch (e) {
      this.writeLog(`[diag:${tag}] db_status exception: ${String(e)}`, true)
    }
  }

  private async runPostOpenDiagnostics(dbPath: string, dbStoragePath: string | null, sessionDbPath: string | null, wxid: string): Promise<void> {
    try {
      this.writeLog(`[diag:open] input dbPath=${dbPath} wxid=${wxid}`, true)
      this.writeLog(`[diag:open] resolved dbStorage=${dbStoragePath || 'null'}`, true)
      this.writeLog(`[diag:open] resolved sessionDb=${sessionDbPath || 'null'}`, true)
      if (!dbStoragePath) return
      try {
        const entries = readdirSync(dbStoragePath)
        const sample = entries.slice(0, 20).join(',')
        this.writeLog(`[diag:open] dbStorage entries(${entries.length}) sample=${sample}`, true)
      } catch (e) {
        this.writeLog(`[diag:open] list dbStorage failed: ${String(e)}`, true)
      }

      const contactProbe = await this.execQuery(
        'contact',
        null,
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 50"
      )
      if (contactProbe.success) {
        const names = (contactProbe.rows || []).map((r: any) => String(r?.name || '')).filter(Boolean)
        this.writeLog(`[diag:open] contact sqlite_master rows=${names.length} names=${names.join(',')}`, true)
      } else {
        this.writeLog(`[diag:open] contact sqlite_master failed: ${contactProbe.error || 'unknown'}`, true)
      }

      const contactCount = await this.execQuery('contact', null, 'SELECT COUNT(1) AS cnt FROM contact')
      if (contactCount.success && Array.isArray(contactCount.rows) && contactCount.rows.length > 0) {
        this.writeLog(`[diag:open] contact count=${String((contactCount.rows[0] as any)?.cnt ?? '')}`, true)
      } else {
        this.writeLog(`[diag:open] contact count failed: ${contactCount.error || 'unknown'}`, true)
      }
    } catch (e) {
      this.writeLog(`[diag:open] post-open diagnostics exception: ${String(e)}`, true)
    }
  }

  /**
   * 递归查找 session.db 文件
   */
  private findSessionDb(dir: string, depth = 0): string | null {
    if (depth > 5) return null

    try {
      const entries = readdirSync(dir)

      for (const entry of entries) {
        if (entry.toLowerCase() === 'session.db') {
          const fullPath = join(dir, entry)
          if (statSync(fullPath).isFile()) {
            return fullPath
          }
        }
      }

      for (const entry of entries) {
        const fullPath = join(dir, entry)
        try {
          if (statSync(fullPath).isDirectory()) {
            const found = this.findSessionDb(fullPath, depth + 1)
            if (found) return found
          }
        } catch { }
      }
    } catch (e) {
      console.error('查找 session.db 失败:', e)
    }

    return null
  }

  private resolveDbStoragePath(basePath: string, wxid: string): string | null {
    if (!basePath) return null
    const normalized = basePath.replace(/[\\\\/]+$/, '')
    if (normalized.toLowerCase().endsWith('db_storage') && existsSync(normalized)) {
      return normalized
    }
    const direct = join(normalized, 'db_storage')
    if (existsSync(direct)) {
      return direct
    }
    if (wxid) {
      const viaWxid = join(normalized, wxid, 'db_storage')
      if (existsSync(viaWxid)) {
        return viaWxid
      }
      // 兼容目录名包含额外后缀（如 wxid_xxx_1234）
      try {
        const entries = readdirSync(normalized)
        const lowerWxid = wxid.toLowerCase()
        const candidates = entries.filter((entry) => {
          const entryPath = join(normalized, entry)
          try {
            if (!statSync(entryPath).isDirectory()) return false
          } catch {
            return false
          }
          const lowerEntry = entry.toLowerCase()
          return lowerEntry === lowerWxid || lowerEntry.startsWith(`${lowerWxid}_`)
        })
        for (const entry of candidates) {
          const candidate = join(normalized, entry, 'db_storage')
          if (existsSync(candidate)) {
            return candidate
          }
        }
      } catch { }
    }
    return null
  }

  private isRealDbFileName(name: string): boolean {
    const lower = String(name || '').toLowerCase()
    if (!lower.endsWith('.db')) return false
    if (lower.endsWith('.db-shm')) return false
    if (lower.endsWith('.db-wal')) return false
    if (lower.endsWith('.db-journal')) return false
    return true
  }

  private resolveContactDbPath(): string | null {
    const dbStorage = this.currentDbStoragePath || this.resolveDbStoragePath(this.currentPath || '', this.currentWxid || '')
    if (!dbStorage) return null
    const contactDir = join(dbStorage, 'Contact')
    if (!existsSync(contactDir)) return null

    const preferred = [
      join(contactDir, 'contact.db'),
      join(contactDir, 'Contact.db')
    ]
    for (const p of preferred) {
      if (existsSync(p)) return p
    }

    try {
      const entries = readdirSync(contactDir)
      const cands = entries
        .filter((name) => this.isRealDbFileName(name))
        .map((name) => join(contactDir, name))
      if (cands.length > 0) return cands[0]
    } catch { }
    return null
  }

  private pickFirstStringField(row: Record<string, any>, candidates: string[]): string {
    for (const key of candidates) {
      const v = row[key]
      if (typeof v === 'string' && v.trim()) return v
      if (v !== null && v !== undefined) {
        const s = String(v).trim()
        if (s) return s
      }
    }
    return ''
  }

  /**
   * 初始化 WCDB
   */
  async initialize(): Promise<boolean> {
    if (this.initialized) return true

    try {
      this.koffi = require('koffi')
      const dllPath = this.getDllPath()
      this.writeLog(`[bootstrap] initialize platform=${process.platform} dllPath=${dllPath} resourcesPath=${this.resourcesPath || ''} userDataPath=${this.userDataPath || ''}`, true)

      if (!existsSync(dllPath)) {
        console.error('WCDB DLL 不存在:', dllPath)
        this.writeLog(`[bootstrap] initialize failed: dll not found path=${dllPath}`, true)
        return false
      }

      const dllDir = dirname(dllPath)
      const isMac = process.platform === 'darwin'
      
      // 预加载依赖库
      if (isMac) {
        const wcdbCorePath = join(dllDir, 'libWCDB.dylib')
        if (existsSync(wcdbCorePath)) {
          try {
            this.koffi.load(wcdbCorePath)
            this.writeLog('预加载 libWCDB.dylib 成功')
          } catch (e) {
            console.warn('预加载 libWCDB.dylib 失败(可能不是致命的):', e)
            this.writeLog(`预加载 libWCDB.dylib 失败: ${String(e)}`)
          }
        }
      } else {
        const wcdbCorePath = join(dllDir, 'WCDB.dll')
        if (existsSync(wcdbCorePath)) {
          try {
            this.koffi.load(wcdbCorePath)
            this.writeLog('预加载 WCDB.dll 成功')
          } catch (e) {
            console.warn('预加载 WCDB.dll 失败(可能不是致命的):', e)
            this.writeLog(`预加载 WCDB.dll 失败: ${String(e)}`)
          }
        }
        const sdl2Path = join(dllDir, 'SDL2.dll')
        if (existsSync(sdl2Path)) {
          try {
            this.koffi.load(sdl2Path)
            this.writeLog('预加载 SDL2.dll 成功')
          } catch (e) {
            console.warn('预加载 SDL2.dll 失败(可能不是致命的):', e)
            this.writeLog(`预加载 SDL2.dll 失败: ${String(e)}`)
          }
        }
      }

      this.lib = this.koffi.load(dllPath)

      // InitProtection (Added for security)
      try {
        this.wcdbInitProtection = this.lib.func('bool InitProtection(const char* resourcePath)')

        // 尝试多个可能的资源路径
        const resourcePaths = [
          dllDir,  // DLL 所在目录
          dirname(dllDir),  // 上级目录
          this.resourcesPath,  // 配置的资源路径
          join(process.cwd(), 'resources')  // 开发环境
        ].filter(Boolean)

        let protectionOk = false
        for (const resPath of resourcePaths) {
          try {
            // 
            protectionOk = this.wcdbInitProtection(resPath)
            if (protectionOk) {
              // 
              break
            }
          } catch (e) {
            // console.warn(`[WCDB] InitProtection 失败 (${resPath}):`, e)
          }
        }

        if (!protectionOk) {
          // console.warn('[WCDB] Core security check failed - 继续运行但可能不稳定')
          // this.writeLog('InitProtection 失败，继续运行')
          // 不返回 false，允许继续运行
        }
      } catch (e) {
        // console.warn('InitProtection symbol not found:', e)
      }

      // 定义类型
      // wcdb_status wcdb_init()
      this.wcdbInit = this.lib.func('int32 wcdb_init()')

      // wcdb_status wcdb_shutdown()
      this.wcdbShutdown = this.lib.func('int32 wcdb_shutdown()')

      // wcdb_status wcdb_open_account(const char* session_db_path, const char* hex_key, wcdb_handle* out_handle)
      // wcdb_handle 是 int64_t
      this.wcdbOpenAccount = this.lib.func('int32 wcdb_open_account(const char* path, const char* key, _Out_ int64* handle)')

      // wcdb_status wcdb_close_account(wcdb_handle handle)
      //  C 接口是 int64， koffi 返回 handle 是 number 类型
      this.wcdbCloseAccount = this.lib.func('int32 wcdb_close_account(int64 handle)')

      // wcdb_status wcdb_set_my_wxid(wcdb_handle handle, const char* wxid)
      try {
        this.wcdbSetMyWxid = this.lib.func('int32 wcdb_set_my_wxid(int64 handle, const char* wxid)')
      } catch {
        this.wcdbSetMyWxid = null
      }

      // wcdb_status wcdb_update_message(wcdb_handle handle, const char* session_id, int64_t local_id, int32_t create_time, const char* new_content, char** out_error)
      try {
        this.wcdbUpdateMessage = this.lib.func('int32 wcdb_update_message(int64 handle, const char* sessionId, int64 localId, int32 createTime, const char* newContent, _Out_ void** outError)')
      } catch {
        this.wcdbUpdateMessage = null
      }

      // wcdb_status wcdb_delete_message(wcdb_handle handle, const char* session_id, int64_t local_id, char** out_error)
      try {
        this.wcdbDeleteMessage = this.lib.func('int32 wcdb_delete_message(int64 handle, const char* sessionId, int64 localId, int32 createTime, const char* dbPathHint, _Out_ void** outError)')
      } catch {
        this.wcdbDeleteMessage = null
      }

      // void wcdb_free_string(char* ptr)
      this.wcdbFreeString = this.lib.func('void wcdb_free_string(void* ptr)')

      // wcdb_status wcdb_get_sessions(wcdb_handle handle, char** out_json)
      this.wcdbGetSessions = this.lib.func('int32 wcdb_get_sessions(int64 handle, _Out_ void** outJson)')

      // wcdb_status wcdb_get_messages(wcdb_handle handle, const char* username, int32_t limit, int32_t offset, char** out_json)
      this.wcdbGetMessages = this.lib.func('int32 wcdb_get_messages(int64 handle, const char* username, int32 limit, int32 offset, _Out_ void** outJson)')

      // wcdb_status wcdb_get_message_count(wcdb_handle handle, const char* username, int32_t* out_count)
      this.wcdbGetMessageCount = this.lib.func('int32 wcdb_get_message_count(int64 handle, const char* username, _Out_ int32* outCount)')

      // wcdb_status wcdb_get_display_names(wcdb_handle handle, const char* usernames_json, char** out_json)
      this.wcdbGetDisplayNames = this.lib.func('int32 wcdb_get_display_names(int64 handle, const char* usernamesJson, _Out_ void** outJson)')

      // wcdb_status wcdb_get_avatar_urls(wcdb_handle handle, const char* usernames_json, char** out_json)
      this.wcdbGetAvatarUrls = this.lib.func('int32 wcdb_get_avatar_urls(int64 handle, const char* usernamesJson, _Out_ void** outJson)')

      // wcdb_status wcdb_get_group_member_count(wcdb_handle handle, const char* chatroom_id, int32_t* out_count)
      this.wcdbGetGroupMemberCount = this.lib.func('int32 wcdb_get_group_member_count(int64 handle, const char* chatroomId, _Out_ int32* outCount)')

      // wcdb_status wcdb_get_group_member_counts(wcdb_handle handle, const char* chatroom_ids_json, char** out_json)
      try {
        this.wcdbGetGroupMemberCounts = this.lib.func('int32 wcdb_get_group_member_counts(int64 handle, const char* chatroomIdsJson, _Out_ void** outJson)')
      } catch {
        this.wcdbGetGroupMemberCounts = null
      }

      // wcdb_status wcdb_get_group_members(wcdb_handle handle, const char* chatroom_id, char** out_json)
      this.wcdbGetGroupMembers = this.lib.func('int32 wcdb_get_group_members(int64 handle, const char* chatroomId, _Out_ void** outJson)')

      // wcdb_status wcdb_get_group_nicknames(wcdb_handle handle, const char* chatroom_id, char** out_json)
      try {
        this.wcdbGetGroupNicknames = this.lib.func('int32 wcdb_get_group_nicknames(int64 handle, const char* chatroomId, _Out_ void** outJson)')
      } catch {
        this.wcdbGetGroupNicknames = null
      }

      // wcdb_status wcdb_get_message_tables(wcdb_handle handle, const char* session_id, char** out_json)
      this.wcdbGetMessageTables = this.lib.func('int32 wcdb_get_message_tables(int64 handle, const char* sessionId, _Out_ void** outJson)')

      // wcdb_status wcdb_get_message_meta(wcdb_handle handle, const char* db_path, const char* table_name, int32_t limit, int32_t offset, char** out_json)
      this.wcdbGetMessageMeta = this.lib.func('int32 wcdb_get_message_meta(int64 handle, const char* dbPath, const char* tableName, int32 limit, int32 offset, _Out_ void** outJson)')

      // wcdb_status wcdb_get_contact(wcdb_handle handle, const char* username, char** out_json)
      this.wcdbGetContact = this.lib.func('int32 wcdb_get_contact(int64 handle, const char* username, _Out_ void** outJson)')

      // wcdb_status wcdb_get_contact_status(wcdb_handle handle, const char* usernames_json, char** out_json)
      try {
        this.wcdbGetContactStatus = this.lib.func('int32 wcdb_get_contact_status(int64 handle, const char* usernamesJson, _Out_ void** outJson)')
      } catch {
        this.wcdbGetContactStatus = null
      }

      // wcdb_status wcdb_get_message_table_stats(wcdb_handle handle, const char* session_id, char** out_json)
      this.wcdbGetMessageTableStats = this.lib.func('int32 wcdb_get_message_table_stats(int64 handle, const char* sessionId, _Out_ void** outJson)')

      // wcdb_status wcdb_get_aggregate_stats(wcdb_handle handle, const char* session_ids_json, int32_t begin_timestamp, int32_t end_timestamp, char** out_json)
      this.wcdbGetAggregateStats = this.lib.func('int32 wcdb_get_aggregate_stats(int64 handle, const char* sessionIdsJson, int32 begin, int32 end, _Out_ void** outJson)')

      // wcdb_status wcdb_get_available_years(wcdb_handle handle, const char* session_ids_json, char** out_json)
      try {
        this.wcdbGetAvailableYears = this.lib.func('int32 wcdb_get_available_years(int64 handle, const char* sessionIdsJson, _Out_ void** outJson)')
      } catch {
        this.wcdbGetAvailableYears = null
      }

      // wcdb_status wcdb_get_annual_report_stats(wcdb_handle handle, const char* session_ids_json, int32_t begin_timestamp, int32_t end_timestamp, char** out_json)
      try {
        this.wcdbGetAnnualReportStats = this.lib.func('int32 wcdb_get_annual_report_stats(int64 handle, const char* sessionIdsJson, int32 begin, int32 end, _Out_ void** outJson)')
      } catch {
        this.wcdbGetAnnualReportStats = null
      }

      // wcdb_status wcdb_get_annual_report_extras(wcdb_handle handle, const char* session_ids_json, int32_t begin_timestamp, int32_t end_timestamp, int32_t peak_day_begin, int32_t peak_day_end, char** out_json)
      try {
        this.wcdbGetAnnualReportExtras = this.lib.func('int32 wcdb_get_annual_report_extras(int64 handle, const char* sessionIdsJson, int32 begin, int32 end, int32 peakBegin, int32 peakEnd, _Out_ void** outJson)')
      } catch {
        this.wcdbGetAnnualReportExtras = null
      }

      // wcdb_status wcdb_get_dual_report_stats(wcdb_handle handle, const char* session_id, int32_t begin_timestamp, int32_t end_timestamp, char** out_json)
      try {
        this.wcdbGetDualReportStats = this.lib.func('int32 wcdb_get_dual_report_stats(int64 handle, const char* sessionId, int32 begin, int32 end, _Out_ void** outJson)')
      } catch {
        this.wcdbGetDualReportStats = null
      }

      // wcdb_status wcdb_get_logs(char** out_json)
      try {
        this.wcdbGetLogs = this.lib.func('int32 wcdb_get_logs(_Out_ void** outJson)')
      } catch {
        this.wcdbGetLogs = null
      }

      // wcdb_status wcdb_get_group_stats(wcdb_handle handle, const char* chatroom_id, int32_t begin_timestamp, int32_t end_timestamp, char** out_json)
      try {
        this.wcdbGetGroupStats = this.lib.func('int32 wcdb_get_group_stats(int64 handle, const char* chatroomId, int32 begin, int32 end, _Out_ void** outJson)')
      } catch {
        this.wcdbGetGroupStats = null
      }

      // wcdb_status wcdb_get_message_dates(wcdb_handle handle, const char* session_id, char** out_json)
      try {
        this.wcdbGetMessageDates = this.lib.func('int32 wcdb_get_message_dates(int64 handle, const char* sessionId, _Out_ void** outJson)')
      } catch {
        this.wcdbGetMessageDates = null
      }

      // wcdb_status wcdb_open_message_cursor(wcdb_handle handle, const char* session_id, int32_t batch_size, int32_t ascending, int32_t begin_timestamp, int32_t end_timestamp, wcdb_cursor* out_cursor)
      this.wcdbOpenMessageCursor = this.lib.func('int32 wcdb_open_message_cursor(int64 handle, const char* sessionId, int32 batchSize, int32 ascending, int32 beginTimestamp, int32 endTimestamp, _Out_ int64* outCursor)')

      // wcdb_status wcdb_open_message_cursor_lite(wcdb_handle handle, const char* session_id, int32_t batch_size, int32_t ascending, int32_t begin_timestamp, int32_t end_timestamp, wcdb_cursor* out_cursor)
      try {
        this.wcdbOpenMessageCursorLite = this.lib.func('int32 wcdb_open_message_cursor_lite(int64 handle, const char* sessionId, int32 batchSize, int32 ascending, int32 beginTimestamp, int32 endTimestamp, _Out_ int64* outCursor)')
      } catch {
        this.wcdbOpenMessageCursorLite = null
      }

      // wcdb_status wcdb_fetch_message_batch(wcdb_handle handle, wcdb_cursor cursor, char** out_json, int32_t* out_has_more)
      this.wcdbFetchMessageBatch = this.lib.func('int32 wcdb_fetch_message_batch(int64 handle, int64 cursor, _Out_ void** outJson, _Out_ int32* outHasMore)')

      // wcdb_status wcdb_close_message_cursor(wcdb_handle handle, wcdb_cursor cursor)
      this.wcdbCloseMessageCursor = this.lib.func('int32 wcdb_close_message_cursor(int64 handle, int64 cursor)')

      // wcdb_status wcdb_get_logs(char** out_json)
      this.wcdbGetLogs = this.lib.func('int32 wcdb_get_logs(_Out_ void** outJson)')

      // wcdb_status wcdb_exec_query(wcdb_handle handle, const char* db_kind, const char* db_path, const char* sql, char** out_json)
      this.wcdbExecQuery = this.lib.func('int32 wcdb_exec_query(int64 handle, const char* kind, const char* path, const char* sql, _Out_ void** outJson)')

      // wcdb_status wcdb_get_emoticon_cdn_url(wcdb_handle handle, const char* db_path, const char* md5, char** out_url)
      this.wcdbGetEmoticonCdnUrl = this.lib.func('int32 wcdb_get_emoticon_cdn_url(int64 handle, const char* dbPath, const char* md5, _Out_ void** outUrl)')

      // wcdb_status wcdb_list_message_dbs(wcdb_handle handle, char** out_json)
      this.wcdbListMessageDbs = this.lib.func('int32 wcdb_list_message_dbs(int64 handle, _Out_ void** outJson)')

      // wcdb_status wcdb_list_media_dbs(wcdb_handle handle, char** out_json)
      this.wcdbListMediaDbs = this.lib.func('int32 wcdb_list_media_dbs(int64 handle, _Out_ void** outJson)')

      // wcdb_status wcdb_get_message_by_id(wcdb_handle handle, const char* session_id, int32 local_id, char** out_json)
      this.wcdbGetMessageById = this.lib.func('int32 wcdb_get_message_by_id(int64 handle, const char* sessionId, int32 localId, _Out_ void** outJson)')

      // wcdb_status wcdb_get_db_status(wcdb_handle handle, char** out_json)
      try {
        this.wcdbGetDbStatus = this.lib.func('int32 wcdb_get_db_status(int64 handle, _Out_ void** outJson)')
      } catch {
        this.wcdbGetDbStatus = null
      }

      // wcdb_status wcdb_get_voice_data(wcdb_handle handle, const char* session_id, int32_t create_time, int32_t local_id, int64_t svr_id, const char* candidates_json, char** out_hex)
      try {
        this.wcdbGetVoiceData = this.lib.func('int32 wcdb_get_voice_data(int64 handle, const char* sessionId, int32 createTime, int32 localId, int64 svrId, const char* candidatesJson, _Out_ void** outHex)')
      } catch {
        this.wcdbGetVoiceData = null
      }

      // wcdb_status wcdb_get_sns_timeline(wcdb_handle handle, int32_t limit, int32_t offset, const char* username, const char* keyword, int32_t start_time, int32_t end_time, char** out_json)
      try {
        this.wcdbGetSnsTimeline = this.lib.func('int32 wcdb_get_sns_timeline(int64 handle, int32 limit, int32 offset, const char* username, const char* keyword, int32 startTime, int32 endTime, _Out_ void** outJson)')
      } catch {
        this.wcdbGetSnsTimeline = null
      }

      // wcdb_status wcdb_get_sns_annual_stats(wcdb_handle handle, int32_t begin_timestamp, int32_t end_timestamp, char** out_json)
      try {
        this.wcdbGetSnsAnnualStats = this.lib.func('int32 wcdb_get_sns_annual_stats(int64 handle, int32 begin, int32 end, _Out_ void** outJson)')
      } catch {
        this.wcdbGetSnsAnnualStats = null
      }

      // wcdb_status wcdb_install_sns_block_delete_trigger(wcdb_handle handle, char** out_error)
      try {
        this.wcdbInstallSnsBlockDeleteTrigger = this.lib.func('int32 wcdb_install_sns_block_delete_trigger(int64 handle, _Out_ void** outError)')
      } catch {
        this.wcdbInstallSnsBlockDeleteTrigger = null
      }

      // wcdb_status wcdb_uninstall_sns_block_delete_trigger(wcdb_handle handle, char** out_error)
      try {
        this.wcdbUninstallSnsBlockDeleteTrigger = this.lib.func('int32 wcdb_uninstall_sns_block_delete_trigger(int64 handle, _Out_ void** outError)')
      } catch {
        this.wcdbUninstallSnsBlockDeleteTrigger = null
      }

      // wcdb_status wcdb_check_sns_block_delete_trigger(wcdb_handle handle, int32_t* out_installed)
      try {
        this.wcdbCheckSnsBlockDeleteTrigger = this.lib.func('int32 wcdb_check_sns_block_delete_trigger(int64 handle, _Out_ int32* outInstalled)')
      } catch {
        this.wcdbCheckSnsBlockDeleteTrigger = null
      }

      // wcdb_status wcdb_delete_sns_post(wcdb_handle handle, const char* post_id, char** out_error)
      try {
        this.wcdbDeleteSnsPost = this.lib.func('int32 wcdb_delete_sns_post(int64 handle, const char* postId, _Out_ void** outError)')
      } catch {
        this.wcdbDeleteSnsPost = null
      }

      // Named pipe IPC for monitoring (replaces callback)
      try {
        this.wcdbStartMonitorPipe = this.lib.func('int32 wcdb_start_monitor_pipe()')
        this.wcdbStopMonitorPipe = this.lib.func('void wcdb_stop_monitor_pipe()')
        this.wcdbGetMonitorPipeName = this.lib.func('int32 wcdb_get_monitor_pipe_name(_Out_ void** outName)')
        this.writeLog('Monitor pipe functions loaded')
      } catch (e) {
        console.warn('Failed to load monitor pipe functions:', e)
        this.wcdbStartMonitorPipe = null
        this.wcdbStopMonitorPipe = null
        this.wcdbGetMonitorPipeName = null
      }

      // void VerifyUser(int64_t hwnd_ptr, const char* message, char* out_result, int max_len)
      try {
        this.wcdbVerifyUser = this.lib.func('void VerifyUser(int64 hwnd, const char* message, _Out_ char* outResult, int maxLen)')
      } catch {
        this.wcdbVerifyUser = null
      }

      // wcdb_status wcdb_cloud_init(int32_t interval_seconds)
      try {
        this.wcdbCloudInit = this.lib.func('int32 wcdb_cloud_init(int32 intervalSeconds)')
      } catch {
        this.wcdbCloudInit = null
      }

      // wcdb_status wcdb_cloud_report(const char* stats_json)
      try {
        this.wcdbCloudReport = this.lib.func('int32 wcdb_cloud_report(const char* statsJson)')
      } catch {
        this.wcdbCloudReport = null
      }

      // void wcdb_cloud_stop()
      try {
        this.wcdbCloudStop = this.lib.func('void wcdb_cloud_stop()')
      } catch {
        this.wcdbCloudStop = null
      }


      // 初始化
      const initResult = this.wcdbInit()
      if (initResult !== 0) {
        console.error('WCDB 初始化失败:', initResult)
        lastDllInitError = `初始化失败（错误码: ${initResult}）`
        return false
      }

      this.initialized = true
      lastDllInitError = null
      return true
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e)
      console.error('WCDB 初始化异常:', errorMsg)
      this.writeLog(`WCDB 初始化异常: ${errorMsg}`, true)
      lastDllInitError = errorMsg
      // 检查是否是常见的 VC++ 运行时缺失错误
      if (errorMsg.includes('126') || errorMsg.includes('找不到指定的模块') ||
        errorMsg.includes('The specified module could not be found')) {
        lastDllInitError = '可能缺少 Visual C++ 运行时库。请安装 Microsoft Visual C++ Redistributable (x64)。'
      } else if (errorMsg.includes('193') || errorMsg.includes('不是有效的 Win32 应用程序')) {
        lastDllInitError = 'DLL 架构不匹配。请确保使用 64 位版本的应用程序。'
      }
      return false
    }
  }

  /**
   * 测试数据库连接
   */
  async testConnection(dbPath: string, hexKey: string, wxid: string): Promise<{ success: boolean; error?: string; sessionCount?: number }> {
    try {
      // 如果当前已经有相同参数的活动连接，直接返回成功
      if (this.handle !== null &&
        this.currentPath === dbPath &&
        this.currentKey === hexKey &&
        this.currentWxid === wxid) {
        return { success: true, sessionCount: 0 }
      }

      // 记录当前活动连接，用于在测试结束后恢复（避免影响聊天页等正在使用的连接）
      const hadActiveConnection = this.handle !== null
      const prevPath = this.currentPath
      const prevKey = this.currentKey
      const prevWxid = this.currentWxid

      if (!this.initialized) {
        const initOk = await this.initialize()
        if (!initOk) {
          // 返回更详细的错误信息，帮助用户诊断问题
          const detailedError = lastDllInitError || 'WCDB 初始化失败'
          return { success: false, error: detailedError }
        }
      }

      // 构建 db_storage 目录路径
      const dbStoragePath = this.resolveDbStoragePath(dbPath, wxid)
      this.writeLog(`testConnection dbPath=${dbPath} wxid=${wxid} dbStorage=${dbStoragePath || 'null'}`)

      if (!dbStoragePath || !existsSync(dbStoragePath)) {
        return { success: false, error: `数据库目录不存在: ${dbPath}` }
      }

      // 递归查找 session.db
      const sessionDbPath = this.findSessionDb(dbStoragePath)
      this.writeLog(`testConnection sessionDb=${sessionDbPath || 'null'}`)

      if (!sessionDbPath) {
        return { success: false, error: `未找到 session.db 文件` }
      }

      // 分配输出参数内存
      const handleOut = [0]
      const result = this.wcdbOpenAccount(sessionDbPath, hexKey, handleOut)

      if (result !== 0) {
        await this.printLogs()
        let errorMsg = '数据库打开失败'
        if (result === -1) errorMsg = '参数错误'
        else if (result === -2) errorMsg = '密钥错误'
        else if (result === -3) errorMsg = '数据库打开失败'
        this.writeLog(`testConnection openAccount failed code=${result}`)
        return { success: false, error: `${errorMsg} (错误码: ${result})` }
      }

      const tempHandle = handleOut[0]
      if (tempHandle <= 0) {
        return { success: false, error: '无效的数据库句柄' }
      }

      // 测试成功：使用 shutdown 清理资源（包括测试句柄）
      // 注意：shutdown 会断开当前活动连接，因此需要在测试后尝试恢复之前的连接
      try {
        this.wcdbShutdown()
        this.handle = null
        this.currentPath = null
        this.currentKey = null
        this.currentWxid = null
        this.initialized = false
      } catch (closeErr) {
        console.error('关闭测试数据库时出错:', closeErr)
      }

      // 恢复测试前的连接（如果之前有活动连接）
      if (hadActiveConnection && prevPath && prevKey && prevWxid) {
        try {
          await this.open(prevPath, prevKey, prevWxid)
        } catch {
          // 恢复失败则保持断开，由调用方处理
        }
      }

      return { success: true, sessionCount: 0 }
    } catch (e) {
      console.error('测试连接异常:', e)
      this.writeLog(`testConnection exception: ${String(e)}`)
      return { success: false, error: String(e) }
    }
  }

  /**
   * 打印 DLL 内部日志（仅在出错时调用）
   */
  private async printLogs(force = false): Promise<void> {
    try {
      if (!this.wcdbGetLogs) return
      const outPtr = [null as any]
      const result = this.wcdbGetLogs(outPtr)
      if (result === 0 && outPtr[0]) {
        try {
          const jsonStr = this.koffi.decode(outPtr[0], 'char', -1)
          this.writeLog(`wcdb_logs: ${jsonStr}`, force)
          this.wcdbFreeString(outPtr[0])
        } catch (e) {
          // ignore
        }
      }
    } catch (e) {
      console.error('获取日志失败:', e)
      this.writeLog(`wcdb_logs failed: ${String(e)}`, force)
    }
  }

  private startLogPolling(): void {
    if (this.logTimer || !this.isLogEnabled()) return
    this.logTimer = setInterval(() => {
      void this.pollLogs()
    }, 2000)
  }

  private stopLogPolling(): void {
    if (this.logTimer) {
      clearInterval(this.logTimer)
      this.logTimer = null
    }
    this.lastLogTail = null
  }

  private async pollLogs(): Promise<void> {
    try {
      if (!this.wcdbGetLogs || !this.isLogEnabled()) return
      const outPtr = [null as any]
      const result = this.wcdbGetLogs(outPtr)
      if (result !== 0 || !outPtr[0]) return
      let jsonStr = ''
      try {
        jsonStr = this.koffi.decode(outPtr[0], 'char', -1)
      } finally {
        try { this.wcdbFreeString(outPtr[0]) } catch { }
      }
      const logs = JSON.parse(jsonStr) as string[]
      if (!Array.isArray(logs) || logs.length === 0) return
      let startIdx = 0
      if (this.lastLogTail) {
        const idx = logs.lastIndexOf(this.lastLogTail)
        if (idx >= 0) startIdx = idx + 1
      }
      for (let i = startIdx; i < logs.length; i += 1) {
        this.writeLog(`wcdb: ${logs[i]}`)
      }
      this.lastLogTail = logs[logs.length - 1]
    } catch (e) {
      // ignore polling errors
    }
  }

  private decodeJsonPtr(outPtr: any): string | null {
    if (!outPtr) return null
    try {
      const jsonStr = this.koffi.decode(outPtr, 'char', -1)
      this.wcdbFreeString(outPtr)
      return jsonStr
    } catch (e) {
      try { this.wcdbFreeString(outPtr) } catch { }
      return null
    }
  }

  private ensureReady(): boolean {
    return this.initialized && this.handle !== null
  }

  private normalizeTimestamp(input: number): number {
    if (!input || input <= 0) return 0
    const asNumber = Number(input)
    if (!Number.isFinite(asNumber)) return 0
    // Treat >1e12 as milliseconds.
    const seconds = asNumber > 1e12 ? Math.floor(asNumber / 1000) : Math.floor(asNumber)
    const maxInt32 = 2147483647
    return Math.min(Math.max(seconds, 0), maxInt32)
  }

  private normalizeRange(beginTimestamp: number, endTimestamp: number): { begin: number; end: number } {
    const normalizedBegin = this.normalizeTimestamp(beginTimestamp)
    let normalizedEnd = this.normalizeTimestamp(endTimestamp)
    if (normalizedEnd <= 0) {
      normalizedEnd = this.normalizeTimestamp(Date.now())
    }
    if (normalizedBegin > 0 && normalizedEnd < normalizedBegin) {
      normalizedEnd = normalizedBegin
    }
    return { begin: normalizedBegin, end: normalizedEnd }
  }

  isReady(): boolean {
    return this.ensureReady()
  }

  /**
   * 打开数据库
   */
  async open(dbPath: string, hexKey: string, wxid: string): Promise<boolean> {
    try {
      if (!this.initialized) {
        const initOk = await this.initialize()
        if (!initOk) return false
      }

      // 检查是否已经是当前连接的参数，如果是则直接返回成功，实现"始终保持链接"
      if (this.handle !== null &&
        this.currentPath === dbPath &&
        this.currentKey === hexKey &&
        this.currentWxid === wxid) {
        return true
      }

      // 如果参数不同，则先关闭原来的连接
      if (this.handle !== null) {
        this.close()
        // 重新初始化，因为 close 呼叫了 shutdown
        const initOk = await this.initialize()
        if (!initOk) return false
      }

      const dbStoragePath = this.resolveDbStoragePath(dbPath, wxid)
      this.writeLog(`open dbPath=${dbPath} wxid=${wxid} dbStorage=${dbStoragePath || 'null'}`, true)

      if (!dbStoragePath || !existsSync(dbStoragePath)) {
        console.error('数据库目录不存在:', dbPath)
        this.writeLog(`open failed: dbStorage not found for ${dbPath}`)
        return false
      }

      const sessionDbPath = this.findSessionDb(dbStoragePath)
      this.writeLog(`open sessionDb=${sessionDbPath || 'null'}`, true)
      if (!sessionDbPath) {
        console.error('未找到 session.db 文件')
        this.writeLog('open failed: session.db not found')
        return false
      }

      const handleOut = [0]
      const result = this.wcdbOpenAccount(sessionDbPath, hexKey, handleOut)

      if (result !== 0) {
        console.error('打开数据库失败:', result)
        await this.printLogs()
        this.writeLog(`open failed: openAccount code=${result}`)
        return false
      }

      const handle = handleOut[0]
      if (handle <= 0) {
        return false
      }

      this.handle = handle
      this.currentPath = dbPath
      this.currentKey = hexKey
      this.currentWxid = wxid
      this.currentDbStoragePath = dbStoragePath
      this.initialized = true
      if (this.wcdbSetMyWxid && wxid) {
        try {
          this.wcdbSetMyWxid(this.handle, wxid)
        } catch (e) {
          // 静默失败
        }
      }
      if (this.isLogEnabled()) {
        this.startLogPolling()
      }
      this.writeLog(`open ok handle=${handle}`, true)
      await this.dumpDbStatus('open')
      await this.runPostOpenDiagnostics(dbPath, dbStoragePath, sessionDbPath, wxid)
      return true
    } catch (e) {
      console.error('打开数据库异常:', e)
      this.writeLog(`open exception: ${String(e)}`)
      return false
    }
  }

  /**
   * 关闭数据库
   * 注意：wcdb_close_account 可能导致崩溃，使用 shutdown 代替
   */
  close(): void {
    if (this.handle !== null || this.initialized) {
      try {
        // 不调用 closeAccount，直接 shutdown
        this.wcdbShutdown()
      } catch (e) {
        console.error('WCDB shutdown 出错:', e)
      }
      this.handle = null
      this.currentPath = null
      this.currentKey = null
      this.currentWxid = null
      this.currentDbStoragePath = null
      this.initialized = false
      this.stopLogPolling()
    }
  }

  /**
   * 关闭服务（与 close 相同）
   */
  shutdown(): void {
    this.close()
  }

  /**
   * 检查是否已连接
   */
  isConnected(): boolean {
    return this.initialized && this.handle !== null
  }

  async getSessions(): Promise<{ success: boolean; sessions?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      this.writeLog('getSessions skipped: not connected')
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      // 使用 setImmediate 让事件循环有机会处理其他任务，避免长时间阻塞
      await new Promise(resolve => setImmediate(resolve))

      const outPtr = [null as any]
      const result = this.wcdbGetSessions(this.handle, outPtr)

      // DLL 调用后再次让出控制权
      await new Promise(resolve => setImmediate(resolve))

      if (result !== 0 || !outPtr[0]) {
        this.writeLog(`getSessions failed: code=${result}`)
        return { success: false, error: `获取会话失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析会话失败' }
      this.writeLog(`getSessions ok size=${jsonStr.length}`)
      const sessions = JSON.parse(jsonStr)
      return { success: true, sessions }
    } catch (e) {
      this.writeLog(`getSessions exception: ${String(e)}`)
      return { success: false, error: String(e) }
    }
  }

  async getMessages(sessionId: string, limit: number, offset: number): Promise<{ success: boolean; messages?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetMessages(this.handle, sessionId, limit, offset, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取消息失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析消息失败' }
      const messages = JSON.parse(jsonStr)
      return { success: true, messages }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  /**
   * 获取指定时间之后的新消息
   */
  async getNewMessages(sessionId: string, minTime: number, limit: number = 1000): Promise<{ success: boolean; messages?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      // 1. 打开游标 (使用 Ascending=1 从指定时间往后查)
      const openRes = await this.openMessageCursor(sessionId, limit, true, minTime, 0)
      if (!openRes.success || !openRes.cursor) {
        return { success: false, error: openRes.error }
      }

      const cursor = openRes.cursor
      try {
        // 2. 获取批次
        const fetchRes = await this.fetchMessageBatch(cursor)
        if (!fetchRes.success) {
          return { success: false, error: fetchRes.error }
        }
        return { success: true, messages: fetchRes.rows }
      } finally {
        // 3. 关闭游标
        await this.closeMessageCursor(cursor)
      }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getMessageCount(sessionId: string): Promise<{ success: boolean; count?: number; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outCount = [0]
      const result = this.wcdbGetMessageCount(this.handle, sessionId, outCount)
      if (result !== 0) {
        return { success: false, error: `获取消息总数失败: ${result}` }
      }
      return { success: true, count: outCount[0] }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getMessageCounts(sessionIds: string[]): Promise<{ success: boolean; counts?: Record<string, number>; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }

    const normalizedSessionIds = Array.from(
      new Set(
        (sessionIds || [])
          .map((id) => String(id || '').trim())
          .filter(Boolean)
      )
    )
    if (normalizedSessionIds.length === 0) {
      return { success: true, counts: {} }
    }

    try {
      const counts: Record<string, number> = {}
      for (let i = 0; i < normalizedSessionIds.length; i += 1) {
        const sessionId = normalizedSessionIds[i]
        const outCount = [0]
        const result = this.wcdbGetMessageCount(this.handle, sessionId, outCount)
        counts[sessionId] = result === 0 && Number.isFinite(outCount[0]) ? Math.max(0, Math.floor(outCount[0])) : 0

        if (i > 0 && i % 160 === 0) {
          await new Promise(resolve => setImmediate(resolve))
        }
      }
      return { success: true, counts }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getDisplayNames(usernames: string[]): Promise<{ success: boolean; map?: Record<string, string>; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (usernames.length === 0) return { success: true, map: {} }
    try {
      if (process.platform === 'darwin') {
        const uniq = Array.from(new Set(usernames.map((x) => String(x || '').trim()).filter(Boolean)))
        if (uniq.length === 0) return { success: true, map: {} }
        const inList = uniq.map((u) => `'${u.replace(/'/g, "''")}'`).join(',')
        const sql = `SELECT * FROM contact WHERE username IN (${inList})`
        const q = await this.execQuery('contact', null, sql)
        if (!q.success) return { success: false, error: q.error || '获取昵称失败' }
        const map: Record<string, string> = {}
        for (const row of (q.rows || []) as Array<Record<string, any>>) {
          const username = this.pickFirstStringField(row, ['username', 'user_name', 'userName'])
          if (!username) continue
          const display = this.pickFirstStringField(row, [
            'remark', 'Remark',
            'nick_name', 'nickName', 'nickname', 'NickName',
            'alias', 'Alias'
          ]) || username
          map[username] = display
        }
        // 保证每个请求用户名至少有回退值
        for (const u of uniq) {
          if (!map[u]) map[u] = u
        }
        return { success: true, map }
      }

      // 让出控制权，避免阻塞事件循环
      await new Promise(resolve => setImmediate(resolve))

      const outPtr = [null as any]
      const result = this.wcdbGetDisplayNames(this.handle, JSON.stringify(usernames), outPtr)

      // DLL 调用后再次让出控制权
      await new Promise(resolve => setImmediate(resolve))

      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取昵称失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析昵称失败' }
      const map = JSON.parse(jsonStr)
      return { success: true, map }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getAvatarUrls(usernames: string[]): Promise<{ success: boolean; map?: Record<string, string>; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (usernames.length === 0) return { success: true, map: {} }
    try {
      const now = Date.now()
      const resultMap: Record<string, string> = {}
      const toFetch: string[] = []
      const seen = new Set<string>()

      for (const username of usernames) {
        if (!username || seen.has(username)) continue
        seen.add(username)
        const cached = this.avatarUrlCache.get(username)
        // 只使用有效的缓存(URL不为空)
        if (cached && cached.url && cached.url.trim() && now - cached.updatedAt < this.avatarCacheTtlMs) {
          resultMap[username] = cached.url
          continue
        }
        toFetch.push(username)
      }

      if (toFetch.length === 0) {
        return { success: true, map: resultMap }
      }

      if (process.platform === 'darwin') {
        const inList = toFetch.map((u) => `'${u.replace(/'/g, "''")}'`).join(',')
        const sql = `SELECT * FROM contact WHERE username IN (${inList})`
        const q = await this.execQuery('contact', null, sql)
        if (!q.success) {
          if (Object.keys(resultMap).length > 0) {
            return { success: true, map: resultMap, error: q.error || '获取头像失败' }
          }
          return { success: false, error: q.error || '获取头像失败' }
        }

        for (const row of (q.rows || []) as Array<Record<string, any>>) {
          const username = this.pickFirstStringField(row, ['username', 'user_name', 'userName'])
          if (!username) continue
          const url = this.pickFirstStringField(row, [
            'big_head_img_url', 'bigHeadImgUrl', 'bigHeadUrl', 'big_head_url',
            'small_head_img_url', 'smallHeadImgUrl', 'smallHeadUrl', 'small_head_url',
            'head_img_url', 'headImgUrl',
            'avatar_url', 'avatarUrl'
          ])
          if (url) {
            resultMap[username] = url
            this.avatarUrlCache.set(username, { url, updatedAt: now })
          }
        }
        return { success: true, map: resultMap }
      }

      // 让出控制权，避免阻塞事件循环
      await new Promise(resolve => setImmediate(resolve))

      const outPtr = [null as any]
      const result = this.wcdbGetAvatarUrls(this.handle, JSON.stringify(toFetch), outPtr)

      // DLL 调用后再次让出控制权
      await new Promise(resolve => setImmediate(resolve))

      if (result !== 0 || !outPtr[0]) {
        if (Object.keys(resultMap).length > 0) {
          return { success: true, map: resultMap, error: `获取头像失败: ${result}` }
        }
        return { success: false, error: `获取头像失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) {
        return { success: false, error: '解析头像失败' }
      }
      const map = JSON.parse(jsonStr) as Record<string, string>
      for (const username of toFetch) {
        const url = map[username]
        if (url && url.trim()) {
          resultMap[username] = url
          // 只缓存有效的URL
          this.avatarUrlCache.set(username, { url, updatedAt: now })
        }
        // 不缓存空URL,下次可以重新尝试
      }
      return { success: true, map: resultMap }
    } catch (e) {
      console.error('[wcdbCore] getAvatarUrls 异常:', e)
      return { success: false, error: String(e) }
    }
  }

  async getGroupMemberCount(chatroomId: string): Promise<{ success: boolean; count?: number; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outCount = [0]
      const result = this.wcdbGetGroupMemberCount(this.handle, chatroomId, outCount)
      if (result !== 0) {
        return { success: false, error: `获取群成员数量失败: ${result}` }
      }
      return { success: true, count: outCount[0] }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getGroupMemberCounts(chatroomIds: string[]): Promise<{ success: boolean; map?: Record<string, number>; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (chatroomIds.length === 0) return { success: true, map: {} }
    if (!this.wcdbGetGroupMemberCounts) {
      const map: Record<string, number> = {}
      for (const chatroomId of chatroomIds) {
        const result = await this.getGroupMemberCount(chatroomId)
        if (result.success && typeof result.count === 'number') {
          map[chatroomId] = result.count
        }
      }
      return { success: true, map }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetGroupMemberCounts(this.handle, JSON.stringify(chatroomIds), outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取群成员数量失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析群成员数量失败' }
      const map = JSON.parse(jsonStr)
      return { success: true, map }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getGroupMembers(chatroomId: string): Promise<{ success: boolean; members?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetGroupMembers(this.handle, chatroomId, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取群成员失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析群成员失败' }
      const members = JSON.parse(jsonStr)
      return { success: true, members }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getGroupNicknames(chatroomId: string): Promise<{ success: boolean; nicknames?: Record<string, string>; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (!this.wcdbGetGroupNicknames) {
      return { success: false, error: '当前 DLL 版本不支持获取群昵称接口' }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetGroupNicknames(this.handle, chatroomId, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取群昵称失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析群昵称失败' }
      const nicknames = JSON.parse(jsonStr)
      return { success: true, nicknames }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getMessageTables(sessionId: string): Promise<{ success: boolean; tables?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetMessageTables(this.handle, sessionId, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取消息表失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析消息表失败' }
      const tables = JSON.parse(jsonStr)
      return { success: true, tables }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getMessageDates(sessionId: string): Promise<{ success: boolean; dates?: string[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      if (!this.wcdbGetMessageDates) {
        return { success: false, error: 'DLL 不支持 getMessageDates' }
      }
      const outPtr = [null as any]
      const result = this.wcdbGetMessageDates(this.handle, sessionId, outPtr)
      if (result !== 0 || !outPtr[0]) {
        // 空结果也可能是正常的（无消息）
        return { success: true, dates: [] }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析日期列表失败' }
      const dates = JSON.parse(jsonStr)
      return { success: true, dates }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getMessageTableStats(sessionId: string): Promise<{ success: boolean; tables?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetMessageTableStats(this.handle, sessionId, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取表统计失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析表统计失败' }
      const tables = JSON.parse(jsonStr)
      return { success: true, tables }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getMessageMeta(dbPath: string, tableName: string, limit: number, offset: number): Promise<{ success: boolean; rows?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetMessageMeta(this.handle, dbPath, tableName, limit, offset, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取消息元数据失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析消息元数据失败' }
      const rows = JSON.parse(jsonStr)
      return { success: true, rows }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getContact(username: string): Promise<{ success: boolean; contact?: any; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      if (process.platform === 'darwin') {
        const safe = String(username || '').replace(/'/g, "''")
        const sql = `SELECT * FROM contact WHERE username='${safe}' LIMIT 1`
        const q = await this.execQuery('contact', null, sql)
        if (!q.success) {
          return { success: false, error: q.error || '获取联系人失败' }
        }
        const row = Array.isArray(q.rows) && q.rows.length > 0 ? q.rows[0] : null
        if (!row) {
          return { success: false, error: `联系人不存在: ${username}` }
        }
        return { success: true, contact: row }
      }

      const outPtr = [null as any]
      const result = this.wcdbGetContact(this.handle, username, outPtr)
      if (result !== 0 || !outPtr[0]) {
        this.writeLog(`[diag:getContact] primary api failed username=${username} code=${result} outPtr=${outPtr[0] ? 'set' : 'null'}`, true)
        await this.dumpDbStatus('getContact-primary-fail')
        await this.printLogs(true)

        // Fallback: 直接查询 contact 表，便于区分是接口失败还是 contact 库本身不可读。
        const safe = String(username || '').replace(/'/g, "''")
        const fallbackSql = `SELECT * FROM contact WHERE username='${safe}' LIMIT 1`
        const fallback = await this.execQuery('contact', null, fallbackSql)
        if (fallback.success) {
          const row = Array.isArray(fallback.rows) ? fallback.rows[0] : null
          if (row) {
            this.writeLog(`[diag:getContact] fallback sql hit username=${username}`, true)
            return { success: true, contact: row }
          }
          this.writeLog(`[diag:getContact] fallback sql no row username=${username}`, true)
          return { success: false, error: `联系人不存在: ${username}` }
        }
        this.writeLog(`[diag:getContact] fallback sql failed username=${username} err=${fallback.error || 'unknown'}`, true)
        return { success: false, error: `获取联系人失败: ${result}; fallback=${fallback.error || 'unknown'}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析联系人失败' }
      const contact = JSON.parse(jsonStr)
      return { success: true, contact }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getContactStatus(usernames: string[]): Promise<{ success: boolean; map?: Record<string, { isFolded: boolean; isMuted: boolean }>; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      // 分批查询，避免 SQL 过长（execQuery 不支持参数绑定，直接拼 SQL）
      const BATCH = 200
      const map: Record<string, { isFolded: boolean; isMuted: boolean }> = {}
      for (let i = 0; i < usernames.length; i += BATCH) {
        const batch = usernames.slice(i, i + BATCH)
        const inList = batch.map(u => `'${u.replace(/'/g, "''")}'`).join(',')
        const sql = `SELECT username, flag, extra_buffer FROM contact WHERE username IN (${inList})`
        const result = await this.execQuery('contact', null, sql)
        if (!result.success || !result.rows) continue
        for (const row of result.rows) {
          const uname: string = row.username
          // 折叠：flag bit 28 (0x10000000)
          const flag = parseInt(row.flag ?? '0', 10)
          const isFolded = (flag & 0x10000000) !== 0
          // 免打扰：extra_buffer field 12 非0
          const { isMuted } = parseExtraBuffer(row.extra_buffer)
          map[uname] = { isFolded, isMuted }
        }
      }
      return { success: true, map }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getAggregateStats(sessionIds: string[], beginTimestamp: number = 0, endTimestamp: number = 0): Promise<{ success: boolean; data?: any; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const normalizedBegin = this.normalizeTimestamp(beginTimestamp)
      let normalizedEnd = this.normalizeTimestamp(endTimestamp)
      if (normalizedEnd <= 0) {
        normalizedEnd = this.normalizeTimestamp(Date.now())
      }
      if (normalizedBegin > 0 && normalizedEnd < normalizedBegin) {
        normalizedEnd = normalizedBegin
      }

      const callAggregate = (ids: string[]) => {
        const idsAreNumeric = ids.length > 0 && ids.every((id) => /^\d+$/.test(id))
        const payloadIds = idsAreNumeric ? ids.map((id) => Number(id)) : ids

        const outPtr = [null as any]
        const result = this.wcdbGetAggregateStats(this.handle, JSON.stringify(payloadIds), normalizedBegin, normalizedEnd, outPtr)

        if (result !== 0 || !outPtr[0]) {
          return { success: false, error: `获取聚合统计失败: ${result}` }
        }
        const jsonStr = this.decodeJsonPtr(outPtr[0])
        if (!jsonStr) {
          return { success: false, error: '解析聚合统计失败' }
        }

        const data = JSON.parse(jsonStr)
        return { success: true, data }
      }

      let result = callAggregate(sessionIds)
      if (result.success && result.data && result.data.total === 0 && result.data.idMap) {
        const idMap = result.data.idMap as Record<string, string>
        const reverseMap: Record<string, string> = {}
        for (const [id, name] of Object.entries(idMap)) {
          if (!name) continue
          reverseMap[name] = id
        }
        const numericIds = sessionIds
          .map((id) => reverseMap[id])
          .filter((id) => typeof id === 'string' && /^\d+$/.test(id))
        if (numericIds.length > 0) {
          const retry = callAggregate(numericIds)
          if (retry.success && retry.data) {
            result = retry
          }
        }
      }

      return result
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getAvailableYears(sessionIds: string[]): Promise<{ success: boolean; data?: number[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (!this.wcdbGetAvailableYears) {
      return { success: false, error: '未支持获取年度列表' }
    }
    if (sessionIds.length === 0) return { success: true, data: [] }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetAvailableYears(this.handle, JSON.stringify(sessionIds), outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取年度列表失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析年度列表失败' }
      const data = JSON.parse(jsonStr)
      return { success: true, data }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getAnnualReportStats(sessionIds: string[], beginTimestamp: number = 0, endTimestamp: number = 0): Promise<{ success: boolean; data?: any; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (!this.wcdbGetAnnualReportStats) {
      return this.getAggregateStats(sessionIds, beginTimestamp, endTimestamp)
    }
    try {
      const { begin, end } = this.normalizeRange(beginTimestamp, endTimestamp)
      const outPtr = [null as any]
      const result = this.wcdbGetAnnualReportStats(this.handle, JSON.stringify(sessionIds), begin, end, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取年度统计失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析年度统计失败' }
      const data = JSON.parse(jsonStr)
      return { success: true, data }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getAnnualReportExtras(
    sessionIds: string[],
    beginTimestamp: number = 0,
    endTimestamp: number = 0,
    peakDayBegin: number = 0,
    peakDayEnd: number = 0
  ): Promise<{ success: boolean; data?: any; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (!this.wcdbGetAnnualReportExtras) {
      return { success: false, error: '未支持年度扩展统计' }
    }
    if (sessionIds.length === 0) return { success: true, data: {} }
    try {
      const { begin, end } = this.normalizeRange(beginTimestamp, endTimestamp)
      const outPtr = [null as any]
      const result = this.wcdbGetAnnualReportExtras(
        this.handle,
        JSON.stringify(sessionIds),
        begin,
        end,
        this.normalizeTimestamp(peakDayBegin),
        this.normalizeTimestamp(peakDayEnd),
        outPtr
      )
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取年度扩展统计失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析年度扩展统计失败' }
      const data = JSON.parse(jsonStr)
      return { success: true, data }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getGroupStats(chatroomId: string, beginTimestamp: number = 0, endTimestamp: number = 0): Promise<{ success: boolean; data?: any; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (!this.wcdbGetGroupStats) {
      return this.getAggregateStats([chatroomId], beginTimestamp, endTimestamp)
    }
    try {
      const { begin, end } = this.normalizeRange(beginTimestamp, endTimestamp)
      const outPtr = [null as any]
      const result = this.wcdbGetGroupStats(this.handle, chatroomId, begin, end, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取群聊统计失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析群聊统计失败' }
      const data = JSON.parse(jsonStr)
      return { success: true, data }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async openMessageCursor(sessionId: string, batchSize: number, ascending: boolean, beginTimestamp: number, endTimestamp: number): Promise<{ success: boolean; cursor?: number; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outCursor = [0]
      const result = this.wcdbOpenMessageCursor(
        this.handle,
        sessionId,
        batchSize,
        ascending ? 1 : 0,
        beginTimestamp,
        endTimestamp,
        outCursor
      )
      if (result !== 0 || outCursor[0] <= 0) {
        await this.printLogs(true)
        this.writeLog(
          `openMessageCursor failed: sessionId=${sessionId} batchSize=${batchSize} ascending=${ascending ? 1 : 0} begin=${beginTimestamp} end=${endTimestamp} result=${result} cursor=${outCursor[0]}`,
          true
        )
        return { success: false, error: `创建游标失败: ${result}，请查看日志` }
      }
      return { success: true, cursor: outCursor[0] }
    } catch (e) {
      await this.printLogs(true)
      this.writeLog(`openMessageCursor exception: ${String(e)}`, true)
      return { success: false, error: '创建游标异常，请查看日志' }
    }
  }

  async openMessageCursorLite(sessionId: string, batchSize: number, ascending: boolean, beginTimestamp: number, endTimestamp: number): Promise<{ success: boolean; cursor?: number; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (!this.wcdbOpenMessageCursorLite) {
      return this.openMessageCursor(sessionId, batchSize, ascending, beginTimestamp, endTimestamp)
    }
    try {
      const outCursor = [0]
      const result = this.wcdbOpenMessageCursorLite(
        this.handle,
        sessionId,
        batchSize,
        ascending ? 1 : 0,
        beginTimestamp,
        endTimestamp,
        outCursor
      )
      if (result !== 0 || outCursor[0] <= 0) {
        await this.printLogs(true)
        this.writeLog(
          `openMessageCursorLite failed: sessionId=${sessionId} batchSize=${batchSize} ascending=${ascending ? 1 : 0} begin=${beginTimestamp} end=${endTimestamp} result=${result} cursor=${outCursor[0]}`,
          true
        )
        return { success: false, error: `创建游标失败: ${result}，请查看日志` }
      }
      return { success: true, cursor: outCursor[0] }
    } catch (e) {
      await this.printLogs(true)
      this.writeLog(`openMessageCursorLite exception: ${String(e)}`, true)
      return { success: false, error: '创建游标异常，请查看日志' }
    }
  }

  async fetchMessageBatch(cursor: number): Promise<{ success: boolean; rows?: any[]; hasMore?: boolean; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outPtr = [null as any]
      const outHasMore = [0]
      const result = this.wcdbFetchMessageBatch(this.handle, cursor, outPtr, outHasMore)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取批次失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析批次失败' }
      const rows = JSON.parse(jsonStr)
      return { success: true, rows, hasMore: outHasMore[0] === 1 }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async closeMessageCursor(cursor: number): Promise<{ success: boolean; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const result = this.wcdbCloseMessageCursor(this.handle, cursor)
      if (result !== 0) {
        return { success: false, error: `关闭游标失败: ${result}` }
      }
      return { success: true }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getLogs(): Promise<{ success: boolean; logs?: string[]; error?: string }> {
    if (!this.lib) return { success: false, error: 'DLL 未加载' }
    if (!this.wcdbGetLogs) return { success: false, error: '接口未就绪' }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetLogs(outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取日志失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析日志失败' }
      return { success: true, logs: JSON.parse(jsonStr) }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async execQuery(kind: string, path: string | null, sql: string, params: any[] = []): Promise<{ success: boolean; rows?: any[]; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      if (!this.wcdbExecQuery) return { success: false, error: '接口未就绪' }
      
      // 如果提供了参数，使用参数化查询（需要 C++ 层支持）
      // 注意：当前 wcdbExecQuery 可能不支持参数化，这是一个占位符实现
      // TODO: 需要更新 C++ 层的 wcdb_exec_query 以支持参数绑定
      if (params && params.length > 0) {
        console.warn('[wcdbCore] execQuery: 参数化查询暂未在 C++ 层实现，将使用原始 SQL（可能存在注入风险）')
      }
      
      const normalizedKind = String(kind || '').toLowerCase()
      const isContactQuery = normalizedKind === 'contact' || /\bfrom\s+contact\b/i.test(String(sql))
      let effectivePath = path || ''
      if (normalizedKind === 'contact' && !effectivePath) {
        const resolvedContactDb = this.resolveContactDbPath()
        if (resolvedContactDb) {
          effectivePath = resolvedContactDb
          this.writeLog(`[diag:execQuery] contact path override -> ${effectivePath}`, true)
        } else {
          this.writeLog('[diag:execQuery] contact path override miss: Contact/contact.db not found', true)
        }
      }

      const outPtr = [null as any]
      const result = this.wcdbExecQuery(this.handle, kind, effectivePath, sql, outPtr)
      if (result !== 0 || !outPtr[0]) {
        if (isContactQuery) {
          this.writeLog(`[diag:execQuery] contact query failed code=${result} kind=${kind} path=${effectivePath} sql="${this.formatSqlForLog(sql)}"`, true)
          await this.dumpDbStatus('execQuery-contact-fail')
          await this.printLogs(true)
        }
        return { success: false, error: `执行查询失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析查询结果失败' }
      const rows = JSON.parse(jsonStr)
      if (isContactQuery) {
        const count = Array.isArray(rows) ? rows.length : -1
        this.writeLog(`[diag:execQuery] contact query ok rows=${count} kind=${kind} path=${effectivePath} sql="${this.formatSqlForLog(sql)}"`, true)
      }
      return { success: true, rows }
    } catch (e) {
      const isContactQuery = String(kind).toLowerCase() === 'contact' || /\bfrom\s+contact\b/i.test(String(sql))
      if (isContactQuery) {
        this.writeLog(`[diag:execQuery] contact query exception kind=${kind} path=${path || ''} sql="${this.formatSqlForLog(sql)}" err=${String(e)}`, true)
        await this.dumpDbStatus('execQuery-contact-exception')
      }
      return { success: false, error: String(e) }
    }
  }

  async getEmoticonCdnUrl(dbPath: string, md5: string): Promise<{ success: boolean; url?: string; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetEmoticonCdnUrl(this.handle, dbPath, md5, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取表情 URL 失败: ${result}` }
      }
      const urlStr = this.decodeJsonPtr(outPtr[0])
      if (urlStr === null) return { success: false, error: '解析表情 URL 失败' }
      return { success: true, url: urlStr || undefined }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async listMessageDbs(): Promise<{ success: boolean; data?: string[]; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    try {
      const outPtr = [null as any]
      const result = this.wcdbListMessageDbs(this.handle, outPtr)
      if (result !== 0 || !outPtr[0]) return { success: false, error: `获取消息库列表失败: ${result}` }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析消息库列表失败' }
      const data = JSON.parse(jsonStr)
      return { success: true, data }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async listMediaDbs(): Promise<{ success: boolean; data?: string[]; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    try {
      const outPtr = [null as any]
      const result = this.wcdbListMediaDbs(this.handle, outPtr)
      if (result !== 0 || !outPtr[0]) return { success: false, error: `获取媒体库列表失败: ${result}` }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析媒体库列表失败' }
      const data = JSON.parse(jsonStr)
      return { success: true, data }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  } async getMessageById(sessionId: string, localId: number): Promise<{ success: boolean; message?: any; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetMessageById(this.handle, sessionId, localId, outPtr)
      if (result !== 0 || !outPtr[0]) return { success: false, error: `查询消息失败: ${result}` }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析消息失败' }
      const message = JSON.parse(jsonStr)
      // 处理 wcdb_get_message_by_id 返回空对象的情况
      if (Object.keys(message).length === 0) return { success: false, error: '未找到消息' }
      return { success: true, message }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getVoiceData(sessionId: string, createTime: number, candidates: string[], localId: number = 0, svrId: string | number = 0): Promise<{ success: boolean; hex?: string; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    if (!this.wcdbGetVoiceData) return { success: false, error: '当前 DLL 版本不支持获取语音数据' }
    try {
      const outPtr = [null as any]
      const result = this.wcdbGetVoiceData(this.handle, sessionId, createTime, localId, BigInt(svrId || 0), JSON.stringify(candidates), outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取语音数据失败: ${result}` }
      }
      const hex = this.decodeJsonPtr(outPtr[0])
      if (hex === null) return { success: false, error: '解析语音数据失败' }
      return { success: true, hex: hex || undefined }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  /**
   * 数据收集初始化
   */
  async cloudInit(intervalSeconds: number = 600): Promise<{ success: boolean; error?: string }> {
    if (!this.initialized) {
      const initOk = await this.initialize()
      if (!initOk) return { success: false, error: 'WCDB init failed' }
    }
    if (!this.wcdbCloudInit) {
      return { success: false, error: 'Cloud init API not supported by DLL' }
    }
    try {
      const result = this.wcdbCloudInit(intervalSeconds)
      if (result !== 0) {
        return { success: false, error: `Cloud init failed: ${result}` }
      }
      return { success: true }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async cloudReport(statsJson: string): Promise<{ success: boolean; error?: string }> {
    if (!this.initialized) {
      const initOk = await this.initialize()
      if (!initOk) return { success: false, error: 'WCDB init failed' }
    }
    if (!this.wcdbCloudReport) {
      return { success: false, error: 'Cloud report API not supported by DLL' }
    }
    try {
      const result = this.wcdbCloudReport(statsJson || '')
      if (result !== 0) {
        return { success: false, error: `Cloud report failed: ${result}` }
      }
      return { success: true }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  cloudStop(): { success: boolean; error?: string } {
    if (!this.wcdbCloudStop) {
      return { success: false, error: 'Cloud stop API not supported by DLL' }
    }
    try {
      this.wcdbCloudStop()
      return { success: true }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }
  async verifyUser(message: string, hwnd?: string): Promise<{ success: boolean; error?: string }> {
    if (!this.initialized) {
      const initOk = await this.initialize()
      if (!initOk) return { success: false, error: 'WCDB 初始化失败' }
    }

    if (!this.wcdbVerifyUser) {
      return { success: false, error: 'Binding not found: VerifyUser' }
    }

    return new Promise((resolve) => {
      try {
        // Allocate buffer for result JSON
        const maxLen = 1024
        const outBuf = Buffer.alloc(maxLen)

        // Call native function
        const hwndVal = hwnd ? BigInt(hwnd) : BigInt(0)
        this.wcdbVerifyUser(hwndVal, message || '', outBuf, maxLen)

        // Parse result
        const jsonStr = this.koffi.decode(outBuf, 'char', -1)
        const result = JSON.parse(jsonStr)
        resolve(result)
      } catch (e) {
        resolve({ success: false, error: String(e) })
      }
    })
  }

  async getSnsTimeline(limit: number, offset: number, usernames?: string[], keyword?: string, startTime?: number, endTime?: number): Promise<{ success: boolean; timeline?: any[]; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    if (!this.wcdbGetSnsTimeline) return { success: false, error: '当前 DLL 版本不支持获取朋友圈' }
    try {
      const outPtr = [null as any]
      const usernamesJson = usernames && usernames.length > 0 ? JSON.stringify(usernames) : ''
      const result = this.wcdbGetSnsTimeline(
        this.handle,
        limit,
        offset,
        usernamesJson,
        keyword || '',
        startTime || 0,
        endTime || 0,
        outPtr
      )
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取朋友圈失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析朋友圈数据失败' }
      const timeline = JSON.parse(jsonStr)
      return { success: true, timeline }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getSnsAnnualStats(beginTimestamp: number, endTimestamp: number): Promise<{ success: boolean; data?: any; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    try {
      if (!this.wcdbGetSnsAnnualStats) {
        return { success: false, error: 'wcdbGetSnsAnnualStats 未找到' }
      }
      await new Promise(resolve => setImmediate(resolve))
      const outPtr = [null as any]
      const result = this.wcdbGetSnsAnnualStats(this.handle, beginTimestamp, endTimestamp, outPtr)
      await new Promise(resolve => setImmediate(resolve))

      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `getSnsAnnualStats failed: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: 'Failed to decode JSON' }
      return { success: true, data: JSON.parse(jsonStr) }
    } catch (e) {
      console.error('getSnsAnnualStats 异常:', e)
      return { success: false, error: String(e) }
    }
  }
  /**
   * 为朋友圈安装删除
   */
  async installSnsBlockDeleteTrigger(): Promise<{ success: boolean; alreadyInstalled?: boolean; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    if (!this.wcdbInstallSnsBlockDeleteTrigger) return { success: false, error: '当前 DLL 版本不支持此功能' }
    try {
      const outPtr = [null]
      const status = this.wcdbInstallSnsBlockDeleteTrigger(this.handle, outPtr)
      let msg = ''
      if (outPtr[0]) {
        try { msg = this.koffi.decode(outPtr[0], 'char', -1) } catch { }
        try { this.wcdbFreeString(outPtr[0]) } catch { }
      }
      if (status === 1) {
        // DLL 返回 1 表示已安装
        return { success: true, alreadyInstalled: true }
      }
      if (status !== 0) {
        return { success: false, error: msg || `DLL error ${status}` }
      }
      return { success: true, alreadyInstalled: false }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  /**
   * 关闭朋友圈删除拦截
   */
  async uninstallSnsBlockDeleteTrigger(): Promise<{ success: boolean; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    if (!this.wcdbUninstallSnsBlockDeleteTrigger) return { success: false, error: '当前 DLL 版本不支持此功能' }
    try {
      const outPtr = [null]
      const status = this.wcdbUninstallSnsBlockDeleteTrigger(this.handle, outPtr)
      let msg = ''
      if (outPtr[0]) {
        try { msg = this.koffi.decode(outPtr[0], 'char', -1) } catch { }
        try { this.wcdbFreeString(outPtr[0]) } catch { }
      }
      if (status !== 0) {
        return { success: false, error: msg || `DLL error ${status}` }
      }
      return { success: true }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  /**
   * 查询朋友圈删除拦截是否已安装
   */
  async checkSnsBlockDeleteTrigger(): Promise<{ success: boolean; installed?: boolean; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    if (!this.wcdbCheckSnsBlockDeleteTrigger) return { success: false, error: '当前 DLL 版本不支持此功能' }
    try {
      const outInstalled = [0]
      const status = this.wcdbCheckSnsBlockDeleteTrigger(this.handle, outInstalled)
      if (status !== 0) {
        return { success: false, error: `DLL error ${status}` }
      }
      return { success: true, installed: outInstalled[0] === 1 }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async deleteSnsPost(postId: string): Promise<{ success: boolean; error?: string }> {
    if (!this.ensureReady()) return { success: false, error: 'WCDB 未连接' }
    if (!this.wcdbDeleteSnsPost) return { success: false, error: '当前 DLL 版本不支持此功能' }
    try {
      const outPtr = [null]
      const status = this.wcdbDeleteSnsPost(this.handle, postId, outPtr)
      let msg = ''
      if (outPtr[0]) {
        try { msg = this.koffi.decode(outPtr[0], 'char', -1) } catch { }
        try { this.wcdbFreeString(outPtr[0]) } catch { }
      }
      if (status !== 0) {
        return { success: false, error: msg || `DLL error ${status}` }
      }
      return { success: true }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  async getDualReportStats(sessionId: string, beginTimestamp: number = 0, endTimestamp: number = 0): Promise<{ success: boolean; data?: any; error?: string }> {
    if (!this.ensureReady()) {
      return { success: false, error: 'WCDB 未连接' }
    }
    if (!this.wcdbGetDualReportStats) {
      return { success: false, error: '未支持双人报告统计' }
    }
    try {
      const { begin, end } = this.normalizeRange(beginTimestamp, endTimestamp)
      const outPtr = [null as any]
      const result = this.wcdbGetDualReportStats(this.handle, sessionId, begin, end, outPtr)
      if (result !== 0 || !outPtr[0]) {
        return { success: false, error: `获取双人报告统计失败: ${result}` }
      }
      const jsonStr = this.decodeJsonPtr(outPtr[0])
      if (!jsonStr) return { success: false, error: '解析双人报告统计失败' }
      const data = JSON.parse(jsonStr)
      return { success: true, data }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }
  /**
   * 修改消息内容
   */
  async updateMessage(sessionId: string, localId: number, createTime: number, newContent: string): Promise<{ success: boolean; error?: string }> {
    if (!this.initialized || !this.wcdbUpdateMessage) return { success: false, error: 'WCDB Not Initialized or Method Missing' }
    if (!this.handle) return { success: false, error: 'Not Connected' }

    return new Promise((resolve) => {
      try {
        const outError = [null as any]
        const result = this.wcdbUpdateMessage(this.handle, sessionId, localId, createTime, newContent, outError)

        if (result !== 0) {
          let errorMsg = 'Unknown Error'
          if (outError[0]) {
            errorMsg = this.decodeJsonPtr(outError[0]) || 'Unknown Error (Decode Failed)'
          }
          resolve({ success: false, error: errorMsg })
          return
        }

        resolve({ success: true })
      } catch (e) {
        resolve({ success: false, error: String(e) })
      }
    })
  }

  /**
   * 删除消息
   */
  async deleteMessage(sessionId: string, localId: number, createTime: number, dbPathHint?: string): Promise<{ success: boolean; error?: string }> {
    if (!this.initialized || !this.wcdbDeleteMessage) return { success: false, error: 'WCDB Not Initialized or Method Missing' }
    if (!this.handle) return { success: false, error: 'Not Connected' }

    return new Promise((resolve) => {
      try {
        const outError = [null as any]
        const result = this.wcdbDeleteMessage(this.handle, sessionId, localId, createTime || 0, dbPathHint || '', outError)

        if (result !== 0) {
          let errorMsg = 'Unknown Error'
          if (outError[0]) {
            errorMsg = this.decodeJsonPtr(outError[0]) || 'Unknown Error (Decode Failed)'
          }
          console.error(`[WcdbCore] deleteMessage fail: code=${result}, error=${errorMsg}`)
          resolve({ success: false, error: errorMsg })
          return
        }

        resolve({ success: true })
      } catch (e) {
        console.error(`[WcdbCore] deleteMessage exception:`, e)
        resolve({ success: false, error: String(e) })
      }
    })
  }
}
