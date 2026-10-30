import fs from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

export const VERSION = '1.1.0';
export const LIMITS = Object.freeze({ files: 500, fileBytes: 8 * 1024 * 1024, totalBytes: 32 * 1024 * 1024 });
export const RELEASE = '.skill-share-release.json';
const SHA = /^[a-f0-9]{40}$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
export class ShareError extends Error {
  constructor(message, code = 'INVALID', details) { super(message); this.name = 'ShareError'; this.code = code; this.details = details; }
}
export function ensure(condition, message, code = 'INVALID') { if (!condition) throw new ShareError(message, code); }
export function sha(value) { ensure(SHA.test(value), '无效的 Git 提交或对象标识。'); return value; }
export function slug(value) { ensure(typeof value === 'string' && SLUG.test(value), 'Skill 标识须为 1–64 位小写字母、数字或连字符。'); return value; }
export function repoName(value) {
  const result = String(value || '').replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '');
  ensure(/^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9_.-]+$/.test(result), '仓库应为 owner/repository 或 GitHub 仓库网址。');
  ensure(!result.split('/').some(x => x === '.' || x === '..'), '仓库地址无效。'); return result;
}
export function skillId(value) {
  ensure(/^u[1-9][0-9]*\/[a-z0-9-]+$/.test(value || ''), '请使用目录返回的唯一标识，例如 u12345/writing-helper。');
  slug(value.split('/')[1]); return value;
}
export function ownerPrefix(userId) { ensure(Number.isSafeInteger(userId) && userId > 0, 'GitHub 用户 ID 无效。'); return `u${userId}`; }
export function safePath(value) {
  ensure(typeof value === 'string' && value.length > 0 && value.length < 240, '文件路径长度无效。');
  ensure(!/[\\\x00-\x1f\x7f:<>"|?*]/.test(value), `文件路径不跨平台兼容：${value}`);
  for (const part of value.split('/')) {
    ensure(part && part !== '.' && part !== '..' && !/[. ]$/.test(part), `不安全的文件路径：${value}`);
    ensure(!/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part), `Windows 保留文件名：${value}`);
  }
  return value;
}
export function sensitivePath(value) {
  return value.split('/').some(p => /^(\.git|node_modules|\.venv|venv|__pycache__|\.DS_Store)$/i.test(p)
    || /^\.env(?:\.|$)/i.test(p) || /^(id_rsa|id_ed25519)(?:\.|$)/i.test(p)
    || /\.(?:pem|key|p12|pfx)$/i.test(p) || /^(credentials|secrets)\.(json|ya?ml|toml)$/i.test(p));
}
export function textSecrets(buffer, file) {
  if (buffer.includes(0)) return;
  const value = buffer.toString('utf8');
  ensure(!/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/.test(value), `检测到疑似凭据，请移出共享内容：${file}`, 'SECRET');
}
export function frontmatter(buffer) {
  const text = buffer.toString('utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  ensure(text.startsWith('---\n'), 'SKILL.md 缺少 YAML frontmatter。');
  const end = text.indexOf('\n---', 4); ensure(end >= 0 && /^(?:\n|$)/.test(text.slice(end + 4)), 'SKILL.md frontmatter 未正确结束。');
  const lines = text.slice(4, end).split('\n'); const result = {};
  // Only extract the two standard required scalar fields. Other host-specific YAML is preserved as data.
  for (let i = 0; i < lines.length; i++) {
    const m = /^(name|description):\s*(.*)$/.exec(lines[i]); if (!m) continue;
    ensure(!(m[1] in result), `SKILL.md 重复字段：${m[1]}`);
    let value = m[2].trim();
    if (/^[>|][-+]?\s*$/.test(value)) {
      const parts = []; while (i + 1 < lines.length && /^(?:\s|$)/.test(lines[i + 1])) parts.push(lines[++i].trim()); value = parts.join(' ').trim();
    } else if (value.startsWith('"')) {
      try { value = JSON.parse(value); } catch { throw new ShareError(`请将 ${m[1]} 写成普通字符串或有效的引号字符串。`); }
    } else if (value.startsWith("'")) { ensure(value.endsWith("'"), 'YAML 字符串引号未闭合。'); value = value.slice(1, -1).replace(/''/g, "'"); }
    else { value = value.replace(/\s+#.*$/, '').trim(); ensure(!/^[\[\]{}&*!]|:\s/.test(value), `${m[1]} 须为普通字符串。`); }
    ensure(typeof value === 'string' && value.length > 0, `${m[1]} 不可为空。`); result[m[1]] = value;
  }
  slug(result.name); ensure(result.description && result.description.length <= 4096, 'description 不能为空，且不能超过 4096 字符。');
  ensure(text.slice(end + 4).trim().length > 0, 'SKILL.md 缺少实际使用说明。'); return result;
}
export function validateBundle(files, expectedSlug) {
  ensure(files instanceof Map && files.size > 0 && files.size <= LIMITS.files, `Skill 文件数必须在 1–${LIMITS.files} 之间。`);
  let total = 0; const names = new Set();
  for (const [name, data] of files) {
    safePath(name); ensure(name !== RELEASE && name !== '.skill-share.json', `发布包不能自行提供 ${name}。`);
    ensure(!sensitivePath(name), `请移除不应共享的文件或目录：${name}`);
    const key = name.normalize('NFC').toLowerCase(); ensure(!names.has(key), `发现跨平台重名文件：${name}`); names.add(key);
    ensure(Buffer.isBuffer(data) && data.length <= LIMITS.fileBytes, `单文件超过 ${LIMITS.fileBytes / 1024 / 1024} MB：${name}`);
    total += data.length; textSecrets(data, name);
  }
  ensure(total <= LIMITS.totalBytes, `Skill 总大小超过 ${LIMITS.totalBytes / 1024 / 1024} MB。`);
  ensure(files.has('SKILL.md'), '根目录必须包含大小写准确的 SKILL.md。');
  const meta = frontmatter(files.get('SKILL.md')); if (expectedSlug) ensure(meta.name === expectedSlug, '目录标识必须和 SKILL.md 中的 name 一致。');
  const markdown = files.get('SKILL.md').toString('utf8').replace(/^```[^\n]*\n[\s\S]*?^```[^\n]*$/gm, '').replace(/`[^`\n]+`/g, '');
  for (const match of markdown.matchAll(/!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+"[^"\n]*")?\)/g)) {
    const link = match[1] || match[2]; if (/^(?:[a-z][a-z0-9+.-]*:|#)/i.test(link)) continue;
    let relative; try { relative = decodeURIComponent(link.split(/[?#]/)[0]); } catch { throw new ShareError(`参考文件链接编码无效：${link}`); }
    const normalized = path.posix.normalize(relative).replace(/\/$/, ''); if (normalized === '.') continue; safePath(normalized);
    ensure(files.has(normalized) || [...files.keys()].some(x => x.startsWith(`${normalized}/`)), `SKILL.md 引用的本地文件缺失：${relative}`, 'MISSING_REFERENCE');
  }
  return { ...meta, files: files.size, bytes: total, digest: bundleDigest(files) };
}
export function bundleDigest(files) {
  const hash = crypto.createHash('sha256');
  for (const name of [...files.keys()].sort()) { hash.update(name); hash.update('\0'); hash.update(crypto.createHash('sha256').update(files.get(name)).digest()); }
  return hash.digest('hex');
}
export async function localBundle(directory, { allowRelease = false } = {}) {
  const root = path.resolve(directory); ensure((await fs.lstat(root)).isDirectory(), 'Skill 来源必须是文件夹。'); const files = new Map(); let count = 0;
  async function walk(current, prefix = '') {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const name = prefix + entry.name; safePath(name);
      ensure(!entry.isSymbolicLink(), `不接受符号链接或目录链接：${name}`);
      ensure(!sensitivePath(name), `请从待发布目录移出：${name}`);
      if (entry.isDirectory()) await walk(path.join(current, entry.name), `${name}/`);
      else {
        ensure(entry.isFile(), `不接受特殊文件：${name}`);
        if (allowRelease && (name === RELEASE || name === '.skill-share.json')) continue;
        ensure(++count <= LIMITS.files, '文件数量超过上限。');
        const stat = await fs.lstat(path.join(current, entry.name)); ensure(stat.size <= LIMITS.fileBytes, `单文件过大：${name}`);
        files.set(name, await fs.readFile(path.join(current, entry.name)));
      }
    }
  }
  await walk(root); return files;
}
export async function atomicJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true }); const temp = `${file}.${crypto.randomUUID()}.tmp`;
  await fs.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  try { await fs.rename(temp, file); } catch (e) { await fs.rm(temp, { force: true }); throw e; }
}
export const defaultState = () => process.env.SKILL_SHARE_HOME ? path.resolve(process.env.SKILL_SHARE_HOME) : path.join(os.homedir(), '.skill-share');
let portableProbe;
export function githubCli() {
  const configured = process.env.SKILL_SHARE_GH;
  if (configured) { ensure(path.isAbsolute(configured) && existsSync(configured), '指定的 GitHub CLI 不存在。', 'MISSING_GH'); return configured; }
  const portable = path.join(defaultState(), 'tools', 'gh', 'bin', process.platform === 'win32' ? 'gh.exe' : 'gh');
  if (!existsSync(portable)) return 'gh';
  const modified = statSync(portable).mtimeMs;
  if (portableProbe?.path !== portable || portableProbe.modified !== modified) {
    const probe = spawnSync(portable, ['--version'], { encoding: 'utf8', timeout: 5000, windowsHide: true, shell: false });
    portableProbe = { path: portable, modified, usable: !probe.error && probe.status === 0 && /^gh version \d+\./.test(probe.stdout || '') };
  }
  return portableProbe.usable ? portable : 'gh';
}
export async function readJson(file, fallback) { try { return JSON.parse(await fs.readFile(file, 'utf8')); } catch (e) { if (e.code === 'ENOENT' && fallback !== undefined) return fallback; throw e; } }
export function targetRoot(target, { scope = 'user', project, dest, home = os.homedir() } = {}) {
  ensure(['user', 'project'].includes(scope), '安装范围必须为 user 或 project。');
  if (target === 'custom') { ensure(dest && path.isAbsolute(dest), '其他工具须用 --dest 指定已核实的绝对安装目录。'); return path.resolve(dest); }
  ensure(['codex', 'claude'].includes(target), '目标工具须为 codex、claude 或 custom。');
  if (scope === 'project') ensure(project && path.isAbsolute(project), '项目安装须用 --project 指定绝对路径。');
  return path.join(scope === 'project' ? project : home, target === 'codex' ? '.agents' : '.claude', 'skills');
}
export class GitHub {
  constructor({ transport, token } = {}) { this.transport = transport; this.token = token; }
  async api(endpoint, method = 'GET', body) {
    ensure(/^\/(?:repos|user|orgs)\//.test(endpoint) || endpoint === '/user', '无效的 GitHub API 路径。');
    if (this.transport) return this.transport(endpoint, method, body);
    if (this.token) {
      let response;
      try { response = await fetch(`https://api.github.com${endpoint}`, { method, redirect: 'error', signal: AbortSignal.timeout(45000),
        headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${this.token}`, 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body) }); }
      catch { throw new ShareError('GitHub 网络请求失败；写入结果不确定时先查询状态。', 'NETWORK'); }
      const text = await response.text(); let data; try { data = text ? JSON.parse(text) : null; } catch { throw new ShareError('GitHub 返回了无法识别的响应。', 'REMOTE'); }
      if (!response.ok) throw new ShareError(`GitHub 请求失败（HTTP ${response.status}）：${data?.message || '未知原因'}`, String(response.status)); return data;
    }
    const args = ['api', '--hostname', 'github.com', '--method', method, endpoint, '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28'];
    if (body !== undefined) args.push('--input', '-');
    const result = spawnSync(githubCli(), args, { encoding: 'utf8', input: body === undefined ? undefined : JSON.stringify(body), timeout: 60000, maxBuffer: 64 * 1024 * 1024, windowsHide: true, shell: false });
    if (result.error?.code === 'ENOENT') throw new ShareError('未安装 GitHub CLI（gh）。请阅读新手引导并安装官方工具。', 'MISSING_GH');
    if (result.error) throw new ShareError('GitHub CLI 未完成请求；请检查网络，并先查询可能已发生的写入。', 'NETWORK');
    if (result.status !== 0) { const status = /HTTP (\d{3})/.exec(result.stderr || '')?.[1]; throw new ShareError(`GitHub 请求失败${status ? `（HTTP ${status}）` : ''}，请检查登录、权限和网络。`, status || 'GH_ERROR'); }
    try { return result.stdout.trim() ? JSON.parse(result.stdout) : null; } catch { throw new ShareError('GitHub CLI 返回了无法识别的数据。', 'REMOTE'); }
  }
  async optional(endpoint) { try { return await this.api(endpoint); } catch (e) { if (e.code === '404') return null; throw e; } }
  async pages(endpoint, maxPages = 100) {
    const result = [];
    for (let page = 1; page <= maxPages; page++) {
      const rows = await this.api(`${endpoint}${endpoint.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      ensure(Array.isArray(rows), 'GitHub 分页响应无效。'); result.push(...rows); if (rows.length < 100) return result;
    }
    throw new ShareError('分页结果超过本次读取上限，未返回不完整结果。', 'LIMIT');
  }
}
export function repoApi(repo) { return `/repos/${repoName(repo)}`; }
export async function commitTree(api, repo, ref) {
  const commit = await api.api(`${repoApi(repo)}/git/commits/${sha(ref)}`); return commit.tree.sha;
}
export async function branchHead(api, repo, branch) {
  ensure(typeof branch === 'string' && branch.length > 0 && !branch.startsWith('-'), '分支名无效。');
  const ref = await api.api(`${repoApi(repo)}/git/ref/heads/${encodeURIComponent(branch)}`); return sha(ref.object.sha);
}
export async function treeEntries(api, repo, treeSha, recursive = false) {
  const response = await api.api(`${repoApi(repo)}/git/trees/${sha(treeSha)}${recursive ? '?recursive=1' : ''}`);
  ensure(Array.isArray(response.tree) && !response.truncated, '远端目录过大，GitHub 返回了截断结果；未继续使用不完整目录。', 'LIMIT'); return response.tree;
}
export async function subtree(api, repo, rootTree, relative) {
  let current = sha(rootTree);
  for (const part of relative.split('/')) {
    safePath(part); const entry = (await treeEntries(api, repo, current)).find(e => e.path === part);
    if (!entry) return null; ensure(entry.type === 'tree' && entry.mode === '040000', `远端目录类型无效：${relative}`); current = sha(entry.sha);
  }
  return current;
}
export async function readBlob(api, repo, blobSha) {
  const result = await api.api(`${repoApi(repo)}/git/blobs/${sha(blobSha)}`);
  ensure(result.encoding === 'base64' && result.size <= LIMITS.fileBytes, '远端文件编码或大小不受支持。');
  const data = Buffer.from(result.content, 'base64'); ensure(data.length === result.size, '远端文件长度校验失败。');
  const actual = crypto.createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex'); ensure(actual === blobSha, '远端文件 Git 校验失败。'); return data;
}
export async function remoteBundle(api, repo, treeSha, { withRelease = false } = {}) {
  const files = new Map(); let release = null, total = 0; const entries = await treeEntries(api, repo, treeSha, true);
  ensure(entries.length <= LIMITS.files * 3, '远端 Skill 目录过大。');
  for (const entry of entries) {
    safePath(entry.path); if (entry.type === 'tree') continue;
    ensure(entry.type === 'blob' && ['100644', '100755'].includes(entry.mode), `不接受符号链接、子模块或特殊文件：${entry.path}`);
    if (entry.path === RELEASE && withRelease) { release = JSON.parse((await readBlob(api, repo, entry.sha)).toString('utf8')); continue; }
    ensure(files.size < LIMITS.files && (!entry.size || entry.size <= LIMITS.fileBytes), '远端 Skill 超过文件数量或大小上限。');
    const data = await readBlob(api, repo, entry.sha); total += data.length; ensure(total <= LIMITS.totalBytes, '远端 Skill 总大小超过上限。');
    files.set(entry.path, data);
  }
  return { files, release };
}
export async function writeTree(api, repo, files) {
  const entries = [];
  for (const [name, data] of files) {
    safePath(name); const text = data.toString('utf8');
    if (Buffer.from(text, 'utf8').equals(data)) entries.push({ path: name, mode: '100644', type: 'blob', content: text });
    else {
      const blob = await api.api(`${repoApi(repo)}/git/blobs`, 'POST', { content: data.toString('base64'), encoding: 'base64' });
      entries.push({ path: name, mode: '100644', type: 'blob', sha: sha(blob.sha) });
    }
  }
  return sha((await api.api(`${repoApi(repo)}/git/trees`, 'POST', { tree: entries })).sha);
}
export async function graftCommit(api, repo, parent, relative, treeSha, message, extra = []) {
  safePath(relative); const root = await commitTree(api, repo, parent);
  const tree = await api.api(`${repoApi(repo)}/git/trees`, 'POST', { base_tree: root, tree: [{ path: relative, mode: '040000', type: 'tree', sha: sha(treeSha) }, ...extra] });
  const commit = await api.api(`${repoApi(repo)}/git/commits`, 'POST', { message, tree: sha(tree.sha), parents: [sha(parent)] }); return sha(commit.sha);
}
export async function catalogSnapshot(api, repo, ref) {
  const info = await api.api(repoApi(repo)); const head = ref ? sha(ref) : await branchHead(api, repo, info.default_branch);
  const root = await commitTree(api, repo, head);
  const entry = (await treeEntries(api, repo, root)).find(e => e.path === 'catalog.json');
  const catalog = entry ? JSON.parse((await readBlob(api, repo, entry.sha)).toString('utf8')) : { schema: 1, skills: {} };
  ensure(catalog.schema === 1 && catalog.skills && typeof catalog.skills === 'object' && !Array.isArray(catalog.skills), '共享目录格式无效。');
  return { head, root, catalog, info };
}
export async function compareTrees(api, repo, oldTree, newTree, prefix = '', output = [], budget = { n: 0 }) {
  if (oldTree === newTree) return output;
  ensure(++budget.n <= 1600, '改动目录过多。', 'LIMIT');
  const before = oldTree ? await treeEntries(api, repo, oldTree) : [];
  const after = newTree ? await treeEntries(api, repo, newTree) : [];
  const names = new Set([...before, ...after].map(e => e.path));
  for (const name of names) {
    safePath(name); const a = before.find(e => e.path === name); const b = after.find(e => e.path === name); const p = prefix + name;
    if (a?.sha === b?.sha && a?.mode === b?.mode) continue;
    if ((!a || a.type === 'tree') && (!b || b.type === 'tree')) await compareTrees(api, repo, a?.sha, b?.sha, `${p}/`, output, budget);
    else { output.push(p); ensure(output.length <= LIMITS.files * 2, '本次修改文件数超过上限。', 'LIMIT'); }
  }
  return output;
}
