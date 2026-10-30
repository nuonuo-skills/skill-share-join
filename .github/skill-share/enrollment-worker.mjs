import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createSign, scryptSync, timingSafeEqual } from 'node:crypto';

export const RECEIPT_MARKER = 'skill-share-enrollment-result:v1';
export const MAX_REQUEST_AGE_MS = 15 * 60 * 1000;
const ACTIONS_BOT_ID = 41898282;
const ROLES = new Set(['read', 'triage', 'write', 'maintain', 'admin']);
const USERNAME = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$/;
const REPOSITORY = /^[a-zA-Z0-9][a-zA-Z0-9-]*\/[a-zA-Z0-9_.-]+$/;

export class EnrollmentError extends Error {
  constructor(code, message) { super(message); this.name = 'EnrollmentError'; this.code = code; }
}
function requireValue(value, code = 'CONFIGURATION') {
  if (!value) throw new EnrollmentError(code, code === 'REQUEST_REJECTED' ? '加入请求未通过校验。' : '自动加入配置无效，请联系管理员。');
}
function safeId(value) { return Number.isSafeInteger(value) && value > 0; }
function statusOf(error) { return Number(error.status || error.code); }
function sameRepo(a, b) { return typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase(); }

/** Minimal REST adapter: no implicit retries of external writes and no credential logging. */
export class EnrollmentApi {
  constructor(token, { fetchImpl = fetch } = {}) { requireValue(typeof token === 'string' && token.length > 0); this.token = token; this.fetchImpl = fetchImpl; }
  async api(endpoint, method = 'GET', body) {
    requireValue(typeof endpoint === 'string' && endpoint.startsWith('/') && !endpoint.startsWith('//'));
    const response = await this.fetchImpl(`https://api.github.com${endpoint}`, {
      method, headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${this.token}`, 'X-GitHub-Api-Version': '2022-11-28', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'error', signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) { const error = new EnrollmentError('REMOTE', 'GitHub 操作未完成，请稍后核对原请求。'); error.status = response.status; throw error; }
    if (response.status === 204) return null;
    return response.json();
  }
  async pages(endpoint) {
    const output = [];
    for (let page = 1; page <= 50; page++) {
      const values = await this.api(`${endpoint}${endpoint.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      requireValue(Array.isArray(values)); output.push(...values);
      if (values.length < 100) return output;
    }
    throw new EnrollmentError('LIMIT', 'GitHub 返回记录过多，请联系管理员。');
  }
}

export function validatePolicy(policy) {
  requireValue(policy?.schema === 1 && REPOSITORY.test(policy.hubRepo || '') && REPOSITORY.test(policy.gatewayRepo || ''));
  requireValue(!sameRepo(policy.hubRepo, policy.gatewayRepo) && safeId(policy.hubRepositoryId) && safeId(policy.gatewayRepositoryId));
  requireValue(typeof policy.keyId === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(policy.keyId));
  requireValue(typeof policy.publicKey === 'string' && policy.publicKey.length <= 8192);
  requireValue(policy.deniedUserIds === undefined || (Array.isArray(policy.deniedUserIds) && policy.deniedUserIds.length <= 10000 && policy.deniedUserIds.every(safeId)));
  return policy;
}

/** The invitation code is compared only in memory; errors never contain the submitted text. */
export function validInvitationCode(code, records, now) {
  requireValue(Array.isArray(records) && records.length > 0 && records.length <= 32);
  for (const item of records) {
    requireValue(item && typeof item.id === 'string' && item.id.length > 0 && item.id.length <= 80);
    requireValue(typeof item.enabled === 'boolean' && typeof item.salt === 'string' && /^[a-f0-9]{32,128}$/i.test(item.salt) && item.salt.length % 2 === 0);
    requireValue(typeof item.hash === 'string' && /^[a-f0-9]{64}$/i.test(item.hash) && typeof item.expiresAt === 'string' && Number.isFinite(Date.parse(item.expiresAt)));
  }
  if (typeof code !== 'string' || code.length < 8 || code.length > 512) return false;
  let accepted = false;
  for (const item of records) {
    if (!item.enabled || Date.parse(item.expiresAt) <= now) continue;
    const derived = scryptSync(code, Buffer.from(item.salt, 'hex'), 32);
    accepted = timingSafeEqual(derived, Buffer.from(item.hash, 'hex')) || accepted;
  }
  return accepted;
}

/** Mint a short-lived token limited to exactly the target hub and its invitation permission. */
export async function mintInstallationToken({ appId, appPrivateKey, policy, now = Date.now(), fetchImpl = fetch }) {
  validatePolicy(policy); requireValue(/^\d+$/.test(String(appId || '')) && typeof appPrivateKey === 'string');
  const seconds = Math.floor(now / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({ iat: seconds - 60, exp: seconds + 540, iss: String(appId) })).toString('base64url');
  const unsigned = `${header}.${claims}`;
  const signature = createSign('RSA-SHA256').update(unsigned).sign(appPrivateKey, 'base64url');
  const app = new EnrollmentApi(`${unsigned}.${signature}`, { fetchImpl });
  const installation = await app.api(`/repos/${policy.hubRepo}/installation`);
  requireValue(safeId(installation?.id) && sameRepo(`${installation.account?.login}/x`, `${policy.hubRepo.split('/')[0]}/x`));
  const minted = await app.api(`/app/installations/${installation.id}/access_tokens`, 'POST', {
    repository_ids: [policy.hubRepositoryId], permissions: { administration: 'write' },
  });
  requireValue(typeof minted?.token === 'string' && minted.token.length > 0 && minted.permissions?.administration === 'write');
  requireValue(Object.entries(minted.permissions).every(([name, level]) => (name === 'administration' && level === 'write') || (name === 'metadata' && level === 'read')));
  requireValue(!minted.repositories || (Array.isArray(minted.repositories) && minted.repositories.length === 1 && minted.repositories[0].id === policy.hubRepositoryId));
  return minted.token;
}

function officialReceipt(comment) {
  if (comment.user?.type !== 'Bot' || comment.user?.login !== 'github-actions[bot]' || comment.user?.id !== ACTIONS_BOT_ID) return null;
  const match = /^<!-- skill-share-enrollment-result:v1 ([^\n]+) -->/.exec(comment.body || '');
  if (!match || match[1].length > 4096) return null;
  try { return JSON.parse(match[1]); } catch { return null; }
}
function matchingReceipt(value, expected) {
  return value?.schema === 1 && value.state === expected.state && value.nonce === expected.nonce && value.userId === expected.userId && sameRepo(value.repo, expected.repo) && value.issueNumber === expected.issueNumber && value.keyId === expected.keyId;
}
async function findReceipt(api, base, expected) {
  const comments = await api.pages(`${base}/comments`);
  return comments.map(officialReceipt).find(value => matchingReceipt(value, expected));
}
async function finishIssue(api, base, result) {
  if (!(await findReceipt(api, base, result))) {
    const text = result.state === 'active' ? '已连接共享库，可以回到安装助手继续。' : result.state === 'invited' ? '邀请已发送，安装助手会自动接受并连接。' : '加入请求未通过校验，请核对邀请码或联系管理员。';
    try { await api.api(`${base}/comments`, 'POST', { body: `<!-- ${RECEIPT_MARKER} ${JSON.stringify(result)} -->\n${text}` }); }
    catch { if (!(await findReceipt(api, base, result))) throw new EnrollmentError('RETRYABLE', '结果尚未确认，请稍后重试原请求。'); }
  }
  try { await api.api(base, 'PATCH', { state: 'closed' }); }
  catch { const issue = await api.api(base); if (issue.state !== 'closed') throw new EnrollmentError('RETRYABLE', '结果已记录，请稍后核对原请求。'); }
  return result;
}
async function accessState(api, policy, user) {
  const base = `/repos/${policy.hubRepo}`;
  let permission;
  try { permission = await api.api(`${base}/collaborators/${encodeURIComponent(user.login)}/permission`); }
  catch (error) { if (statusOf(error) !== 404) throw error; }
  requireValue(!permission?.user?.id || permission.user.id === user.id, 'REQUEST_REJECTED');
  if (ROLES.has(permission?.permission)) return 'active';
  const invitations = await api.pages(`${base}/invitations`);
  const pending = invitations.find(item => item.invitee?.id === user.id);
  if (pending) {
    requireValue(ROLES.has(pending.permissions) || pending.permissions === 'pull', 'REQUEST_REJECTED');
    requireValue(!pending.repository?.id || pending.repository.id === policy.hubRepositoryId);
    return 'invited';
  }
  return null;
}

/** Process one untrusted issue using only trusted policy and injected, independently scoped APIs. */
export async function handleEnrollment({ event, policy, secrets, gateApi, hubApi, openRequestFn, parseRequestFn, now = () => Date.now(), mintTokenFn = mintInstallationToken, fetchImpl = fetch }) {
  validatePolicy(policy);
  const initial = event.action === 'opened' && !event.comment;
  const retry = event.action === 'created' && event.comment?.body === '/skill-share-retry' && event.comment?.user?.id === event.issue?.user?.id && event.comment?.user?.type === 'User';
  requireValue((initial || retry) && event.repository?.id === policy.gatewayRepositoryId && sameRepo(event.repository.full_name, policy.gatewayRepo) && event.repository.private === false);
  const number = event.issue?.number; requireValue(safeId(number));
  const issueBase = `/repos/${policy.gatewayRepo}/issues/${number}`;
  const issue = await gateApi.api(issueBase);
  requireValue(!issue.pull_request && issue.user?.type === 'User' && safeId(issue.user.id) && USERNAME.test(issue.user.login || ''), 'REQUEST_REJECTED');
  requireValue(issue.user.id === event.issue.user?.id, 'REQUEST_REJECTED');
  if (!openRequestFn || !parseRequestFn) {
    const protocol = await import('./enrollment.mjs');
    openRequestFn ||= protocol.openRequest; parseRequestFn ||= protocol.parseRequest;
  }
  let envelope;
  try { envelope = parseRequestFn(issue.body); }
  catch {
    // No nonce can be bound to a malformed message; post no machine-readable success receipt.
    await gateApi.api(`${issueBase}/comments`, 'POST', { body: '加入请求格式无效，请使用安装助手重新发起。请勿在公开 Issue 中填写邀请码。' });
    await gateApi.api(issueBase, 'PATCH', { state: 'closed' });
    return { state: 'rejected', code: 'REQUEST_REJECTED' };
  }
  requireValue(typeof envelope.nonce === 'string' && /^[a-zA-Z0-9_-]{16,128}$/.test(envelope.nonce), 'REQUEST_REJECTED');
  const receipt = { schema: 1, nonce: envelope.nonce, userId: issue.user.id, repo: policy.hubRepo, issueNumber: number, keyId: policy.keyId };
  let records;
  try { records = JSON.parse(secrets.ENROLLMENT_CODES_JSON); } catch { throw new EnrollmentError('CONFIGURATION', '自动加入配置无效，请联系管理员。'); }
  requireValue(typeof secrets.ENROLLMENT_PRIVATE_KEY === 'string' && secrets.ENROLLMENT_PRIVATE_KEY.length > 0);
  // Validate policy records separately so an operator error never looks like a member rejection.
  validInvitationCode('', records, now());
  let request;
  try {
    request = openRequestFn(issue.body, { privateKey: secrets.ENROLLMENT_PRIVATE_KEY, keyId: policy.keyId, actualUserId: issue.user.id, hubRepo: policy.hubRepo, now: now(), maxAgeMs: MAX_REQUEST_AGE_MS });
    requireValue(request.userId === issue.user.id && sameRepo(request.repo, policy.hubRepo) && request.nonce === envelope.nonce && request.keyId === policy.keyId, 'REQUEST_REJECTED');
    requireValue(!policy.deniedUserIds?.includes(issue.user.id) && validInvitationCode(request.code, records, now()), 'REQUEST_REJECTED');
  } catch { return finishIssue(gateApi, issueBase, { ...receipt, state: 'rejected', code: 'REQUEST_REJECTED' }); }
  if (!hubApi) {
    const token = await mintTokenFn({ appId: secrets.APP_ID, appPrivateKey: secrets.APP_PRIVATE_KEY, policy, now: now(), fetchImpl });
    hubApi = new EnrollmentApi(token, { fetchImpl });
  }
  const hub = await hubApi.api(`/repos/${policy.hubRepo}`);
  requireValue(hub.id === policy.hubRepositoryId && hub.private === true && hub.owner?.type === 'Organization');
  const user = await hubApi.api(`/users/${encodeURIComponent(issue.user.login)}`);
  requireValue(user.id === issue.user.id && USERNAME.test(user.login || ''), 'REQUEST_REJECTED');
  let state = await accessState(hubApi, policy, user);
  if (!state) {
    try { await hubApi.api(`/repos/${policy.hubRepo}/collaborators/${encodeURIComponent(user.login)}`, 'PUT', { permission: 'pull' }); }
    catch {
      // A dropped response may follow a successful invitation: resolve through reads first.
      state = await accessState(hubApi, policy, user);
      if (!state) throw new EnrollmentError('RETRYABLE', '邀请结果尚未确认，请稍后重试原请求。');
    }
    state ||= await accessState(hubApi, policy, user);
    if (!state) throw new EnrollmentError('RETRYABLE', '邀请结果尚未确认，请稍后重试原请求。');
  }
  return finishIssue(gateApi, issueBase, { ...receipt, state });
}

export async function runEvent(event, env = process.env) {
  requireValue(sameRepo(event.repository?.full_name, env.GITHUB_REPOSITORY) && env.GH_TOKEN);
  const policyPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'join-policy.json');
  const policy = JSON.parse(await fs.readFile(policyPath, 'utf8'));
  return handleEnrollment({ event, policy, secrets: env, gateApi: new EnrollmentApi(env.GH_TOKEN) });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { const event = JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH, 'utf8')); console.log(JSON.stringify(await runEvent(event))); }
  catch (error) {
    // Never emit raw crypto, HTTP, environment or submitted request content.
    console.error(JSON.stringify({ state: 'failed', code: error instanceof EnrollmentError ? error.code : 'RETRYABLE', message: '自动加入未完成，请核对原请求或联系管理员。' }));
    process.exitCode = 1;
  }
}
