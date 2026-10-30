import crypto from 'node:crypto';
import path from 'node:path';
import { ensure, ShareError, repoName, readJson, atomicJson, repoApi } from './core.mjs';

const REQUEST_MARKER = 'skill-share-enrollment-request:v1';
const RESULT_MARKER = 'skill-share-enrollment-result:v1';
const MAX_AGE = 15 * 60 * 1000;
const BOT_ID = 41898282;
const INFO = Buffer.from('skill-share-enrollment-v1');

function decode(value, maxBytes) {
  ensure(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), '加入请求格式无效。', 'ENROLLMENT_INVALID');
  const data = Buffer.from(value, 'base64url');
  ensure(data.length <= maxBytes && data.toString('base64url') === value, '加入请求大小或编码无效。', 'ENROLLMENT_INVALID');
  return data;
}
function keyFingerprint(publicKey) {
  const key = crypto.createPublicKey(publicKey);
  ensure(key.asymmetricKeyType === 'x25519', '加入入口公钥类型无效。', 'ENROLLMENT_CONFIG');
  return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 24);
}
export function enrollmentKeys() {
  const keys = crypto.generateKeyPairSync('x25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { keyId: keyFingerprint(publicKey), publicKey, privateKey: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
}
export function validateGateway(value, expectedRepo) {
  ensure(value?.schema === 1, '管理员尚未启用邀请码加入入口。', 'ENROLLMENT_NOT_CONFIGURED');
  const repo = repoName(value.repo), hubRepo = repoName(value.hubRepo);
  ensure(repo.toLowerCase() !== hubRepo.toLowerCase(), '加入入口必须与私有共享库分开。', 'ENROLLMENT_CONFIG');
  if (expectedRepo) ensure(hubRepo.toLowerCase() === repoName(expectedRepo).toLowerCase(), '邀请码入口不属于当前共享库。', 'ENROLLMENT_CONFIG');
  ensure(typeof value.publicKey === 'string' && value.publicKey.length < 2048 && value.keyId === keyFingerprint(value.publicKey), '加入入口公钥校验失败。', 'ENROLLMENT_CONFIG');
  return { schema: 1, repo, hubRepo, publicKey: value.publicKey, keyId: value.keyId };
}
function associatedData(envelope) {
  return Buffer.from(JSON.stringify([1, envelope.keyId, envelope.userId, envelope.repo, envelope.nonce, envelope.createdAt]));
}
export function sealRequest({ code, userId, repo, gateway, now = Date.now() }) {
  gateway = validateGateway(gateway, repo);
  ensure(typeof code === 'string' && /^[A-Za-z0-9_-]{12,128}$/.test(code.trim()), '请输入管理员发放的完整邀请码。', 'INVITATION_CODE');
  ensure(Number.isSafeInteger(userId) && userId > 0, 'GitHub 账号标识无效。');
  const ephemeral = crypto.generateKeyPairSync('x25519');
  const salt = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: crypto.createPublicKey(gateway.publicKey) });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO, 32));
  const envelope = { schema: 1, keyId: gateway.keyId, userId, repo: gateway.hubRepo, nonce: crypto.randomBytes(16).toString('hex'), createdAt: new Date(now).toISOString(),
    ephemeralKey: ephemeral.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), salt: salt.toString('base64url'), iv: iv.toString('base64url') };
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(associatedData(envelope));
  envelope.ciphertext = Buffer.concat([cipher.update(code.trim(), 'utf8'), cipher.final()]).toString('base64url');
  envelope.tag = cipher.getAuthTag().toString('base64url');
  shared.fill(0); key.fill(0);
  return envelope;
}
export function issueBody(envelope) {
  return 'Skill Share 自动加入请求。此记录公开 GitHub 用户名和申请状态，不包含明文邀请码或 Skill 内容。\n\n'
    + `<!-- ${REQUEST_MARKER} ${Buffer.from(JSON.stringify(envelope)).toString('base64url')} -->`;
}
export function parseRequest(body) {
  ensure(typeof body === 'string' && body.length <= 16384, '加入请求格式无效。', 'ENROLLMENT_INVALID');
  const matches = [...body.matchAll(/<!-- skill-share-enrollment-request:v1 ([A-Za-z0-9_-]+) -->/g)];
  ensure(matches.length === 1, '加入请求格式无效。', 'ENROLLMENT_INVALID');
  let envelope;
  try { envelope = JSON.parse(decode(matches[0][1], 4096).toString('utf8')); } catch { throw new ShareError('加入请求格式无效。', 'ENROLLMENT_INVALID'); }
  ensure(envelope?.schema === 1 && Number.isSafeInteger(envelope.userId) && envelope.userId > 0 && /^[a-f0-9]{24}$/.test(envelope.keyId || '')
    && /^[a-f0-9]{32}$/.test(envelope.nonce || '') && typeof envelope.createdAt === 'string' && Number.isFinite(Date.parse(envelope.createdAt)) && new Date(Date.parse(envelope.createdAt)).toISOString() === envelope.createdAt,
  '加入请求格式无效。', 'ENROLLMENT_INVALID');
  repoName(envelope.repo);
  return envelope;
}
export function openRequest(body, { privateKey, keyId, actualUserId, hubRepo, now = Date.now(), maxAgeMs = MAX_AGE }) {
  try {
    const envelope = parseRequest(body);
    ensure(envelope.keyId === keyId && envelope.userId === actualUserId && envelope.repo.toLowerCase() === repoName(hubRepo).toLowerCase(), '请求身份不匹配。');
    const age = now - Date.parse(envelope.createdAt);
    ensure(age >= -60000 && age <= maxAgeMs, '加入请求已过期。');
    const ephemeralKey = crypto.createPublicKey({ key: decode(envelope.ephemeralKey, 80), format: 'der', type: 'spki' });
    ensure(ephemeralKey.asymmetricKeyType === 'x25519', '请求公钥无效。');
    const shared = crypto.diffieHellman({ privateKey: crypto.createPrivateKey(privateKey), publicKey: ephemeralKey });
    const salt = decode(envelope.salt, 32), iv = decode(envelope.iv, 12), tag = decode(envelope.tag, 16);
    ensure(salt.length === 32 && iv.length === 12 && tag.length === 16, '请求格式无效。');
    const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO, 32));
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(associatedData(envelope)); decipher.setAuthTag(tag);
    const code = Buffer.concat([decipher.update(decode(envelope.ciphertext, 128)), decipher.final()]).toString('utf8');
    shared.fill(0); key.fill(0);
    ensure(/^[A-Za-z0-9_-]{12,128}$/.test(code), '邀请码格式无效。');
    return { nonce: envelope.nonce, userId: envelope.userId, repo: envelope.repo, createdAt: envelope.createdAt, code, keyId: envelope.keyId };
  } catch { throw new ShareError('加入请求未通过校验。', 'ENROLLMENT_REJECTED'); }
}
export function codeRecord(code, { id = crypto.randomUUID(), expiresAt = new Date(Date.now() + 30 * 86400000).toISOString() } = {}) {
  ensure(typeof code === 'string' && /^[A-Za-z0-9_-]{12,128}$/.test(code), '邀请码格式无效。');
  ensure(Date.parse(expiresAt) > Date.now(), '邀请码到期时间须在未来。');
  const salt = crypto.randomBytes(16).toString('hex');
  return { id, salt, hash: crypto.scryptSync(code, Buffer.from(salt, 'hex'), 32).toString('hex'), expiresAt, enabled: true };
}
export function receiptBody(receipt) {
  return `<!-- ${RESULT_MARKER} ${JSON.stringify(receipt)} -->`;
}
export function readReceipt(comments, expected) {
  for (const comment of [...comments].reverse()) {
    if (comment.user?.id !== BOT_ID || comment.user?.type !== 'Bot' || comment.user?.login !== 'github-actions[bot]') continue;
    if (typeof comment.body !== 'string' || comment.body.length > 8192) continue;
    const match = /<!-- skill-share-enrollment-result:v1 (\{[^\n]+\}) -->/.exec(comment.body);
    if (!match) continue;
    let value; try { value = JSON.parse(match[1]); } catch { continue; }
    if (value.schema !== 1 || !['invited', 'active', 'rejected'].includes(value.state) || value.nonce !== expected.nonce
      || value.userId !== expected.userId || value.repo?.toLowerCase() !== expected.repo.toLowerCase() || value.keyId !== expected.keyId) continue;
    return value;
  }
  return null;
}
async function connectOrAccept(client, repo) {
  try { return await client.connect(repo); }
  catch (error) { if (!['404', 'ACCESS'].includes(error.code)) throw error; }
  const invitation = (await client.api.pages('/user/repository_invitations')).find(x => x.repository.full_name.toLowerCase() === repo.toLowerCase());
  if (!invitation) return null;
  await client.acceptInvitation({ repo, apply: true });
  return client.connect(repo);
}
export async function enroll({ client, code, gateway, waitMs = 180000, pollMs = 5000, onProgress = () => {}, now = () => Date.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  gateway = validateGateway(gateway);
  ensure(Number.isFinite(waitMs) && waitMs >= 0 && waitMs <= 300000 && pollMs >= 1000, '等待参数无效。');
  const connected = await connectOrAccept(client, gateway.hubRepo);
  if (connected) return connected;
  const user = await client.identity();
  const stateFile = path.join(client.stateRoot, 'enrollments.json');
  const records = await readJson(stateFile, {});
  const recordKey = `${gateway.repo.toLowerCase()}:${gateway.hubRepo.toLowerCase()}:${user.id}:${gateway.keyId}`;
  let task = records[recordKey];
  if (task?.state === 'rejected' || task && now() - Date.parse(task.createdAt) > MAX_AGE) task = null;
  if (!task) {
    const envelope = sealRequest({ code, userId: user.id, repo: gateway.hubRepo, gateway, now: now() });
    task = { gateway: gateway.repo, repo: gateway.hubRepo, userId: user.id, keyId: gateway.keyId, nonce: envelope.nonce, createdAt: envelope.createdAt, body: issueBody(envelope), state: 'preparing' };
    records[recordKey] = task; await atomicJson(stateFile, records);
  }
  if (!task.number) {
    const issues = await client.api.pages(`${repoApi(gateway.repo)}/issues?creator=${encodeURIComponent(user.login)}&state=all`, 10);
    const original = issues.find(issue => !issue.pull_request && issue.user?.id === user.id && issue.body === task.body);
    if (original) { task.number = original.number; task.url = original.html_url; }
    else if (task.uncertain) return { state: 'pending', repo: gateway.hubRepo, reason: '请求结果尚未确认，已保留原请求；稍后重新打开安装入口继续核对。' };
    else {
      try {
        const issue = await client.api.api(`${repoApi(gateway.repo)}/issues`, 'POST', { title: 'Skill Share enrollment', body: task.body });
        task.number = issue.number; task.url = issue.html_url;
      } catch (error) {
        task.uncertain = true; await atomicJson(stateFile, records);
        throw new ShareError('加入请求结果尚未确认；重新打开安装入口会先查询原请求，不会重复提交。', 'ENROLLMENT_UNCERTAIN');
      }
    }
    task.state = 'pending'; await atomicJson(stateFile, records);
  }
  // A member can retry their own original request after a worker/network failure.
  // Serialize locally and record intent before the comment; the worker remains idempotent.
  if (task.state === 'pending' && now() - Date.parse(task.lastRetryAt || task.createdAt) >= 60000) {
    const comments = await client.api.pages(`${repoApi(gateway.repo)}/issues/${task.number}/comments`, 10);
    if (!readReceipt(comments, task)) {
      task.lastRetryAt = new Date(now()).toISOString(); await atomicJson(stateFile, records);
      await client.api.api(`${repoApi(gateway.repo)}/issues/${task.number}/comments`, 'POST', { body: '/skill-share-retry' });
    }
  }
  onProgress({ state: 'pending', requestNumber: task.number, url: task.url });
  const until = now() + waitMs;
  do {
    const comments = await client.api.pages(`${repoApi(gateway.repo)}/issues/${task.number}/comments`, 10);
    const receipt = readReceipt(comments, task);
    if (receipt?.state === 'rejected') {
      task.state = 'rejected'; await atomicJson(stateFile, records);
      throw new ShareError('邀请码或加入请求未通过校验。请核对管理员发放的邀请码；账号被禁止加入时需联系管理员。', 'ENROLLMENT_REJECTED');
    }
    if (receipt && ['invited', 'active'].includes(receipt.state)) {
      const result = await connectOrAccept(client, gateway.hubRepo);
      if (result) { task.state = 'connected'; await atomicJson(stateFile, records); return { ...result, enrollmentRequest: task.number }; }
    }
    if (now() >= until) return { state: 'pending', repo: gateway.hubRepo, requestNumber: task.number, url: task.url, next: '自动加入仍在处理。稍后重新打开安装入口，会继续核对原请求。' };
    await sleep(Math.min(pollMs, Math.max(0, until - now())));
  } while (true);
}
