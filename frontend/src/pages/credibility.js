import {credibility, sealIdemKey} from '../api/entities.js';
import {downloadSeal, verifySealFile} from '../api/client.js';
import {session} from '../stores/session.js';
import {heading} from '../components/common/shell.js';
import {esc, date, notify} from '../utils/dom.js';

const ISSUE_LABEL = {
  tamper: '内容篡改 / 断链',
  gap: '缺条 / 空号',
  order: '乱序',
  truncated: '整段尾部被删',
  genesis: '可信起点不符',
};

function statusBadge(s){
  const map = {completed: ['已完成', 'ok'], processing: ['封存中', 'run'], failed: ['中断待恢复', 'bad']};
  const [text, cls] = map[s] || [s, 'run'];
  return '<span class="seal-badge ' + cls + '">' + esc(text) + '</span>';
}

export async function credibilityPage(){
  const isAdmin = session.user.role === 'admin';
  const [anchor, live, seals, creds] = await Promise.all([
    credibility.anchor(), credibility.verifyLive(), credibility.seals(), credibility.credentials(100),
  ]);
  const headSeq = creds.length ? Math.max(...creds.map(c => c.seq)) : anchor.genesis_seq;
  const verifyPanel = '<section class="panel"><div class="section-title"><h2>在线链核验</h2><span>实时读取在线凭据</span></div>'
    + (live.ok
      ? '<div class="verify-result ok"><strong>核验通过 ✓</strong><p>共 ' + live.count + ' 条凭据，seq 0~' + live.head_seq + ' 连续无断链，末链哈希 ' + esc(live.tail_hash.slice(0, 24)) + '…</p></div>'
      : '<div class="verify-result bad"><strong>核验未通过 ✕</strong><ul class="issue-list">' + live.issues.map(i => '<li><b>' + esc(ISSUE_LABEL[i.type] || i.type) + '</b>：' + esc(i.detail) + '</li>').join('') + '</ul></div>')
    + '<button class="button small" id="reverify-live">重新核验 ↻</button>'
    + '<div class="anchor-box"><p class="eyebrow">可信起点 TRUST ANCHOR</p><p>genesis（seq=' + anchor.genesis_seq + '）内容固定，任何链上凭据都由它递推：</p><pre>' + esc(anchor.expected_hash) + '</pre><p class="hint">' + esc(anchor.legacy_audit_note) + '</p></div></section>';

  const sealsPanel = '<section class="panel"><div class="section-title"><h2>封存档案</h2><span>另存快照 · 可离线核验</span></div>'
    + (isAdmin ? '<form id="seal-form" class="seal-form"><label>封存截至 seq（留空=当前链尾 ' + headSeq + '）<input name="up_to_seq" type="number" min="0" max="' + headSeq + '" placeholder="默认封存全部 ' + (headSeq + 1) + ' 条"></label><button class="primary" type="submit">封存截至该条的凭据</button><p class="hint">封存范围即刻固定，封存途中及之后的新操作不会混入；中断后可点“继续封存”恢复。</p></form>' : '<p class="hint">仅业务负责人可发起封存；你可以下载与核验已封存档案。</p>')
    + '<div class="seal-list">' + (seals.length ? seals.map(s => '<article class="seal-item"><div><strong>' + esc(s.seal_code) + '</strong> ' + statusBadge(s.status) + '<p>seq 0~' + s.up_to_seq + ' · 共 ' + s.entry_count + ' 条 · ' + date(s.created_at) + '</p><small>封存哈希 ' + esc(s.seal_hash ? s.seal_hash.slice(0, 24) + '…' : '（未完成）') + (s.error ? ' · 中断原因：' + esc(s.error) : '') + '</small></div><div class="seal-actions">'
      + (s.status === 'completed'
        ? '<button class="text-button" data-seal-download="' + s.id + '" data-code="' + esc(s.seal_code) + '">下载封存 ↓</button>'
        : (isAdmin ? '<button class="button small" data-seal-resume="' + s.id + '">继续封存 ↻</button>' : '<span class="hint">封存中断，待负责人恢复</span>'))
      + '</div></article>').join('') : '<p class="empty">尚无封存。负责人可对截至某条的凭据发起封存。</p>') + '</div></section>';

  const offlinePanel = '<section class="panel"><div class="section-title"><h2>离线核验封存文件</h2><span>以另存的封存凭据为准</span></div>'
    + '<label class="upload-line">选择 .seal.json 封存文件<input type="file" id="seal-file" accept=".json,application/json"></label>'
    + '<div id="offline-result" class="verify-result"><p class="hint">核验完全基于封存文件自身：重算每条自哈希、prev_hash 链接、seq 连续性与封存总哈希，可指出篡改、缺条、乱序及整段尾部被删。</p></div></section>';

  const chainPanel = '<section class="panel"><div class="section-title"><h2>连续凭据链（最近 100 条）</h2><span>接入 → 分析 → 批准 → 归档</span></div>'
    + '<div class="table-wrap"><table><thead><tr><th>seq</th><th>事件</th><th>操作者</th><th>载荷摘要</th><th>自哈希</th><th>时间</th></tr></thead><tbody>'
    + creds.map(c => '<tr><td>' + c.seq + '</td><td><b>' + esc(c.event) + '</b></td><td>' + esc(c.actor) + '</td><td class="payload-cell">' + esc(JSON.stringify(c.payload)) + '</td><td><code>' + esc(c.entry_hash.slice(0, 16)) + '…</code></td><td>' + date(c.at) + '</td></tr>').join('')
    + '</tbody></table></div><p class="hint">每条凭据的自哈希覆盖 seq/事件/操作者/载荷/前条哈希/时间；删除或修改任意一条都会导致其后全部链接失配。</p></section>';

  return heading('06 / CREDIBILITY', '连续凭据与封存核验',
      '业务变更与凭据在同一事务内落库：要么一起保存，要么一起拒绝。哈希链给出并发下的唯一顺序，封存另存独立凭据，离线即可验证完整性。',
      '<button class="button" id="refresh-cred">刷新 ↻</button>')
    + verifyPanel + '<div class="two-columns">' + sealsPanel + offlinePanel + '</div>' + chainPanel;
}

export function bindCredibility(refresh){
  document.querySelector('#refresh-cred')?.addEventListener('click', refresh);
  document.querySelector('#reverify-live')?.addEventListener('click', refresh);
  const form = document.querySelector('#seal-form');
  if(form){
    form.addEventListener('submit', async e => {
      e.preventDefault();
      const raw = new FormData(form).get('up_to_seq');
      const upTo = raw === '' ? null : Number(raw);
      try{
        const s = await credibility.createSeal(upTo, sealIdemKey());
        notify(s.status === 'completed' ? '封存完成，可下载离线核验' : '封存已开始，可稍后继续');
        await refresh();
      }catch(err){ notify(err.message, true); }
    });
  }
  document.querySelectorAll('[data-seal-resume]').forEach(b => b.addEventListener('click', async () => {
    try{ await credibility.resumeSeal(b.dataset.sealResume); notify('封存已恢复完成'); await refresh(); }
    catch(err){ notify(err.message, true); }
  }));
  document.querySelectorAll('[data-seal-download]').forEach(b => b.addEventListener('click', () =>
    downloadSeal(b.dataset.sealDownload, b.dataset.code).catch(err => notify(err.message, true))));
  const fileInput = document.querySelector('#seal-file');
  fileInput?.addEventListener('change', async e => {
    const file = e.target.files[0];
    const box = document.querySelector('#offline-result');
    if(!file) return;
    box.innerHTML = '<p class="hint">核验中…</p>';
    try{
      const r = await verifySealFile(file);
      if(r.ok){
        box.className = 'verify-result ok';
        box.innerHTML = '<strong>封存核验通过 ✓</strong><p>' + esc(r.seal?.seal_code || '') + '：seq 0~' + r.head_seq + '，共 ' + r.count + ' 条；封存总哈希' + (r.seal_hash_ok ? '一致' : '不一致') + '。该封存文件完整可信。</p>';
      }else{
        box.className = 'verify-result bad';
        box.innerHTML = '<strong>封存核验未通过 ✕</strong><ul class="issue-list">' + r.issues.map(i => '<li><b>' + esc(ISSUE_LABEL[i.type] || i.type) + '</b>：' + esc(i.detail) + '</li>').join('') + '</ul>';
      }
    }catch(err){ box.className = 'verify-result bad'; box.innerHTML = '<strong>核验失败</strong><p>' + esc(err.message) + '</p>'; }
  });
}
