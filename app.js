// Gần Nhau – phòng ngang hàng bảo mật cao: chat, ảnh, thả tim, xem/nghe chung có đồng bộ.
//
// Mô hình bảo mật
//  1. Link mời = mã phòng + khoá link (sau dấu #, trình duyệt không bao giờ gửi phần này lên máy chủ).
//     Mật khẩu phòng KHÔNG nằm trong link – báo bằng lời. Khoá = PBKDF2-SHA256(khoá link + mật khẩu, 310 000 vòng).
//  2. Nửa đầu khoá mã hoá thông tin bắt tay (Trystero password): không có mật khẩu thì không tìm thấy / không nối được ai.
//  3. Nửa sau là khoá AES-GCM 256: MỌI dữ liệu của app (tin nhắn, ảnh, lệnh phát, danh sách thành viên) được mã hoá
//     thêm một lớp riêng, chồng lên lớp DTLS của WebRTC.
//  4. Chủ phòng duyệt từng người (kèm mã xác minh), có thể khoá phòng. Chưa được duyệt thì không nhận / gửi được gì.
//  5. Mã xác minh từng người = băm(vân tay chứng chỉ DTLS của hai máy + khoá phòng): hai người đọc cho nhau nghe,
//     giống nhau = nối thẳng với nhau, không ai đứng giữa.
import { joinRoom, selfId } from './vendor/trystero.js'

const APP_ID = 'gan-nhau-v2'
const $ = (s) => document.querySelector(s)
const COLORS = ['#ff7aa2', '#5ee6c1', '#ffc94a', '#8fb8ff', '#c79bff', '#ff9e6b']
const te = new TextEncoder(), td = new TextDecoder()
// cầu nối khi chạy trong app Android (chỉ trang của app gọi được, xem MainActivity)
const bridge = window.GanNhauBridge
const native = bridge ? {
  share: (t) => bridge.postMessage(JSON.stringify({ a: 'share', t })),
  copy: (t) => bridge.postMessage(JSON.stringify({ a: 'copy', t })),
  openUrl: (t) => bridge.postMessage(JSON.stringify({ a: 'open', t })),
  webBase: () => 'https://isaedu68-tech.github.io/gan-nhau/'
} : null

// ---------- tiện ích ----------
const ALPHA = 'abcdefghijkmnpqrstuvwxyz23456789'
const rand = (n) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return Array.from(a, (b) => ALPHA[b % 32]).join('') }
const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('')
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const store = { get: (k) => { try { return localStorage.getItem(k) } catch { return null } }, set: (k, v) => { try { localStorage.setItem(k, v) } catch {} } }
let toastT = 0
function toast (s) { const t = $('#toast'); t.textContent = s; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => { t.hidden = true }, 2800) }
function genPass () {                                   // 3 nhóm 4 chữ số: dễ đọc qua điện thoại, ~40 bit
  const a = new Uint32Array(3); crypto.getRandomValues(a)
  return Array.from(a, (x) => String(x % 10000).padStart(4, '0')).join('-')
}

// ---------- khoá ----------
let signalPw = '', aesKey = null, keyTag = ''
async function deriveKeys (rid, linkKey, pass) {
  const base = await crypto.subtle.importKey('raw', te.encode(linkKey + '\u0000' + pass.normalize('NFC')), 'PBKDF2', false, ['deriveBits'])
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: te.encode('gan-nhau/v2/' + rid), iterations: 310000 }, base, 512))
  signalPw = hex(bits.slice(0, 32))
  aesKey = await crypto.subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt'])
  keyTag = hex(await crypto.subtle.digest('SHA-256', bits.slice(32))).slice(0, 16)
}
async function seal (name, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(name) }, aesKey, bytes))
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12)
  return out
}
async function open (name, data) {
  const u = data instanceof Uint8Array ? data : new Uint8Array(data)
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12), additionalData: te.encode(name) }, aesKey, u.slice(12)))
}

// ---------- trạng thái ----------
let room = null, roomId = '', linkKey = '', pass = ''
const me = { name: '', color: COLORS[0] }
let state = 'off'                 // off | waiting (chờ duyệt) | in (đã vào)
let hostId = ''                   // chủ phòng
let roster = []                   // thứ tự thành viên đã duyệt (chủ phòng đứng đầu)
let locked = false
const peers = new Map()           // peerId -> {name, color, rtt, ok}
const requests = new Map()        // chủ phòng: peerId -> {name}
const sendRaw = {}
let media = null, seq = 0, applying = 0
let castStream = null, yt = null, ytReady = null, pendingYt = null
let hbTimer = 0, typingT = 0, waitTimer = 0, wakeLock = null
const typingFrom = new Map()
const isHost = () => hostId === selfId
const approved = () => roster.filter((id) => id !== selfId && peers.has(id))

// ---------- link ----------
function parseLink (s) {
  const h = (String(s).includes('#') ? String(s).split('#')[1] : String(s)).trim()
  const m = h.match(/^([a-z0-9]{6,32})\.([a-z0-9]{12,64})$/)
  return m ? { roomId: m[1], key: m[2] } : null
}
function inviteLink () { return (native && native.webBase ? native.webBase() : location.origin + location.pathname) + '#' + roomId + '.' + linkKey }

// ---------- kênh mã hoá ----------
// mọi kênh: chỉ gửi tới / nhận từ người đã được duyệt, trừ 3 kênh "gõ cửa" (knock, roster, deny)
const OPEN_CH = new Set(['knock', 'roster', 'deny'])
function chan (name, onGet, binary = false) {
  const [s, g] = room.makeAction(name)
  sendRaw[name] = s
  g(async (data, id) => {
    const p = peers.get(id)
    if (!OPEN_CH.has(name) && !(p && p.ok)) return
    let plain
    try { plain = await open(name, data) } catch { return }       // sai khoá / bị sửa: bỏ
    onGet(binary ? plain : JSON.parse(td.decode(plain)), id)
  })
  return async (obj, target) => {
    const to = target ? [].concat(target) : approved()
    if (!to.length) return
    const box = await seal(name, binary ? obj : te.encode(JSON.stringify(obj)))
    s(box, to)
  }
}
const send = {}

// ---------- vào / rời phòng ----------
async function enter (rid, k, asHost) {
  pass = $('#pass').value.trim()
  if (pass.length < 6) { toast('Mật khẩu phòng cần ít nhất 6 ký tự'); $('#pass').focus(); return }
  roomId = rid; linkKey = k
  me.name = ($('#myName').value.trim() || store.get('gn-name') || 'Bạn').slice(0, 24)
  store.set('gn-name', me.name)
  me.color = COLORS[(parseInt(selfId.slice(0, 6), 36) || 0) % COLORS.length]
  history.replaceState(null, '', '#' + rid + '.' + k)
  $('#home').hidden = true; $('#room').hidden = false
  showWait('Đang tạo khoá…', 'Mất khoảng một giây.')
  await deriveKeys(rid, k, pass)
  // tìm nhau qua nhiều relay cùng lúc (relay chỉ thấy dữ liệu bắt tay đã mã hoá) để nhanh và ít phụ thuộc một relay
  room = joinRoom({ appId: APP_ID, password: signalPw, relayRedundancy: 8 }, roomId)
  wire()
  if (asHost) {
    state = 'in'; hostId = selfId; roster = [selfId]
    $('#waiting').hidden = true
    sys('Phòng đã sẵn sàng. Bấm “Mời” để gửi link, rồi nói mật khẩu cho người kia bằng lời.')
    openInvite()
  } else {
    state = 'waiting'
    const t0 = Date.now()
    const tick = () => {
      if (state !== 'waiting' || peers.size) return
      const s = Math.round((Date.now() - t0) / 1000)
      if (s < 20) showWait('Đang tìm phòng… ' + s + ' giây', 'Mở khoá bằng mật khẩu và kết nối thẳng tới người trong phòng. Thường mất 5–20 giây.')
      else if (s < 90) showWait('Vẫn đang tìm phòng… ' + s + ' giây', 'Mạng di động đôi khi cần tới 1 phút. Chủ phòng cần đang mở phòng trên màn hình.')
      else showWait('Chưa thấy ai trong phòng (' + s + ' giây)', 'App vẫn đang tìm. Kiểm tra: mật khẩu đúng (phân biệt hoa thường), chủ phòng đang mở phòng, thử cả hai cùng dùng Wi-Fi.')
      waitTimer = setTimeout(tick, 1000)
    }
    clearTimeout(waitTimer); tick()
  }
  renderPeople(); renderControls()
}

function leave () {
  try { room && room.leave() } catch {}
  stopCast(); history.replaceState(null, '', location.pathname); location.reload()
}

function showWait (title, text) {
  $('#waiting').hidden = false; $('#waitTitle').textContent = title; $('#waitText').textContent = text
}

// ---------- nối dây ----------
function wire () {
  send.knock = chan('knock', (d, id) => onKnock(d, id))
  send.roster = chan('roster', (d, id) => onRoster(d, id))
  send.deny = chan('deny', (d) => {
    if (state !== 'waiting') return
    showWait(d === 'locked' ? 'Phòng đã khoá' : 'Chủ phòng chưa cho vào', d === 'locked' ? 'Chủ phòng đã khoá phòng, không nhận thêm người.' : 'Bạn có thể hỏi lại chủ phòng rồi thử vào lại.')
    setTimeout(leave, 6000)
  })
  send.hello = chan('hello', (d, id) => { const p = peers.get(id); if (p) { p.name = String(d.name || 'Bạn').slice(0, 24); p.color = COLORS.includes(d.color) ? d.color : COLORS[1] } renderPeople() })
  send.chat = chan('chat', (d, id) => addMsg(peerName(id), String(d.text || ''), false, peerColor(id)))
  send.heart = chan('heart', () => burst())
  send.typing = chan('typing', (d, id) => { typingFrom.set(id, Date.now()); renderTyping() })
  send.sync = chan('sync', (d, id) => applyRemote(d, id))
  send.req = chan('req', (d, id) => { if (media && d === 'state') send.sync(stateMsg(), id) })
  send.img = chan('img', (bytes, id) => addImg(peerName(id), URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' })), false, peerColor(id)), true)

  room.onPeerJoin((id) => {
    if (!peers.has(id)) peers.set(id, { name: '', color: COLORS[1], ok: state === 'in' && roster.includes(id) })
    if (state === 'waiting') {                                   // mình đang xin vào: gõ cửa mọi người
      send.knock({ name: me.name, color: me.color }, id)
      showWait('Đang chờ chủ phòng cho vào…', 'Chủ phòng sẽ thấy tên bạn và mã xác minh. Gọi điện cho nhau để so mã nếu muốn chắc chắn.')
      renderWaitCodes()
    }
    renderPeople()
  })
  room.onPeerLeave((id) => {
    const p = peers.get(id); peers.delete(id); requests.delete(id); renderRequests()
    if (p && p.ok) sys((p.name || 'Một người') + ' đã rời phòng')
    if (id === hostId && state === 'in') {                       // chủ phòng đi: người vào sớm nhất làm chủ
      roster = roster.filter((x) => x !== id)
      hostId = roster.find((x) => x === selfId || peers.has(x)) || selfId
      if (isHost()) { sys('Bạn giờ là chủ phòng'); pushRoster() }
    } else if (isHost() && roster.includes(id)) { roster = roster.filter((x) => x !== id); pushRoster() }
    if (media && media.kind === 'stream' && media.by === id) { showOnly('empty'); media = null; info('') }
    renderPeople(); renderControls()
  })
  room.onPeerStream((stream, id) => {
    if (!(peers.get(id) && peers.get(id).ok)) { stream.getTracks().forEach((t) => t.stop()); return }
    const v = $('#remote'); v.srcObject = stream; showOnly('remote')
    v.play().catch(() => { $('#tapToJoin').hidden = false })
    info(peerName(id) + ' đang phát cho cả nhóm')
  })
  setInterval(async () => {                                      // đo độ trễ để bù khi đồng bộ
    for (const id of approved()) { try { const ms = await room.ping(id); const p = peers.get(id); if (p) p.rtt = ms } catch {} }
  }, 5000)
}

// chủ phòng nhận người gõ cửa
function onKnock (d, id) {
  if (!peers.has(id)) peers.set(id, { name: '', color: COLORS[1], ok: false })
  const p = peers.get(id); if (p.ok) return
  p.name = String(d.name || 'Ai đó').slice(0, 24); p.color = COLORS.includes(d.color) ? d.color : COLORS[1]
  if (!isHost()) { if (state === 'in') sys(p.name + ' đang chờ chủ phòng cho vào'); return }
  if (locked) { send.deny('locked', id); return }
  requests.set(id, { name: p.name }); renderRequests()
  notify(p.name + ' muốn vào phòng')
}

async function approve (id) {
  const p = peers.get(id); if (!p) return
  requests.delete(id); renderRequests()
  p.ok = true
  if (!roster.includes(id)) roster.push(id)
  pushRoster()
  sys(p.name + ' đã vào phòng')
  if (media) setTimeout(() => send.sync(stateMsg(), id), 600)
  if (castStream) room.addStream(castStream, id)
  renderPeople()
}
function deny (id) { requests.delete(id); renderRequests(); send.deny('no', id) }

function pushRoster () {
  const names = {}; for (const id of roster) names[id] = id === selfId ? { name: me.name, color: me.color } : { name: peerName(id), color: peerColor(id) }
  const msg = { host: selfId, members: roster, names, locked }
  const to = roster.filter((id) => id !== selfId && peers.has(id))
  if (to.length) send.roster(msg, to)
}

// thành viên nhận danh sách từ chủ phòng
function onRoster (d, id) {
  if (!d || !Array.isArray(d.members) || d.host !== id) return
  if (state === 'in' && id !== hostId) return                    // chỉ tin chủ phòng hiện tại
  if (!d.members.includes(selfId)) return
  const firstTime = state !== 'in'
  hostId = id; roster = d.members.slice(0, 12); locked = !!d.locked
  for (const [pid, p] of peers) {
    p.ok = roster.includes(pid)
    const nm = d.names && d.names[pid]; if (nm && p.ok) { p.name = String(nm.name || p.name).slice(0, 24); if (COLORS.includes(nm.color)) p.color = nm.color }
  }
  if (firstTime) {
    state = 'in'; clearTimeout(waitTimer); $('#waiting').hidden = true
    sys('Bạn đã vào phòng của ' + peerName(id) + '.')
    send.hello({ name: me.name, color: me.color })
    send.req('state', id)
  }
  renderPeople(); renderControls()
}

const peerName = (id) => (peers.get(id) && peers.get(id).name) || 'Bạn ấy'
const peerColor = (id) => (peers.get(id) && peers.get(id).color) || COLORS[1]

// ---------- mã xác minh ----------
async function verifyCode (id) {
  try {
    const all = room.getPeers ? room.getPeers() : {}
    const pc = all && (all[id] || (all.get && all.get(id)))
    if (!pc) return null
    const fp = (sdp) => ((sdp || '').match(/a=fingerprint:sha-256 ([0-9A-Fa-f:]+)/) || [])[1] || ''
    const a = fp((pc.currentLocalDescription || pc.localDescription || {}).sdp)
    const b = fp((pc.currentRemoteDescription || pc.remoteDescription || {}).sdp)
    if (!a || !b) return null
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode([a.toUpperCase(), b.toUpperCase()].sort().join('|') + '|' + keyTag)))
    const n = ((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3]
    const s = String(n % 100000000).padStart(8, '0')
    return s.slice(0, 4) + ' ' + s.slice(4)
  } catch { return null }
}
async function showVerify (id) {
  const c = await verifyCode(id)
  $('#verifyTitle').textContent = 'Mã xác minh với ' + peerName(id)
  $('#verifyCode').textContent = c || 'Chưa lấy được – thử lại sau vài giây'
  $('#verifyBox').hidden = false
}
async function renderWaitCodes () {
  const rows = []
  for (const id of peers.keys()) { const c = await verifyCode(id); rows.push(`<div>${esc(peerName(id))} · mã <b>${esc(c || '…')}</b></div>`) }
  $('#waitCodes').innerHTML = rows.join('')
}

// ---------- giao diện phòng ----------
function renderPeople () {
  const list = [{ id: selfId, ...me }, ...approved().map((id) => ({ id, ...peers.get(id) }))]
  $('#people').innerHTML = list.map((p) =>
    `<button class="person" data-id="${esc(p.id)}" title="${p.id === selfId ? 'Bạn' : 'Xem mã xác minh'}"><i style="background:${esc(p.color)}">${esc((p.name || '?')[0].toUpperCase())}</i>${esc(p.name || '…')}${p.id === selfId ? ' (bạn)' : ''}${p.id === hostId ? ' ★' : ''}</button>`).join('')
  $('#people').querySelectorAll('.person').forEach((b) => { if (b.dataset.id !== selfId) b.onclick = () => showVerify(b.dataset.id) })
  const n = approved().length
  $('#status').textContent = state !== 'in' ? 'Đang chờ…'
    : n === 0 ? (isHost() ? 'Chưa có ai. Gửi link + nói mật khẩu cho người kia.' : 'Chỉ còn bạn trong phòng')
      : `🔒 ${n + 1} người · nối thẳng, mã hoá hai lớp${locked ? ' · phòng đã khoá' : ''} · chạm tên để xem mã xác minh`
}
function renderControls () {
  $('#btnInvite').hidden = !(state === 'in' && isHost())
  $('#btnLock').hidden = !(state === 'in' && isHost())
  $('#btnLock').textContent = locked ? '🔒' : '🔓'
  $('#btnLock').classList.toggle('on', locked)
  $('#btnLock').title = locked ? 'Mở khoá phòng' : 'Khoá phòng (không nhận thêm người)'
}
async function renderRequests () {
  const box = $('#requests')
  const rows = []
  for (const [id, r] of requests) {
    const c = await verifyCode(id)
    rows.push(`<div class="req" data-id="${esc(id)}"><div class="t"><b>${esc(r.name)}</b> muốn vào phòng<br><span class="hint">Mã xác minh: <span class="code">${esc(c || '…')}</span> – đọc cho nhau để so</span></div><button class="primary" data-a="ok">Cho vào</button><button data-a="no">Từ chối</button></div>`)
  }
  box.innerHTML = rows.join('')
  box.querySelectorAll('.req').forEach((el) => {
    el.querySelector('[data-a=ok]').onclick = () => approve(el.dataset.id)
    el.querySelector('[data-a=no]').onclick = () => deny(el.dataset.id)
  })
}
function notify (t) { toast(t); try { navigator.vibrate && navigator.vibrate(120) } catch {} }

// ---------- chat ----------
function sys (t) { const d = document.createElement('div'); d.className = 'sys'; d.textContent = t; $('#msgs').append(d); scroll() }
function scroll () { const m = $('#msgs'); m.scrollTop = m.scrollHeight }
function addMsg (who, text, mine, color) {
  const d = document.createElement('div'); d.className = 'msg' + (mine ? ' me' : '')
  d.innerHTML = `<div class="meta" style="color:${esc(color)}">${esc(who)}</div><div class="b"></div>`
  d.querySelector('.b').textContent = text.slice(0, 2000)
  $('#msgs').append(d); scroll()
}
function addImg (who, url, mine, color) {
  const d = document.createElement('div'); d.className = 'msg' + (mine ? ' me' : '')
  d.innerHTML = `<div class="meta" style="color:${esc(color)}">${esc(who)}</div><div class="b"><img alt="Ảnh"></div>`
  const img = d.querySelector('img'); img.onload = scroll; img.src = url
  $('#msgs').append(d); scroll()
}
function renderTyping () {
  const now = Date.now(); const names = []
  for (const [id, t] of typingFrom) { if (now - t < 3000) names.push(peerName(id)); else typingFrom.delete(id) }
  $('#typing').textContent = names.length ? names.join(', ') + ' đang nhắn…' : ''
}
setInterval(renderTyping, 1000)
function burst () {
  for (let i = 0; i < 6; i++) {
    const s = document.createElement('span'); s.textContent = '♥'
    s.style.left = (10 + Math.random() * 80) + '%'; s.style.animationDelay = (i * 0.12) + 's'
    $('#hearts').append(s); setTimeout(() => s.remove(), 3200)
  }
}
// ảnh: vẽ lại qua canvas (bỏ hết thông tin ẩn như vị trí GPS, máy chụp) và thu nhỏ ≤ 1600 px
async function cleanImage (file) {
  const bmp = await createImageBitmap(file)
  const k = Math.min(1, 1600 / Math.max(bmp.width, bmp.height))
  const c = document.createElement('canvas'); c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k)
  c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height)
  return await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.85))
}

// ---------- xem / nghe chung ----------
function showOnly (which) {
  for (const id of ['empty', 'ytBox', 'vid', 'remote', 'webBox']) $('#' + id).hidden = id !== which
  $('#needFile').hidden = true; $('#tapToJoin').hidden = true; $('#ytAsk').hidden = true
  if (which !== 'vid') { const v = $('#vid'); if (!v.paused) { applying++; v.pause(); setTimeout(() => applying--, 300) } }
  if (which !== 'ytBox' && yt && yt.pauseVideo) { try { applying++; yt.pauseVideo(); setTimeout(() => applying--, 300) } catch {} }
  if (which === 'vid' || which === 'remote' || which === 'ytBox') keepAwake()
}
function info (t) { $('#nowInfo').textContent = t }
async function keepAwake () { try { if (!wakeLock && navigator.wakeLock) { wakeLock = await navigator.wakeLock.request('screen'); wakeLock.addEventListener('release', () => { wakeLock = null }) } } catch {} }

function ytId (u) {
  const m = String(u).match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?(?:.*&)?v=|embed\/|shorts\/|live\/))([A-Za-z0-9_-]{11})/)
  return m ? m[1] : null
}
const isMedia = (u) => /\.(mp4|webm|ogv|mov|m4v|mp3|m4a|aac|wav|ogg|opus|flac)(\?|#|$)/i.test(u)

function loadYT () {
  if (ytReady) return ytReady
  ytReady = new Promise((res) => {
    window.onYouTubeIframeAPIReady = () => res()
    const s = document.createElement('script'); s.src = 'https://www.youtube.com/iframe_api'; s.referrerPolicy = 'no-referrer'; document.head.append(s)
  })
  return ytReady
}
async function ytLoad (id, start, play) {
  await loadYT()
  showOnly('ytBox')
  if (!yt) {
    await new Promise((res) => {
      yt = new YT.Player('yt', {
        host: 'https://www.youtube-nocookie.com', videoId: id,
        playerVars: { playsinline: 1, rel: 0, start: Math.floor(start || 0) },
        events: { onReady: () => res(), onStateChange: onYtState }
      })
    })
  } else { applying++; yt.loadVideoById({ videoId: id, startSeconds: start || 0 }); setTimeout(() => applying--, 800) }
  if (!play) { applying++; setTimeout(() => { try { yt.pauseVideo() } catch {} ; setTimeout(() => applying--, 400) }, 600) }
}
function onYtState (e) {
  if (applying > 0 || !media || media.kind !== 'yt') return
  if (e.data === YT.PlayerState.PLAYING) localChange({ playing: true, t: yt.getCurrentTime() })
  else if (e.data === YT.PlayerState.PAUSED) localChange({ playing: false, t: yt.getCurrentTime() })
}
function curTime () {
  if (!media) return 0
  if (media.kind === 'yt') return yt && yt.getCurrentTime ? yt.getCurrentTime() : media.t
  return $('#vid').currentTime
}
function isPlaying () {
  if (!media) return false
  if (media.kind === 'yt') return !!(yt && yt.getPlayerState && yt.getPlayerState() === 1)
  return !$('#vid').paused
}
function stateMsg () { return { ...media, t: curTime(), playing: isPlaying(), seq } }
function localChange (p) {
  if (!media) return
  media = { ...media, ...p, by: selfId }; seq++
  send.sync({ ...media, seq }); heartbeat()
}
function heartbeat () {
  clearInterval(hbTimer)
  hbTimer = setInterval(() => {
    if (!media || media.by !== selfId || media.kind === 'stream' || media.kind === 'web') return
    if (isPlaying()) send.sync({ ...media, t: curTime(), playing: true, hb: 1, seq })
  }, 4000)
}
function startMedia (m) { media = { ...m, by: selfId, playing: false, t: 0 }; seq++; send.sync({ ...media, seq }); heartbeat() }

async function applyRemote (d, from) {
  if (!d || typeof d.kind !== 'string') return
  const lat = ((peers.get(from) && peers.get(from).rtt) || 120) / 2000
  const target = Math.max(0, Number(d.t) || 0) + (d.playing ? lat : 0)
  const same = media && media.kind === d.kind && media.src === d.src
  if (!d.hb) info(peerName(from) + (d.playing ? ' đang phát' : ' đã dừng') + (d.name ? ' · ' + String(d.name).slice(0, 80) : ''))
  media = { kind: d.kind, src: String(d.src || ''), name: String(d.name || '').slice(0, 120), size: Number(d.size) || 0, playing: !!d.playing, t: target, rate: Number(d.rate) || 1, by: from }
  if (d.kind === 'web') {
    if (!/^https?:\/\//i.test(media.src)) return
    showOnly('webBox'); $('#webLink').textContent = media.src; return
  }
  if (d.kind === 'stream') return
  if (d.kind === 'yt') {
    if (!/^[A-Za-z0-9_-]{11}$/.test(media.src)) return
    if (!ytReady) {                                              // chưa đồng ý dùng YouTube: hỏi trước
      pendingYt = { id: media.src, t: target, playing: media.playing }
      showOnly('empty'); $('#ytAskText').textContent = peerName(from) + ' mở một video YouTube. Xem bằng trình phát YouTube? Google sẽ biết video này được xem.'
      $('#ytAsk').hidden = false; return
    }
    if (!same || !yt) { await ytLoad(media.src, target, media.playing); if (media.playing) tryPlay(); return }
    const drift = Math.abs(yt.getCurrentTime() - target)
    applying++
    try {
      if (drift > (d.hb ? 1.0 : 0.4)) yt.seekTo(target, true)
      if (media.playing && yt.getPlayerState() !== 1) yt.playVideo()
      if (!media.playing && yt.getPlayerState() === 1) yt.pauseVideo()
    } finally { setTimeout(() => applying--, 500) }
    return
  }
  const v = $('#vid')
  if (!same) {
    if (d.kind === 'url') { if (!/^https:\/\//i.test(media.src)) return; showOnly('vid'); v.src = media.src } else if (d.kind === 'file') {
      showOnly('vid'); v.removeAttribute('src'); v.load()
      $('#needFileText').innerHTML = `${esc(peerName(from))} đang mở file <b>${esc(media.name)}</b>${media.size ? ' (' + (media.size / 1048576).toFixed(1) + ' MB)' : ''}.<br>Chọn đúng file đó trên máy bạn để xem cùng.`
      $('#needFile').hidden = false
      return
    } else return
  }
  if (d.kind === 'file' && !v.src) return
  syncEl(v, target, media.playing, d.hb)
}
function syncEl (v, target, playing, hb) {
  applying++
  try {
    const drift = Math.abs(v.currentTime - target)
    if (drift > (hb ? 0.8 : 0.3)) v.currentTime = target
    else if (hb && playing && drift > 0.12) {
      v.playbackRate = v.currentTime < target ? 1.05 : 0.95
      setTimeout(() => { v.playbackRate = media && media.rate ? media.rate : 1 }, 2500)
    }
    if (playing && v.paused) v.play().catch(() => { $('#tapToJoin').hidden = false })
    if (!playing && !v.paused) v.pause()
  } finally { setTimeout(() => applying--, 400) }
}
function tryPlay () {
  try { yt.playVideo() } catch {}
  setTimeout(() => { if (media && media.playing && yt && yt.getPlayerState && yt.getPlayerState() !== 1) $('#tapToJoin').hidden = false }, 1500)
}
const vid = $('#vid')
for (const ev of ['play', 'pause', 'seeked', 'ratechange']) {
  vid.addEventListener(ev, () => {
    if (applying > 0 || !media || (media.kind !== 'url' && media.kind !== 'file')) return
    localChange({ playing: !vid.paused, t: vid.currentTime, rate: vid.playbackRate })
  })
}

function stopCast () {
  if (castStream) { try { room && room.removeStream(castStream) } catch {} ; castStream.getTracks().forEach((t) => { try { t.stop() } catch {} }) }
  castStream = null
}
function castFrom (stream, label) {
  stopCast(); castStream = stream
  const to = approved(); if (to.length) room.addStream(stream, to)
  startMedia({ kind: 'stream', src: 'stream-' + rand(6), name: label })
  info('Bạn đang phát cho cả nhóm: ' + label)
}

// ---------- nút bấm ----------
document.querySelectorAll('.source-tabs button').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('.source-tabs button').forEach((x) => x.classList.toggle('on', x === b))
  document.querySelectorAll('.source-pane').forEach((p) => { p.hidden = p.dataset.pane !== b.dataset.src })
}))
if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia || native) $('#tabScreen').hidden = true

$('#btnLink').onclick = async () => {
  const u = $('#linkInput').value.trim(); if (!u) return
  const id = ytId(u)
  if (id) { await ytLoad(id, 0, false); startMedia({ kind: 'yt', src: id, name: 'YouTube' }); info('Bấm ▶ trên video, cả phòng sẽ phát cùng lúc'); return }
  if (!/^https:\/\//i.test(u)) { toast('Chỉ nhận link bắt đầu bằng https:// (an toàn)'); return }
  if (isMedia(u)) { showOnly('vid'); vid.src = u; startMedia({ kind: 'url', src: u, name: decodeURIComponent(u.split('/').pop().split('?')[0]).slice(0, 80) }); info('Bấm ▶ để phát cùng nhau'); return }
  showOnly('webBox'); $('#webLink').textContent = u
  startMedia({ kind: 'web', src: u, name: 'Trang web' })
}
$('#btnOpenWeb').onclick = () => { const u = $('#webLink').textContent; if (/^https?:\/\//i.test(u)) { if (native && native.openUrl) native.openUrl(u); else { const a = document.createElement('a'); a.href = u; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.click() } } }
$('#btnCopyWeb').onclick = () => copyText($('#webLink').textContent)
$('#btnYtOk').onclick = async () => { $('#ytAsk').hidden = true; const p = pendingYt; pendingYt = null; if (p) { await ytLoad(p.id, p.t, p.playing); if (p.playing) tryPlay() } }
$('#btnYtNo').onclick = () => { $('#ytAsk').hidden = true; pendingYt = null; info('Bạn đã không mở YouTube') }

$('#fileLocal').onchange = (e) => {
  const f = e.target.files[0]; if (!f) return
  showOnly('vid'); vid.src = URL.createObjectURL(f)
  startMedia({ kind: 'file', src: f.name + ':' + f.size, name: f.name, size: f.size })
  info('Đã báo mọi người mở file “' + f.name + '”. Bấm ▶ khi tất cả sẵn sàng.')
}
$('#fileMatch').onchange = (e) => {
  const f = e.target.files[0]; if (!f || !media) return
  if (media.size && f.size !== media.size) toast('File này khác file của bạn ấy (dung lượng khác) – vẫn mở thử')
  vid.src = URL.createObjectURL(f); $('#needFile').hidden = true
  vid.addEventListener('loadedmetadata', () => { send.req('state', media.by) }, { once: true })
}
$('#fileCast').onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return
  showOnly('vid'); vid.src = URL.createObjectURL(f)
  await new Promise((r) => vid.addEventListener('loadedmetadata', r, { once: true }))
  try { await vid.play() } catch {}
  const s = vid.captureStream ? vid.captureStream() : vid.mozCaptureStream ? vid.mozCaptureStream() : null
  if (!s) { toast('Trình duyệt này chưa phát được cho nhóm – dùng Chrome / Edge hoặc app Android'); return }
  media = null
  castFrom(s, f.name)
}
$('#btnScreen').onclick = async () => {
  try {
    const s = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true })
    showOnly('remote'); $('#remote').srcObject = s; $('#remote').muted = true
    s.getVideoTracks()[0].addEventListener('ended', () => { stopCast(); showOnly('empty'); info('') })
    castFrom(s, 'Màn hình của ' + me.name)
  } catch { toast('Chưa chia sẻ màn hình') }
}
$('#tapToJoin').onclick = () => {
  $('#tapToJoin').hidden = true
  if (media && media.kind === 'yt') { try { yt.playVideo() } catch {} } else if (!$('#remote').hidden) $('#remote').play().catch(() => {})
  else vid.play().catch(() => {})
}

$('#chatForm').onsubmit = (e) => {
  e.preventDefault()
  const t = $('#chatInput').value.trim(); if (!t) return
  send.chat({ text: t }); addMsg(me.name, t, true, me.color)
  $('#chatInput').value = ''
}
$('#chatInput').oninput = () => { if (Date.now() - typingT > 1500) { typingT = Date.now(); send.typing(1) } }
$('#btnHeart').onclick = () => { burst(); send.heart(1) }
$('#pic').onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return
  try {
    const b = await cleanImage(f)
    addImg(me.name, URL.createObjectURL(b), true, me.color)
    await send.img(new Uint8Array(await b.arrayBuffer()))
  } catch { toast('Không gửi được ảnh này') }
  e.target.value = ''
}

async function copyText (t) {
  if (native && native.copy) { native.copy(t); toast('Đã chép'); return }
  try { await navigator.clipboard.writeText(t); toast('Đã chép') } catch { toast('Bấm giữ để chép') }
}
function openInvite () { $('#inviteLink').value = inviteLink(); $('#passShow').textContent = pass; $('#inviteBox').hidden = false }
$('#btnInvite').onclick = openInvite
$('#btnClose').onclick = () => { $('#inviteBox').hidden = true }
$('#btnCopy').onclick = () => copyText(inviteLink())
$('#btnShare').onclick = async () => {
  const text = 'Vào phòng Gần Nhau với mình nhé (mật khẩu mình sẽ nói riêng): ' + inviteLink()
  if (native && native.share) { native.share(text); return }
  if (navigator.share) { try { await navigator.share({ text }) } catch {} } else copyText(inviteLink())
}
$('#btnLock').onclick = () => {
  locked = !locked; renderControls(); renderPeople(); pushRoster()
  toast(locked ? 'Đã khoá phòng: không nhận thêm người' : 'Đã mở khoá phòng')
  if (locked) for (const id of requests.keys()) deny(id)
}
$('#btnVerifyClose').onclick = () => { $('#verifyBox').hidden = true }
$('#btnLeave').onclick = leave
$('#btnWaitLeave').onclick = leave
setInterval(() => { if (state === 'waiting' && peers.size) renderWaitCodes(); if (requests.size) renderRequests() }, 3000)

// ---------- màn hình đầu ----------
$('#myName').value = store.get('gn-name') || ''
$('#btnGen').onclick = () => { $('#pass').value = genPass() }
$('#btnCreate').onclick = () => { if (!$('#pass').value.trim()) $('#pass').value = genPass(); enter(rand(12), rand(24), true) }
$('#btnJoin').onclick = () => {
  const p = parseLink($('#joinLink').value)
  if (!p) { toast('Link mời chưa đúng – hãy dán nguyên link'); return }
  enter(p.roomId, p.key, false)
}
function invitedMode (p) {
  $('#lead').textContent = 'Bạn được mời vào một phòng. Nhập mật khẩu người mời nói với bạn.'
  $('#btnGen').hidden = true; $('#passHint').textContent = 'Mật khẩu do người mời báo riêng (không có trong link).'
  $('#btnCreate').textContent = 'Vào phòng'; $('#joinBlock').hidden = true
  $('#btnCreate').onclick = () => enter(p.roomId, p.key, false)
  $('#pass').focus()
}
const fromHash = parseLink(location.hash.slice(1))
if (fromHash) invitedMode(fromHash)
window.addEventListener('hashchange', () => { const p = parseLink(location.hash.slice(1)); if (p && state === 'off') invitedMode(p) })

// cho kiểm thử tự động
window.__gn = { peers, get state () { return state }, get hostId () { return hostId }, selfId, verifyCode, approve, get requests () { return requests } }
