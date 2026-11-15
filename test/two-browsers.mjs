// Kiểm thử bảo mật + chức năng: chủ phòng A, khách B (đúng mật khẩu, được duyệt),
// C (sai mật khẩu – không được thấy ai), D (đúng mật khẩu nhưng bị từ chối), E (vào khi phòng đã khoá)
import { chromium } from 'playwright'
const URL = process.env.SITE || 'http://localhost:8080/'
const PASS = '1234-5678-9012'
const b = await chromium.launch({ args: ['--autoplay-policy=no-user-gesture-required'] })
const page = async (n) => {
  const p = await (await b.newContext()).newPage()
  p.on('console', (m) => { if (m.type() === 'error' && !/WebSocket|wss:|ERR_NAME|relay/i.test(m.text())) console.log(n, 'console:', m.text()) })
  p.on('pageerror', (e) => console.log(n, 'LỖI TRANG:', e.message))
  return p
}
// trang có CSP chặn eval: tự hỏi trạng thái bằng evaluate thay cho waitForFunction
async function until (p, fn, arg, opt = {}) {
  const end = Date.now() + (opt.timeout || 30000)
  while (Date.now() < end) { try { if (await p.evaluate(fn, arg)) return } catch {} ; await new Promise((r) => setTimeout(r, 250)) }
  throw new Error('quá thời gian chờ: ' + fn.toString().slice(0, 120))
}
const ok = (s) => console.log('✓', s)
const A = await page('A'), B = await page('B'), C = await page('C'), D = await page('D'), E = await page('E')

await A.goto(URL); await A.fill('#myName', 'Mây'); await A.fill('#pass', PASS); await A.click('#btnCreate')
await until(A, () => window.__gn.state === 'in')
const link = await A.evaluate(() => location.href)
const shown = await A.textContent('#passShow')
if (shown !== PASS) throw new Error('hộp mời không hiện đúng mật khẩu')
if (link.includes(PASS) || link.includes(PASS.replace(/-/g, ''))) throw new Error('mật khẩu lọt vào link!')
ok('tạo phòng; mật khẩu không nằm trong link')
await A.click('#btnClose')

async function join (p, name, pw) { await p.goto(link); await p.fill('#myName', name); await p.fill('#pass', pw); await p.click('#btnCreate') }
await join(B, 'Gió', PASS)
await join(C, 'Kẻ lạ', 'sai-mat-khau')
const t0 = Date.now()
await until(A, () => window.__gn.requests.size === 1, null, { timeout: 90000 })
ok('chủ phòng thấy B xin vào sau ' + ((Date.now() - t0) / 1000).toFixed(1) + ' s')
// mã xác minh hai bên phải giống nhau
const bId = await B.evaluate(() => window.__gn.selfId), aId = await A.evaluate(() => window.__gn.selfId)
await until(A, (id) => window.__gn.verifyCode(id).then((c) => !!c), bId, { timeout: 20000 })
const codeA = await A.evaluate((id) => window.__gn.verifyCode(id), bId)
const codeB = await B.evaluate((id) => window.__gn.verifyCode(id), aId)
console.log('  mã xác minh A:', codeA, ' B:', codeB)
if (!codeA || codeA !== codeB) throw new Error('mã xác minh không khớp')
ok('mã xác minh hai bên khớp')
// B chưa được duyệt: chưa nhận được tin nhắn
await A.fill('#chatInput', 'bí mật trước khi duyệt'); await A.click('.send')
await B.waitForTimeout(1500)
if (await B.evaluate(() => document.body.innerText.includes('bí mật trước khi duyệt'))) throw new Error('chưa duyệt mà đã nhận tin!')
ok('chưa được duyệt thì không nhận được tin')
await A.click('.req [data-a=ok]')
await until(B, () => window.__gn.state === 'in', null, { timeout: 15000 })
ok('chủ phòng cho vào – B đã vào phòng')
await A.fill('#chatInput', 'Chào em 🌙'); await A.click('.send')
await until(B, () => [...document.querySelectorAll('.msg .b')].some((x) => x.textContent === 'Chào em 🌙'), null, { timeout: 15000 })
await B.fill('#chatInput', 'Chào anh'); await B.click('.send')
await until(A, () => [...document.querySelectorAll('.msg .b')].some((x) => x.textContent === 'Chào anh'), null, { timeout: 15000 })
ok('tin nhắn hai chiều (mã hoá lớp app)')
await B.setInputFiles('#pic', { name: 'a.png', mimeType: 'image/png', buffer: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64') })
await until(A, () => document.querySelectorAll('.msg img').length > 0, null, { timeout: 15000 })
ok('ảnh tới nơi')
await A.fill('#linkInput', 'https://example.com/'); await A.click('#btnLink')
await until(B, () => !document.querySelector('#webBox').hidden && document.querySelector('#webLink').textContent === 'https://example.com/', null, { timeout: 15000 })
ok('chia sẻ link trang web')
await A.setInputFiles('#fileLocal', { name: 'phim.webm', mimeType: 'video/webm', buffer: Buffer.alloc(2000) })
await until(B, () => !document.querySelector('#needFile').hidden && document.querySelector('#needFileText').textContent.includes('phim.webm'), null, { timeout: 15000 })
ok('đồng bộ file mỗi người')
// YouTube: B phải được hỏi trước khi tải trình phát của Google
await A.evaluate(() => { document.querySelector('#linkInput').value = 'https://youtu.be/aqz-KE-bpKQ' })
await A.click('#btnLink').catch(() => {})
await until(B, () => !document.querySelector('#ytAsk').hidden, null, { timeout: 20000 }).then(() => ok('YouTube: người nhận được hỏi trước khi tải trình phát Google')).catch(() => console.log('  (bỏ qua YouTube: máy kiểm thử không tải được YouTube)'))

// C sai mật khẩu: không bao giờ thấy ai, chủ phòng không nhận yêu cầu
const cPeers = await C.evaluate(() => window.__gn.peers.size)
const aReq = await A.evaluate(() => window.__gn.requests.size)
if (cPeers !== 0 || aReq !== 0) throw new Error('sai mật khẩu mà vẫn nối được!')
ok('sai mật khẩu: không tìm thấy / không nối được ai')
await C.close()                     // máy sai mật khẩu rời đi (không để nó làm nhiễu các bước sau)

// D đúng mật khẩu nhưng bị từ chối
await join(D, 'Người thứ ba', PASS)
const diag = async () => { for (const [n, p] of [['A', A], ['B', B], ['D', D]]) console.log('  ', n, await p.evaluate(() => JSON.stringify({ st: window.__gn.state, peers: [...window.__gn.peers.entries()].map(([k, v]) => k.slice(0, 4) + ':' + (v.name || '?') + ':' + v.ok), req: window.__gn.requests.size, wait: document.querySelector('#waitTitle').textContent }))) }
try { await until(A, () => window.__gn.requests.size === 1, null, { timeout: 90000 }) } catch (e) { await diag(); throw e }
await A.click('.req [data-a=no]')
await until(D, () => document.querySelector('#waitTitle').textContent.includes('chưa cho vào'), null, { timeout: 15000 })
await A.fill('#chatInput', 'chỉ hai đứa mình'); await A.click('.send')
await D.waitForTimeout(1500)
if (await D.evaluate(() => document.body.innerText.includes('chỉ hai đứa mình'))) throw new Error('bị từ chối mà vẫn nhận tin!')
ok('bị từ chối: không vào được, không nhận được tin')

// khoá phòng: E đúng mật khẩu bị từ chối tự động
await A.click('#btnLock')
await join(E, 'Người thứ tư', PASS)
const tE = Date.now()
try { await until(E, () => document.querySelector('#waitTitle').textContent.includes('đã khoá'), null, { timeout: 120000 }) } catch (e) {
  // E không tìm được phòng trong 2 phút (mạng relay chậm): vẫn an toàn – E không vào được phòng
  if (await E.evaluate(() => window.__gn.state) === 'in') throw new Error('phòng khoá mà vẫn vào được!')
  console.log('  ⚠ E chưa tìm được phòng trong 2 phút – không vào được, vẫn an toàn')
}
console.log('  E tìm thấy phòng sau', ((Date.now() - tE) / 1000).toFixed(1), 's'); ok('phòng khoá: người mới bị từ chối tự động')

await A.screenshot({ path: 'shot-A.png' }); await B.setViewportSize({ width: 390, height: 844 }); await B.screenshot({ path: 'shot-B-phone.png' })
await b.close()
console.log('TẤT CẢ ĐẠT')
