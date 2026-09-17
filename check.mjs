// Monitor de disponibilidade dos sites da Agência Gota e dos clientes.
// Roda no GitHub Actions a cada 5 minutos e avisa no WhatsApp (CallMeBot) quando um site
// cai e quando volta. Os endereços ficam no secret SITES (um por linha, "Nome|https://url"),
// então nada sobre clientes fica visível no repositório.
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'

const STATE_FILE = 'state.json'
const FALHAS_PARA_ALERTAR = 2 // 2 checagens seguidas (~10 min) evita alarme por oscilação
const TIMEOUT_MS = 20000

const sites = (process.env.SITES || '')
  .split('\n')
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith('#'))
  .map((l) => {
    const [nome, url] = l.includes('|') ? l.split('|').map((s) => s.trim()) : [l, l]
    return { nome, url }
  })

if (!sites.length) {
  console.error('Secret SITES vazio')
  process.exit(1)
}

const chave = (url) => createHash('sha256').update(url).digest('hex').slice(0, 16)
const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, 'utf8')) : {}

async function checar(url) {
  const inicio = Date.now()
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; GotaMonitor/1.0)' },
    })
    const ms = Date.now() - inicio
    // 429 = bloqueio por excesso de acesso: site no ar, não é queda
    const ok = res.status < 500 && res.status !== 404
    return { ok, detalhe: `HTTP ${res.status}`, ms }
  } catch (e) {
    const motivo = e?.name === 'TimeoutError' ? `sem resposta em ${TIMEOUT_MS / 1000}s` : (e?.cause?.code || e?.message || 'erro de conexão')
    return { ok: false, detalhe: motivo, ms: Date.now() - inicio }
  }
}

async function whatsapp(texto) {
  const phone = process.env.CALLMEBOT_PHONE
  const apikey = process.env.CALLMEBOT_APIKEY
  if (!phone || !apikey) {
    console.log('[sem WhatsApp configurado]', texto)
    return
  }
  const url = `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(phone)}&text=${encodeURIComponent(texto)}&apikey=${encodeURIComponent(apikey)}`
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) }).catch((e) => ({ ok: false, status: e.message }))
  console.log('WhatsApp enviado:', res.status)
}

const hora = () => new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'short', timeStyle: 'short' })
const duracao = (desde) => {
  const min = Math.round((Date.now() - desde) / 60000)
  return min < 60 ? `${min} min` : `${Math.floor(min / 60)}h${String(min % 60).padStart(2, '0')}`
}

let mudou = false
for (const site of sites) {
  const k = chave(site.url)
  const s = state[k] || { falhas: 0, fora: false, desde: null }
  const r = await checar(site.url)
  console.log(`${r.ok ? 'OK  ' : 'FALHA'} ${site.nome} ${r.detalhe} ${r.ms}ms`)

  if (r.ok) {
    if (s.fora) {
      await whatsapp(`✅ ${site.nome} voltou ao ar (${hora()}).\nFicou fora por ${duracao(s.desde)}.\n${site.url}`)
    }
    if (s.falhas || s.fora) mudou = true
    state[k] = { falhas: 0, fora: false, desde: null }
  } else {
    s.falhas += 1
    if (!s.desde) s.desde = Date.now()
    if (!s.fora && s.falhas >= FALHAS_PARA_ALERTAR) {
      await whatsapp(`🚨 ${site.nome} está FORA DO AR (${hora()}).\nMotivo: ${r.detalhe}.\n${site.url}`)
      s.fora = true
    }
    state[k] = s
    mudou = true
  }
}

if (mudou) writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + '\n')
