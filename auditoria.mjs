// Auditoria semanal dos sites da Agência Gota e dos clientes.
//
// O monitor de 5 minutos (check.mjs) responde "o site está no ar?". Este aqui
// responde "o site continua certo?", que é a pergunta que ninguém lembra de
// fazer depois do lançamento. Confere, de fora, o que dá pra conferir de fora:
// cabeçalho de segurança, SPF e DMARC do domínio, e a higiene básica de HTML
// que vale como acessibilidade e SEO.
//
// O que NÃO dá pra checar daqui: dependência vulnerável (npm audit precisa do
// repositório do site, não do domínio) e Core Web Vitals de campo (precisa de
// volume de visita real). Dependência fica com o Dependabot em cada repositório.
//
// Manda WhatsApp só quando encontra problema. Semana limpa não gera mensagem,
// senão o aviso vira ruído e para de ser lido. O relatório completo fica
// sempre commitado em auditoria.md, com histórico no Git.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { resolveTxt } from 'node:dns/promises'

const ARQUIVO_RELATORIO = 'auditoria.md'
const TIMEOUT_MS = 25000

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

// grave  = risco de segurança ou obrigação legal
// medio  = está errado, mas não expõe ninguém hoje
// aviso  = vale melhorar
const GRAVE = 'grave'
const MEDIO = 'medio'
const AVISO = 'aviso'

function dominioDe(url) {
  const host = new URL(url).hostname.replace(/^www\./, '')
  return host
}

// Consulta TXT por DNS-over-HTTPS, com o resolvedor do sistema como reserva.
// DoH primeiro porque runner e máquina de trabalho às vezes bloqueiam a porta
// 53, e um bloqueio de porta não pode virar "o domínio não tem SPF".
// Devolve null quando a consulta falhou, que é diferente de devolver lista
// vazia (domínio consultado e sem registro). Confundir os dois é o que gera
// alarme falso, e alarme falso mata monitor.
async function txt(nome) {
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(nome)}&type=TXT`, {
      signal: AbortSignal.timeout(15000),
      headers: { accept: 'application/dns-json' },
    })
    if (res.ok) {
      const dados = await res.json()
      // 0 = sucesso, 3 = domínio não existe. Os dois são resposta, não falha.
      if (dados.Status === 0 || dados.Status === 3) {
        return (dados.Answer || [])
          .filter((r) => r.type === 16)
          .map((r) => String(r.data).replace(/^"|"$/g, '').replace(/" "/g, ''))
      }
    }
  } catch {
    // cai para o resolvedor do sistema
  }
  try {
    return (await resolveTxt(nome)).map((partes) => partes.join(''))
  } catch {
    return null
  }
}

async function checarDns(dominio) {
  const achados = []
  const registros = await txt(dominio)
  if (registros === null) {
    achados.push([AVISO, 'Não foi possível consultar o DNS deste domínio nesta execução (SPF e DMARC não verificados)'])
    return achados
  }
  const spf = registros.filter((r) => r.toLowerCase().startsWith('v=spf1'))

  if (spf.length === 0) {
    achados.push([GRAVE, 'Sem SPF: qualquer um consegue enviar e-mail se passando por este domínio'])
  } else if (spf.length > 1) {
    achados.push([GRAVE, `${spf.length} registros SPF no mesmo domínio: a especificação permite um só, com mais de um o SPF é ignorado`])
  } else if (/\?all/.test(spf[0])) {
    achados.push([MEDIO, 'SPF em modo neutro (?all), que não rejeita nada'])
  }

  const registrosDmarc = await txt('_dmarc.' + dominio)
  if (registrosDmarc === null) {
    achados.push([AVISO, 'Não foi possível consultar o DMARC deste domínio nesta execução'])
    return achados
  }
  const dmarc = registrosDmarc.filter((r) => r.toLowerCase().startsWith('v=dmarc1'))
  if (dmarc.length === 0) {
    achados.push([GRAVE, 'Sem DMARC: nada impede falsificação de remetente neste domínio'])
  } else if (/p=none/i.test(dmarc[0])) {
    achados.push([AVISO, 'DMARC em p=none: só observa, não bloqueia. Subir para quarantine depois de conferir os relatórios'])
  }

  return achados
}

function checarCabecalhos(h) {
  const achados = []
  const get = (n) => h.get(n) || ''

  const hsts = get('strict-transport-security')
  if (!hsts) {
    achados.push([GRAVE, 'Sem Strict-Transport-Security (HSTS)'])
  } else {
    const idade = Number((hsts.match(/max-age=(\d+)/) || [])[1] || 0)
    if (idade < 31536000) achados.push([MEDIO, `HSTS com max-age de ${idade}s, abaixo de 1 ano`])
    if (!/includesubdomains/i.test(hsts)) achados.push([AVISO, 'HSTS sem includeSubDomains'])
  }

  const csp = get('content-security-policy')
  if (!csp) {
    achados.push([GRAVE, 'Sem Content-Security-Policy'])
  } else {
    const temFrameAncestors = /frame-ancestors/i.test(csp)
    const temXFO = /^(deny|sameorigin)$/i.test(get('x-frame-options').trim())
    if (!temFrameAncestors && !temXFO) {
      achados.push([GRAVE, 'Sem frame-ancestors no CSP e sem X-Frame-Options: o site pode ser embutido em iframe de terceiro (clickjacking)'])
    } else if (!temFrameAncestors) {
      achados.push([AVISO, 'Protegido só por X-Frame-Options, que foi tornado obsoleto pelo frame-ancestors do CSP'])
    }
    for (const [diretiva, recado] of [
      ['object-src', "Sem object-src 'none' no CSP"],
      ['base-uri', "Sem base-uri 'self' no CSP"],
      ['form-action', "Sem form-action 'self' no CSP"],
    ]) {
      if (!new RegExp(diretiva, 'i').test(csp)) achados.push([MEDIO, recado])
    }
    const scriptSrc = (csp.match(/script-src([^;]*)/i) || [])[1] || ''
    if (/unsafe-inline/i.test(scriptSrc)) {
      achados.push([AVISO, "script-src com 'unsafe-inline', que enfraquece a proteção contra XSS. Saída é CSP com nonce"])
    }
  }

  if (!/nosniff/i.test(get('x-content-type-options'))) achados.push([MEDIO, 'Sem X-Content-Type-Options: nosniff'])
  if (!get('referrer-policy')) achados.push([MEDIO, 'Sem Referrer-Policy'])
  if (!get('permissions-policy')) achados.push([AVISO, 'Sem Permissions-Policy'])
  if (get('x-xss-protection')) achados.push([AVISO, 'X-XSS-Protection presente: o recurso não existe mais em navegador atual e o OWASP pede para remover'])
  if (get('x-powered-by')) achados.push([AVISO, `X-Powered-By expõe a stack (${get('x-powered-by')})`])

  return achados
}

function checarHtml(html) {
  const achados = []

  if (!/<html[^>]*\blang=/i.test(html)) {
    achados.push([GRAVE, 'Sem atributo lang no <html>: leitor de tela não sabe em que idioma ler (WCAG 3.1.1, obrigação da LBI art. 63)'])
  }

  const h1 = (html.match(/<h1\b/gi) || []).length
  if (h1 === 0) achados.push([MEDIO, 'Página sem <h1>'])
  if (h1 > 1) achados.push([MEDIO, `Página com ${h1} elementos <h1>, deveria ter um só`])

  const imgs = html.match(/<img\b[^>]*>/gi) || []
  const semAlt = imgs.filter((i) => !/\balt=/i.test(i)).length
  if (semAlt) achados.push([GRAVE, `${semAlt} de ${imgs.length} imagens sem atributo alt (WCAG 1.1.1)`])

  const titulo = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]
  if (!titulo) achados.push([MEDIO, 'Sem <title>'])
  else if (titulo.trim().length > 65) achados.push([AVISO, `<title> com ${titulo.trim().length} caracteres, o Google costuma cortar acima de 60`])

  const desc = (html.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']*)["']/i) || [])[1]
  if (!desc) achados.push([MEDIO, 'Sem meta description'])
  else if (desc.length < 80 || desc.length > 165) achados.push([AVISO, `Meta description com ${desc.length} caracteres, fora da faixa de 80 a 165`])

  return achados
}

async function auditar(site) {
  try {
    const res = await fetch(site.url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; GotaAuditoria/1.0)' },
    })
    const html = await res.text()
    const achados = [
      ...checarCabecalhos(res.headers),
      ...checarHtml(html),
      ...(await checarDns(dominioDe(site.url))),
    ]
    if (!res.url.startsWith('https://')) achados.unshift([GRAVE, 'Site não está em HTTPS'])
    return { ok: true, status: res.status, achados }
  } catch (e) {
    return { ok: false, status: 0, achados: [[GRAVE, `Não respondeu: ${e?.message || 'erro de conexão'}`]] }
  }
}

async function whatsapp(texto) {
  const phone = process.env.CALLMEBOT_PHONE
  const apikey = process.env.CALLMEBOT_APIKEY
  if (!phone || !apikey) {
    console.log('[sem WhatsApp configurado]\n' + texto)
    return
  }
  const url = `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(phone)}&text=${encodeURIComponent(texto)}&apikey=${encodeURIComponent(apikey)}`
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) }).catch((e) => ({ status: e.message }))
  console.log('WhatsApp enviado:', res.status)
}

const agora = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'short', timeStyle: 'short' })
const resultados = []

for (const site of sites) {
  const r = await auditar(site)
  resultados.push({ site, ...r })
  const graves = r.achados.filter(([s]) => s === GRAVE).length
  console.log(`${graves ? 'PROBLEMA' : 'ok      '} ${site.nome}: ${r.achados.length} achados (${graves} graves)`)
}

// relatório completo, sempre, com histórico no Git
const linhas = [`# Auditoria dos sites`, ``, `Última execução: ${agora}`, ``]
for (const r of resultados) {
  linhas.push(`## ${r.site.nome}`, ``, `${r.site.url}`, ``)
  if (!r.achados.length) {
    linhas.push(`Nenhum problema encontrado.`, ``)
    continue
  }
  for (const nivel of [GRAVE, MEDIO, AVISO]) {
    const doNivel = r.achados.filter(([s]) => s === nivel)
    if (!doNivel.length) continue
    const rotulo = { [GRAVE]: 'Grave', [MEDIO]: 'Médio', [AVISO]: 'Aviso' }[nivel]
    linhas.push(`**${rotulo}**`, ``)
    for (const [, texto] of doNivel) linhas.push(`- ${texto}`)
    linhas.push(``)
  }
}
writeFileSync(ARQUIVO_RELATORIO, linhas.join('\n'))

// WhatsApp só quando há grave, pra mensagem continuar sendo lida
const comGrave = resultados.filter((r) => r.achados.some(([s]) => s === GRAVE))
if (comGrave.length) {
  const partes = [`🔎 Auditoria semanal (${agora})`, ``]
  for (const r of comGrave) {
    partes.push(`*${r.site.nome}*`)
    for (const [, texto] of r.achados.filter(([s]) => s === GRAVE)) partes.push(`• ${texto}`)
    partes.push(``)
  }
  partes.push(`Relatório completo no repositório monitor-sites, arquivo auditoria.md.`)
  await whatsapp(partes.join('\n'))
} else {
  console.log('Nenhum problema grave, WhatsApp não enviado.')
}
