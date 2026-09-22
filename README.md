# Monitor de sites

Dois verificadores, com perguntas diferentes.

## 1. Disponibilidade, a cada 5 minutos (`check.mjs`)

Responde "o site está no ar?". Avisa no WhatsApp quando um cai (depois de 2 falhas seguidas, pra não alarmar por oscilação) e quando volta.

## 2. Auditoria, toda segunda às 9h (`auditoria.mjs`)

Responde "o site continua certo?". É a pergunta que ninguém lembra de fazer depois do lançamento, e foi ela que revelou, na primeira execução, que um dos sites estava sem proteção contra clickjacking e três domínios estavam com SPF quebrado ou ausente.

Confere, de fora, o que dá pra conferir de fora:

- **Segurança**: HSTS, CSP (incluindo `frame-ancestors`, `object-src`, `base-uri`, `form-action` e `unsafe-inline`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, headers obsoletos e vazamento de stack
- **E-mail do domínio**: SPF (ausente, duplicado ou neutro) e DMARC (ausente ou em `p=none`)
- **Higiene de HTML**: `lang`, quantidade de `h1`, imagem sem `alt`, `title` e meta description

Manda WhatsApp **só quando encontra problema grave**. Semana limpa não gera mensagem, senão o aviso vira ruído e para de ser lido. O relatório completo, com os três níveis (grave, médio, aviso), fica sempre em `auditoria.md`, commitado, com histórico no Git.

### O que a auditoria não cobre, de propósito

- **Dependência vulnerável**: `npm audit` precisa do repositório do site, não do domínio. Isso fica com o Dependabot em cada repositório de cliente.
- **Core Web Vitals de campo**: precisa de volume de visita real, que os sites dos clientes ainda não têm.

## Configuração

- Lista de sites: secret `SITES`, um por linha no formato `Nome|https://endereco`.
- WhatsApp: secrets `CALLMEBOT_PHONE` (ex.: +5522999999999) e `CALLMEBOT_APIKEY` (https://www.callmebot.com/blog/free-api-whatsapp-messages/).
- Para testar: aba Actions, escolher o workflow, "Run workflow".

Consulta de DNS usa DNS-over-HTTPS (dns.google) com o resolvedor do sistema como reserva, porque runner e máquina de trabalho às vezes bloqueiam a porta 53. Quando a consulta falha, o relatório diz que não conseguiu verificar, nunca que o registro está ausente.
