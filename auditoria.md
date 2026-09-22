# Auditoria dos sites

Última execução: 22/09/2026, 15:02

## Dr. Daniel Pinheiro

https://drdanielpinheiro.com.br/

**Grave**

- Sem frame-ancestors no CSP e sem X-Frame-Options: o site pode ser embutido em iframe de terceiro (clickjacking)
- Sem SPF: qualquer um consegue enviar e-mail se passando por este domínio
- Sem DMARC: nada impede falsificação de remetente neste domínio

**Médio**

- Sem object-src 'none' no CSP
- Sem base-uri 'self' no CSP
- Sem form-action 'self' no CSP

**Aviso**

- HSTS sem includeSubDomains
- script-src com 'unsafe-inline', que enfraquece a proteção contra XSS. Saída é CSP com nonce

## Pax Vida

https://paxvidams.com.br/

**Grave**

- 4 registros SPF no mesmo domínio: a especificação permite um só, com mais de um o SPF é ignorado

**Aviso**

- HSTS sem includeSubDomains
- script-src com 'unsafe-inline', que enfraquece a proteção contra XSS. Saída é CSP com nonce
- DMARC em p=none: só observa, não bloqueia. Subir para quarantine depois de conferir os relatórios

## Agência Gota

https://agenciagota.com.br/

**Grave**

- Sem SPF: qualquer um consegue enviar e-mail se passando por este domínio

**Aviso**

- HSTS sem includeSubDomains
- script-src com 'unsafe-inline', que enfraquece a proteção contra XSS. Saída é CSP com nonce
- DMARC em p=none: só observa, não bloqueia. Subir para quarantine depois de conferir os relatórios
