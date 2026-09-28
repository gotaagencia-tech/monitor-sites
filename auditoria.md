# Auditoria dos sites

Última execução: 28/09/2026, 16:10

## Agência Gota

https://agenciagota.com.br

**Grave**

- Sem SPF: qualquer um consegue enviar e-mail se passando por este domínio

**Aviso**

- HSTS sem includeSubDomains
- script-src com 'unsafe-inline', que enfraquece a proteção contra XSS. Saída é CSP com nonce
- DMARC em p=none: só observa, não bloqueia. Subir para quarantine depois de conferir os relatórios

## Gestão Gota

https://gestao.agenciagota.com.br/login

**Grave**

- Sem SPF: qualquer um consegue enviar e-mail se passando por este domínio
- Sem DMARC: nada impede falsificação de remetente neste domínio

**Médio**

- Página sem <h1>

**Aviso**

- X-XSS-Protection presente: o recurso não existe mais em navegador atual e o OWASP pede para remover
- X-Powered-By expõe a stack (Next.js)
- Meta description com 41 caracteres, fora da faixa de 80 a 165

## Peres & Fernandes

https://peresefernandes.com.br

**Grave**

- Sem Strict-Transport-Security (HSTS)
- Sem frame-ancestors no CSP e sem X-Frame-Options: o site pode ser embutido em iframe de terceiro (clickjacking)

**Médio**

- Sem object-src 'none' no CSP
- Sem base-uri 'self' no CSP
- Sem form-action 'self' no CSP
- Sem X-Content-Type-Options: nosniff
- Sem Referrer-Policy

**Aviso**

- Sem Permissions-Policy
- X-Powered-By expõe a stack (PHP/7.4.33)
- <title> com 76 caracteres, o Google costuma cortar acima de 60
- DMARC em p=none: só observa, não bloqueia. Subir para quarantine depois de conferir os relatórios

## Dr. Daniel Pinheiro

https://drdanielpinheiro.com.br

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

## Dra. Camila Insuela

https://dracamilainsuela.com.br

**Grave**

- Sem Content-Security-Policy

**Médio**

- Sem X-Content-Type-Options: nosniff
- Sem Referrer-Policy

**Aviso**

- HSTS sem includeSubDomains
- Sem Permissions-Policy
- Meta description com 203 caracteres, fora da faixa de 80 a 165
- DMARC em p=none: só observa, não bloqueia. Subir para quarantine depois de conferir os relatórios

## Dra. Laura Terra

https://dralauraterra.com.br

**Aviso**

- HSTS sem includeSubDomains
- script-src com 'unsafe-inline', que enfraquece a proteção contra XSS. Saída é CSP com nonce

## Pax Vida

https://paxvidams.com.br

**Grave**

- 4 registros SPF no mesmo domínio: a especificação permite um só, com mais de um o SPF é ignorado

**Aviso**

- HSTS sem includeSubDomains
- script-src com 'unsafe-inline', que enfraquece a proteção contra XSS. Saída é CSP com nonce
- DMARC em p=none: só observa, não bloqueia. Subir para quarantine depois de conferir os relatórios
