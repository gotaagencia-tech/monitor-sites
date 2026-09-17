# Monitor de sites

Checa a cada 5 minutos se os sites estão no ar e avisa no WhatsApp quando um cai (depois de 2 falhas seguidas) e quando volta.

- Lista de sites: secret `SITES`, um por linha no formato `Nome|https://endereco`.
- WhatsApp: secrets `CALLMEBOT_PHONE` (ex.: +5522999999999) e `CALLMEBOT_APIKEY` (https://www.callmebot.com/blog/free-api-whatsapp-messages/).
- Para testar: aba Actions > "Monitor de sites" > Run workflow.
