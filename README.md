# Brasil-Imposto: monitor

As conferências agendadas da segurança da doação em cripto do Brasil-Imposto (spec `seguranca-doacoes`, seções 3, 7 e 9, no
repositório `Brasil-Imposto/brasil-imposto.github.io`). Cada conferência roda no GitHub Actions e falha quando acha algo: o e-mail
do GitHub sobre a falha é o alarme. Os logs trazem só tipos, redes e hashes de transação, nunca endereço, valor ou endereço de webhook.

| Conferência | O que vê | Quando |
|---|---|---|
| `chain` | qualquer transação que saia de um dos cinco endereços de doação; um nó sem resposta três vezes seguidas | a cada 15 minutos |
| `heartbeat` | o sinal de vida diário na issue fixada "Sinal de vida"; se não chegar até as 10h de Brasília, vale como alarme | todo dia, 9h de Brasília |

`pins.json` é a cópia própria dos endereços e contratos do projeto: só muda por pull request aqui. O estado das conferências fica no
ramo `state`, escrito só pelos workflows.
