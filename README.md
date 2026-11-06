# Brasil-Imposto: monitor

As conferências agendadas da segurança da doação em cripto do Brasil-Imposto (spec `seguranca-doacoes`, seções 3, 7 e 9, no
repositório `Brasil-Imposto/brasil-imposto.github.io`). Cada conferência roda no GitHub Actions e falha quando acha algo: o e-mail
do GitHub sobre a falha é o alarme. Os logs trazem só tipos, redes e hashes de transação, nunca endereço, valor ou endereço de webhook.

| Conferência | O que vê | Quando |
|---|---|---|
| `chain` | qualquer transação que saia de um dos cinco endereços de doação; um nó sem resposta três vezes seguidas | a cada 15 minutos |
| `served` | cada arquivo servido contra o manifesto que o GitHub registrou na publicação (B1); os endereços e contratos do bloco de dados contra `pins.json` (L1); a CSP em toda página | à mão até o lote da produção; depois, a cada 5 minutos só a pergunta "mudou?", as quatro páginas com os endereços inteiras, e tudo uma vez por dia (D222) |
| `heartbeat` | o sinal de vida diário na issue fixada "Sinal de vida"; se não chegar no dia inteiro, vale como alarme (D226: o agendador do GitHub roda o comentário horas depois das 9h) | todo dia, 9h de Brasília |

`pins.json` é a cópia própria dos endereços e contratos do projeto: só muda por pull request aqui. O estado das conferências fica no
ramo `state`, escrito só pelos workflows.
