# A2H — Agent-To-Human

Um comando pede autorização humana no Discord e verifica a decisão Ed25519 localmente. Node.js 22+ foi escolhido porque já fornece criptografia, HTTP e testes, sem dependências de terceiros. [Referência de criptografia](https://nodejs.org/api/crypto.html).

## Instalação e uso

No Windows, execute `powershell -NoProfile -File scripts/install.ps1`. O programa é copiado para `%USERPROFILE%\.h2a`; nenhum serviço, janela de fundo ou alteração de PATH é criado. A instalação inicial fica sem conexão até configurar o servidor.

Configure `%USERPROFILE%\.h2a\config.json` com `endpoint` (origem HTTPS, sem caminho), `publicKey` (PEM Ed25519 obtido por canal confiável) e `identity` (identidade vinculada à credencial no servidor). Opcionalmente passe um JSON apenas com esses campos em `-ConfigPath`. Nunca coloque credenciais nesse arquivo ou no repositório. Injete `A2H_API_KEY` no ambiente do processo por seu gerenciador de segredos; não passe o valor em argumentos. Use uma credencial Actions de identidade ou uma credencial A2H dedicada provisionada no servidor.

```powershell
& "$env:USERPROFILE\.h2a\a2h.cmd" request --summary "Publicar a versão revisada" --ttl 300
```

Qualquer harness pode chamar esse mesmo comando. `--ttl` vale de 1 a 3600 segundos. O resumo tem até 500 caracteres, sem controles ou caracteres invisíveis. A saída JSON omite o resumo. Códigos: `0` aprovado e verificado; `1` recusado e verificado; `2` expirado (sem autorização); `3` falha de verificação; `4` erro de configuração/rede/protocolo. Só `0` autoriza prosseguir, apenas com a ação exata e dentro do prazo; o programa não executa a ação.

Desinstale com `powershell -NoProfile -File scripts/uninstall.ps1`. A instalação e a configuração são arquivadas em `%USERPROFILE%\.archive`, sem exclusão permanente. Não há processo de fundo para encerrar. Testes: `npm test`.

## Servidor e protocolo

A integração do bot deve fornecer `POST /actions/a2h/requests` e `GET /actions/a2h/requests/:id`, autenticados por Bearer e isolados por identidade. O POST contém `v=1`, nonce aleatório de 256 bits em `id`, `requester`, `summary`, `created_at` e `expires_at` (milissegundos Unix). Sem decisão, responde `{"status":"pending"}`. A resposta final é `{payload, signature}`; o payload repete todos os campos e acrescenta `decision` (`approved`, `denied`, `expired`) e `decided_at`.

Assina-se UTF-8 de `JSON.stringify(["A2H-DECISION-v1", v, id, requester, summary, created_at, expires_at, decision, decided_at])`, usando Ed25519, com assinatura base64url sem padding. O cliente exige correspondência exata de todos os campos, confere assinatura, tipo da chave, decisão e horários. O relógio monotônico também limita a espera. HTTP sem TLS só é aceito em loopback literal com `allowLoopbackHttp: true`, reservado a testes locais.

## Modelo de ameaça

Texto colado por outro agente, respostas de outro pedido, alterações do resumo e assinaturas falsas não autorizam. O bot confere o usuário aprovador numa interação autenticada pelo Discord e vincula o clique ao servidor, canal, aplicação e mensagem originais. A chave privada existe somente no servidor; a chave pública local precisa ser fixada por um canal confiável. Não baixe uma chave automaticamente da mesma resposta que pretende verificar.

O sistema confia no servidor, no Discord, na conta do aprovador, no relógio e na integridade do cliente/configuração locais. Um agente com permissão para substituir o verificador ou a chave fixada pode contornar essa confiança; A2H não é uma barreira contra administrador local malicioso, nem impõe que outro programa obedeça à decisão. Uma aprovação descreve a ação; para autorizar bytes específicos, inclua seu hash no resumo. Nunca envie segredos no resumo, que será exibido no Discord.

Sem resposta, falha de rede, reinício do bot ou configuração incompleta, não há aprovação. O servidor inicial usa memória limitada e requer uma única instância; reinícios perdem pedidos e múltiplas réplicas exigem armazenamento transacional compartilhado antes de habilitar. Aprovar é válido até `expires_at`, não indefinidamente, e não é uma autorização genérica para ações futuras.
