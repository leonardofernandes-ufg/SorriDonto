# SorriDonto – site e área administrativa

Site de apresentação da clínica (`/`) e painel administrativo (`/admin`) para cadastro de
funcionários e pacientes. Sem dependências externas: usa só o Node (>= 22.13) e o SQLite embutido.

## Como rodar

```bash
cd sorridonto
npm start
```

Abra http://127.0.0.1:3000. Na **primeira execução** o servidor cria o administrador
`admin@sorridonto.local` e mostra a senha gerada **uma única vez** no terminal.
Para escolher a senha: `ADMIN_EMAIL=voce@clinica.com ADMIN_PASSWORD_FILE=/caminho/senha.txt npm start`
(melhor que `ADMIN_PASSWORD`, que fica visível em `/proc/<pid>/environ`).

Variáveis opcionais: `PORT` (3000), `HOST` (127.0.0.1), `DATA_DIR` (pasta do banco, padrão `data/`),
`RATE_LIMIT_PER_MIN` (240), `MAX_CONNECTIONS` (500), `TRUST_PROXY` (1 atrás de proxy),
`NODE_ENV=production` (cookie `Secure`; exige HTTPS na frente).

## Perfis e permissões (menor privilégio)

| Perfil    | Pacientes                                  | Funcionários | Auditoria |
|-----------|--------------------------------------------|--------------|-----------|
| admin     | ver (CPF completo), criar, editar, excluir | tudo         | ver       |
| recepcao  | ver (CPF mascarado na lista), criar, editar | —           | —         |
| dentista  | somente ver (CPF mascarado na lista)       | —            | —         |

## Segurança

Rodar com os limites de memória e proteção de protótipo ligados: `npm start`
(= `node --max-old-space-size=256 --disable-proto=delete server.js`).

| Ataque | Proteção no sistema |
|---|---|
| **SQL injection** | Todas as consultas são parametrizadas; ID na URL só aceita dígitos; `LIKE` com escape. |
| **Injeção de HTML / XSS** | Campos de texto recusam marcação HTML (`<tag`) e caracteres de controle; o front usa `textContent` (sem `innerHTML`); CSP sem `unsafe-inline`; `nosniff`; erros não ecoam a URL. |
| **Injeção em memória / objetos** | JSON recusa `__proto__`, `constructor` e `prototype`; corpo máximo de 64 KB; só objetos JSON; cabeçalhos até 16 KB; URL malformada responde 400 (não derruba o processo). |
| **Esgotamento de memória** | Teto de 2.000 sessões (5 por usuário), contador de limites com teto de 50.000 chaves, `LIMIT` nas consultas, heap de 256 MB. |
| **Leitura de memória (memory finder)** | Sessões guardadas só como hash SHA-256 do token; senha inicial por `ADMIN_PASSWORD_FILE` e removida de `process.env`; hash de senha com scrypt. Veja os limites abaixo. |
| **DoS / DDoS (aplicação)** | 240 requisições/min por IP (`RATE_LIMIT_PER_MIN`), login limitado por e-mail e por IP, timeouts de cabeçalho/requisição, conexões ociosas e slowloris derrubadas em ~12 s, máx. de 500 conexões. |
| **Força bruta** | 8 falhas por IP+e-mail e 30 por IP em 15 min; resposta de tempo igual para e-mail inexistente. |
| **Sessão** | Cookie `HttpOnly`, `SameSite=Strict` (e `Secure` em produção), 8 h, encerrado ao desativar o usuário. |
| **Path traversal** | Só serve arquivos de `public/`; recusa `..`, dotfiles e bytes nulos. |

### Verificação automática dos ataques

Com o servidor rodando, simule os ataques contra o próprio sistema (use só em ambiente local ou de teste):

```bash
TEST_EMAIL=admin@sorridonto.local TEST_SENHA='sua-senha' npm run verifica
```

São 43 verificações em 6 grupos (cabeçalhos, SQL injection, HTML/XSS, injeção em memória, leitura de
memória e DoS). Leva cerca de 2 minutos, por causa da inundação e do slowloris. O resultado fica em
[security/relatorio.md](security/relatorio.md); o comando sai com erro se algo falhar.
`PULAR_DDOS=1` pula a parte de inundação.

### O que a verificação aponta e não dá para resolver só no código

- **Leitura de memória por outro processo.** O JavaScript não apaga strings já criadas (a senha digitada e o
  cookie ficam na memória até o coletor de lixo). A defesa é do sistema operacional: `kernel.yama.ptrace_scope`
  igual a 1 ou mais (`sudo sysctl -w kernel.yama.ptrace_scope=1`), rodar o servidor com um usuário dedicado,
  em contêiner, e desativar *core dumps* (`ulimit -c 0`).
- **DDoS volumétrico (rede).** O limite por IP segura inundação simples, mas um ataque distribuído só se
  resolve com proxy reverso, CDN ou WAF na frente (por exemplo, Cloudflare ou Nginx com `limit_req`).
  Atrás de proxy, defina `TRUST_PROXY=1` para o limite usar o IP real do cliente.
- **Cookie `Secure`.** Só ativa com `NODE_ENV=production` e HTTPS.

## Estrutura

```
server.js   rotas da API, sessões, permissões e arquivos estáticos
db.js       esquema SQLite (funcionario, paciente, log_acesso)
public/     index.html (site), admin.html + admin.js (painel), style.css
security/   verifica.js (simula os ataques) e relatorio.md (último resultado)
data/       banco SQLite (ignorado pelo git)
```

## Para a disciplina (PostgreSQL)

O esquema em `db.js` usa só `CHECK`, `UNIQUE` e `FOREIGN KEY`, e se traduz direto para
PostgreSQL (`INTEGER PRIMARY KEY AUTOINCREMENT` vira `SERIAL`). Os papéis, `GRANT`/`REVOKE`, o
trigger de auditoria e o `pg_dump` da Etapa 4 podem ser feitos nesse esquema.

## Antes de publicar

- Troque endereço, telefone e e-mail de exemplo em `public/index.html`.
- Coloque atrás de HTTPS (proxy reverso) e defina `NODE_ENV=production`.
- Faça backup do arquivo `data/sorridonto.db`.
- Limitação atual: as sessões ficam em memória (reiniciar o servidor desconecta todos).
