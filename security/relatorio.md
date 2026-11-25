# Relatório de verificação de segurança – SorriDonto

Executado em 25/11/2026, 10:40:11 contra `http://127.0.0.1:3000`.

**39 aprovados · 0 falharam · 4 alertas · 0 pulados**


## 1. Cabeçalhos HTTP e cookies

| Resultado | Verificação | Detalhe |
|---|---|---|
| APROVADO | CSP bloqueia script inline e eval | default-src 'self'; img-src 'self' data:; style-src 'self'; … |
| APROVADO | Proteção contra clickjacking (frame-ancestors / X-Frame-Options) |  |
| APROVADO | X-Content-Type-Options: nosniff |  |
| APROVADO | Não revela a tecnologia do servidor (X-Powered-By) |  |
| APROVADO | Respostas da API não ficam em cache |  |
| APROVADO | API responde com content-type JSON |  |
| APROVADO | Método TRACE recusado | status 405 |
| APROVADO | Cookie de sessão é HttpOnly (JavaScript não lê) |  |
| APROVADO | Cookie de sessão é SameSite=Strict (protege contra CSRF) |  |
| ALERTA | Cookie de sessão é Secure | só ativa com NODE_ENV=production atrás de HTTPS |

## 2. SQL injection

| Resultado | Verificação | Detalhe |
|---|---|---|
| APROVADO | Login resiste a 12 cargas de SQL injection (e-mail e senha) |  |
| APROVADO | Busca trata 7 cargas como texto comum (nenhuma linha a mais que o normal) |  |
| APROVADO | Nenhum hash de senha aparece nas respostas |  |
| APROVADO | Injeção por tempo (randomblob) não atrasa a resposta | 2 ms |
| APROVADO | ID na URL só aceita números (outros valores dão 404) |  |
| APROVADO | Cadastro aceita aspas e ponto e vírgula como texto | status 200 |
| APROVADO | O texto foi gravado literalmente, sem executar |  |
| APROVADO | Tabelas paciente e funcionario continuam existindo |  |

## 3. Injeção de HTML / XSS

| Resultado | Verificação | Detalhe |
|---|---|---|
| APROVADO | Formulário público recusa 8 cargas de HTML | 8/8 |
| APROVADO | Cadastro de paciente recusa HTML em nome e observações | 8/8 |
| APROVADO | Cadastro de funcionário recusa HTML | status 400 |
| APROVADO | Páginas de erro não refletem o que foi digitado na URL |  |
| APROVADO | Front-end sem pontos perigosos (4 arquivos analisados) |  |

## 4. Injeção em memória: protótipo, corpos gigantes, JSON malicioso e URLs malformadas

| Resultado | Verificação | Detalhe |
|---|---|---|
| APROVADO | Poluição de protótipo (__proto__, constructor) é recusada | 3/3 |
| APROVADO | JSON com 60.000 níveis de aninhamento não derruba o servidor | status 400 |
| APROVADO | Corpo de 70 KB é recusado (limite de 64 KB) | status 413 |
| APROVADO | Content-Length absurdo é recusado sem ler o corpo | status 413 |
| APROVADO | Corpo binário/UTF-8 inválido dá 400 | status 400 |
| APROVADO | Cabeçalho de 20 KB é recusado | status 400 |
| APROVADO | Servidor sobrevive a 6 URLs malformadas |  |
| APROVADO | Path traversal e arquivos sensíveis: 11 tentativas bloqueadas |  |
| APROVADO | Métodos PUT/DELETE/PATCH em páginas estáticas recusados |  |

## 5. Memory finder: leitura da memória do processo do servidor (Linux)

| Resultado | Verificação | Detalhe |
|---|---|---|
| ALERTA | ptrace_scope (Yama) restringe a leitura da memória por outros processos | valor 0: qualquer processo do mesmo usuário pode ler a memória do servidor (ver README) |
| APROVADO | Senha inicial não está no ambiente do processo (/proc/PID/environ) | use ADMIN_PASSWORD_FILE |
| ALERTA | senha em texto encontrado(a) na memória do servidor (1 ocorrência/s) | resíduo da requisição até o coletor de lixo; mitigue com ptrace_scope ≥ 1, usuário dedicado e contêiner |
| ALERTA | cookie de sessão (token cru) encontrado(a) na memória do servidor (3 ocorrência/s) | resíduo da requisição até o coletor de lixo; mitigue com ptrace_scope ≥ 1, usuário dedicado e contêiner |

## 6. Força bruta e negação de serviço (DoS/DDoS na camada da aplicação)

| Resultado | Verificação | Detalhe |
|---|---|---|
| APROVADO | Força bruta no login é bloqueada (429) | bloqueio na tentativa 9 |
| APROVADO | Atende normalmente com 150 conexões ociosas abertas | status 200, 7 ms |
| APROVADO | Slowloris (cabeçalho que nunca termina) é cortado pelo servidor | conexão encerrada em 10.5 s |
| APROVADO | Conexões ociosas que nunca enviam nada são fechadas pelo servidor | 150/150 fechadas |
| APROVADO | Inundação de requisições é limitada (429 após o teto por minuto) | 160 bloqueadas de 400 |
| APROVADO | As respostas 429 são rápidas (o servidor não gasta trabalho com o excesso) | 19 ms no pior caso |
| APROVADO | Servidor volta ao normal depois da inundação | após 60 s |

> Limites conhecidos: a verificação cobre a camada da aplicação. Um DDoS volumétrico (rede) só se resolve com CDN/WAF/proxy na frente; a leitura de memória por outro processo do mesmo usuário depende do sistema operacional (ptrace_scope), pois o JavaScript não consegue apagar com garantia strings já criadas.
