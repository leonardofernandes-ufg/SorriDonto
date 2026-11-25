# SorriDonto – site e área administrativa

Site de apresentação da clínica (`/`) e painel administrativo (`/admin`) para cadastro de
funcionários e pacientes. Sem dependências externas: usa só o Node (>= 22.13) e o SQLite embutido.

## Como rodar

```bash
cd sorridonto
node server.js
```

Abra http://127.0.0.1:3000. Na **primeira execução** o servidor cria o administrador
`admin@sorridonto.local` e mostra a senha gerada **uma única vez** no terminal.
Para escolher a senha: `ADMIN_EMAIL=voce@clinica.com ADMIN_PASSWORD='sua-senha-forte' node server.js`.

Variáveis opcionais: `PORT` (3000), `HOST` (127.0.0.1), `DATA_DIR` (pasta do banco, padrão `data/`),
`NODE_ENV=production` (cookie `Secure`; exige HTTPS na frente).

## Perfis e permissões (menor privilégio)

| Perfil    | Pacientes                                  | Funcionários | Auditoria |
|-----------|--------------------------------------------|--------------|-----------|
| admin     | ver (CPF completo), criar, editar, excluir | tudo         | ver       |
| recepcao  | ver (CPF mascarado na lista), criar, editar | —           | —         |
| dentista  | somente ver (CPF mascarado na lista)       | —            | —         |

## O que há de segurança

- Senhas com `scrypt` + salt; comparação em tempo constante; limite de tentativas de login (8 por 15 min).
- Sessão em cookie `HttpOnly` + `SameSite=Strict`, expira em 8 h; desativar o funcionário encerra as sessões dele.
- Consultas SQL parametrizadas; CSP restritiva (sem scripts ou estilos inline); cabeçalhos de segurança.
- Validação no servidor: CPF (dígitos verificadores), e-mail, telefone, data de nascimento.
- Trilha de auditoria (`log_acesso`): logins, falhas, criação/alteração/exclusão e leitura de ficha de paciente.
- Não permite remover o último administrador ativo.

## Estrutura

```
server.js   rotas da API, sessões, permissões e arquivos estáticos
db.js       esquema SQLite (funcionario, paciente, log_acesso)
public/     index.html (site), admin.html + admin.js (painel), style.css
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
