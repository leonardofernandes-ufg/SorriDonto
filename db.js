'use strict';
// Banco SQLite local (módulo nativo do Node). O esquema usa tipos e constraints
// que se traduzem direto para PostgreSQL (SERIAL, CHECK, UNIQUE, FOREIGN KEY).
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const cripto = require('./cripto');

const dir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dir, { recursive: true });

const db = new DatabaseSync(path.join(dir, 'sorridonto.db'));
// secure_delete: zera o conteúdo apagado dentro do arquivo (não deixa resíduo de dado removido)
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS funcionario (
  id_funcionario INTEGER PRIMARY KEY AUTOINCREMENT,
  nome        TEXT NOT NULL,
  email       TEXT NOT NULL UNIQUE,
  senha_hash  TEXT NOT NULL,
  perfil      TEXT NOT NULL CHECK (perfil IN ('admin','dentista','recepcao')),
  cargo       TEXT,
  cro         TEXT,
  telefone    TEXT,
  ativo       INTEGER NOT NULL DEFAULT 1 CHECK (ativo IN (0,1)),
  criado_em   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS paciente (
  id_paciente     INTEGER PRIMARY KEY AUTOINCREMENT,
  nome            TEXT NOT NULL,
  cpf             TEXT NOT NULL UNIQUE,
  data_nascimento TEXT,
  telefone        TEXT,
  email           TEXT,
  cidade          TEXT,
  endereco        TEXT,
  observacoes     TEXT,
  criado_em       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  criado_por      INTEGER REFERENCES funcionario (id_funcionario)
);

-- Interessados que pedem o teste grátis pela landing page (formulário público).
CREATE TABLE IF NOT EXISTS interesse (
  id_interesse INTEGER PRIMARY KEY AUTOINCREMENT,
  nome      TEXT NOT NULL,
  email     TEXT NOT NULL,
  clinica   TEXT,
  mensagem  TEXT,
  criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Trilha de auditoria: escrita só pela aplicação (append-only).
CREATE TABLE IF NOT EXISTS log_acesso (
  id_log         INTEGER PRIMARY KEY AUTOINCREMENT,
  momento        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  id_funcionario INTEGER REFERENCES funcionario (id_funcionario),
  acao           TEXT NOT NULL,
  detalhe        TEXT
);
`);

// ---- criptografia em repouso: colunas e índices cegos --------------------------------------------
const colunas = (t) => db.prepare(`PRAGMA table_info(${t})`).all().map((c) => c.name);
if (!colunas('paciente').includes('cpf_idx')) db.exec('ALTER TABLE paciente ADD COLUMN cpf_idx TEXT');
if (!colunas('paciente').includes('email_idx')) db.exec('ALTER TABLE paciente ADD COLUMN email_idx TEXT');
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ux_paciente_cpf_idx ON paciente (cpf_idx);
         CREATE INDEX IF NOT EXISTS ix_paciente_email_idx ON paciente (email_idx);`);

/** Campos de paciente cifrados no banco (nome, cidade e data de cadastro ficam legíveis para busca/relatórios). */
const CAMPOS_PACIENTE = ['cpf', 'data_nascimento', 'telefone', 'email', 'endereco', 'observacoes'];

function paraBanco(d) {
  const o = {};
  for (const c of CAMPOS_PACIENTE) o[c] = cripto.cifra(d[c], 'paciente.' + c);
  o.cpf_idx = cripto.indice(d.cpf, 'paciente.cpf');
  o.email_idx = cripto.indice(d.email, 'paciente.email');
  return o;
}
function doBanco(l) {
  const o = { ...l };
  for (const c of CAMPOS_PACIENTE) o[c] = cripto.decifra(l[c], 'paciente.' + c);
  delete o.cpf_idx; delete o.email_idx;
  return o;
}

/** Cifra o que já estava em texto puro (bancos criados antes da criptografia) e limpa os resíduos. */
function migraCriptografia() {
  const antigos = db.prepare('SELECT * FROM paciente').all().filter((p) => !cripto.estaCifrado(p.cpf));
  const leads = db.prepare('SELECT * FROM interesse').all().filter((i) => !cripto.estaCifrado(i.email));
  if (!antigos.length && !leads.length) return 0;
  db.exec('BEGIN');
  try {
    for (const p of antigos) {
      const c = paraBanco(p);
      db.prepare(`UPDATE paciente SET cpf=?, data_nascimento=?, telefone=?, email=?, endereco=?, observacoes=?, cpf_idx=?, email_idx=?
                  WHERE id_paciente=?`).run(c.cpf, c.data_nascimento, c.telefone, c.email, c.endereco, c.observacoes, c.cpf_idx, c.email_idx, p.id_paciente);
    }
    for (const i of leads) {
      db.prepare('UPDATE interesse SET email=?, mensagem=? WHERE id_interesse=?')
        .run(cripto.cifra(i.email, 'interesse.email'), cripto.cifra(i.mensagem, 'interesse.mensagem'), i.id_interesse);
    }
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  // reescreve o arquivo para não sobrar texto puro em páginas livres nem no WAL
  db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);');
  return antigos.length + leads.length;
}

module.exports = db;
module.exports.paraBanco = paraBanco;
module.exports.doBanco = doBanco;
module.exports.migraCriptografia = migraCriptografia;
