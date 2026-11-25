'use strict';
// Banco SQLite local (módulo nativo do Node). O esquema usa tipos e constraints
// que se traduzem direto para PostgreSQL (SERIAL, CHECK, UNIQUE, FOREIGN KEY).
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const dir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dir, { recursive: true });

const db = new DatabaseSync(path.join(dir, 'sorridonto.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

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

module.exports = db;
