'use strict';
// Banco SQLite local (módulo nativo do Node). O esquema segue o banco da equipe (grupo 4 – controle de
// acesso): empresa, usuario, recurso (+ logico/fisico), credencial (+ cracha/cartao), autorizacao e
// tentativa. Acrescenta visitante, visita, interesse e log_auditoria. Usa só tipos e constraints que
// se traduzem direto para PostgreSQL (CHECK, UNIQUE, FOREIGN KEY).
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
-- ---------------------------------------------------------------- banco da equipe (etapas anteriores)
CREATE TABLE IF NOT EXISTS empresa (
  id_empresa INTEGER PRIMARY KEY AUTOINCREMENT,
  nome       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usuario (
  id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
  nome       TEXT NOT NULL,
  unidade    TEXT NOT NULL,
  situacao   TEXT NOT NULL DEFAULT 'ATIVO' CHECK (situacao IN ('ATIVO','INATIVO','BLOQUEADO')),
  -- acrescentadas para o sistema de portaria:
  id_empresa INTEGER NOT NULL REFERENCES empresa (id_empresa) ON UPDATE CASCADE ON DELETE RESTRICT,
  email      TEXT NOT NULL UNIQUE,
  perfil     TEXT NOT NULL CHECK (perfil IN ('ADMIN','PORTEIRO','MORADOR'))
);

CREATE TABLE IF NOT EXISTS recurso (
  id_recurso  INTEGER PRIMARY KEY AUTOINCREMENT,
  id_empresa  INTEGER NOT NULL REFERENCES empresa (id_empresa) ON UPDATE CASCADE ON DELETE RESTRICT,
  nome        TEXT NOT NULL,
  criticidade TEXT NOT NULL CHECK (criticidade IN ('BAIXA','MEDIA','ALTA')),
  tipo        TEXT NOT NULL CHECK (tipo IN ('L','F')),
  UNIQUE (id_recurso, tipo)
);
CREATE TABLE IF NOT EXISTS recurso_logico (
  id_recurso INTEGER PRIMARY KEY,
  tipo       TEXT NOT NULL DEFAULT 'L' CHECK (tipo = 'L'),
  FOREIGN KEY (id_recurso, tipo) REFERENCES recurso (id_recurso, tipo) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS recurso_fisico (
  id_recurso INTEGER PRIMARY KEY,
  tipo       TEXT NOT NULL DEFAULT 'F' CHECK (tipo = 'F'),
  FOREIGN KEY (id_recurso, tipo) REFERENCES recurso (id_recurso, tipo) ON UPDATE CASCADE ON DELETE CASCADE
);

-- senha: hash scrypt (salt:hash), nunca a senha. tipo C = crachá (acesso físico), T = cartão (acesso lógico)
CREATE TABLE IF NOT EXISTS credencial (
  id_credencial INTEGER PRIMARY KEY AUTOINCREMENT,
  id_usuario    INTEGER NOT NULL REFERENCES usuario (id_usuario) ON UPDATE CASCADE ON DELETE RESTRICT,
  senha         TEXT NOT NULL,
  tipo          TEXT NOT NULL CHECK (tipo IN ('C','T')),
  UNIQUE (id_credencial, tipo)
);
CREATE TABLE IF NOT EXISTS cracha (
  id_credencial INTEGER PRIMARY KEY,
  tipo          TEXT NOT NULL DEFAULT 'C' CHECK (tipo = 'C'),
  FOREIGN KEY (id_credencial, tipo) REFERENCES credencial (id_credencial, tipo) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS cartao (
  id_credencial INTEGER PRIMARY KEY,
  tipo          TEXT NOT NULL DEFAULT 'T' CHECK (tipo = 'T'),
  FOREIGN KEY (id_credencial, tipo) REFERENCES credencial (id_credencial, tipo) ON UPDATE CASCADE ON DELETE CASCADE
);

-- liberação: quem pode usar qual recurso, de quando até quando
CREATE TABLE IF NOT EXISTS autorizacao (
  id_usuario INTEGER NOT NULL REFERENCES usuario (id_usuario) ON DELETE CASCADE,
  id_recurso INTEGER NOT NULL REFERENCES recurso (id_recurso) ON DELETE CASCADE,
  inicio     TEXT NOT NULL,                      -- AAAA-MM-DD
  fim        TEXT,                               -- AAAA-MM-DD; vazio = sem prazo
  situacao   TEXT NOT NULL DEFAULT 'ATIVA' CHECK (situacao IN ('ATIVA','SUSPENSA')),
  PRIMARY KEY (id_usuario, id_recurso)
);

-- cada tentativa de passagem, permitida ou negada (registro que o sistema nunca altera nem apaga)
CREATE TABLE IF NOT EXISTS tentativa (
  id_tentativa  INTEGER PRIMARY KEY AUTOINCREMENT,
  id_usuario    INTEGER REFERENCES usuario (id_usuario),   -- vazio quando a credencial é desconhecida
  id_recurso    INTEGER NOT NULL REFERENCES recurso (id_recurso),
  data_hora     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,   -- UTC
  resultado     TEXT NOT NULL CHECK (resultado IN ('PERMITIDO','NEGADO')),
  motivo_recusa TEXT
);
CREATE INDEX IF NOT EXISTS ix_tentativa_recurso ON tentativa (id_recurso, id_tentativa);

-- ---------------------------------------------------------------- acrescentado para a portaria
-- Visitantes: CPF e telefone cifrados (AES-256-GCM); cpf_idx é o índice cego para busca e unicidade.
CREATE TABLE IF NOT EXISTS visitante (
  id_visitante INTEGER PRIMARY KEY AUTOINCREMENT,
  id_empresa   INTEGER NOT NULL REFERENCES empresa (id_empresa),
  nome         TEXT NOT NULL,
  cpf          TEXT NOT NULL,
  cpf_idx      TEXT NOT NULL,
  telefone     TEXT,
  criado_em    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (id_empresa, cpf_idx)
);

CREATE TABLE IF NOT EXISTS visita (
  id_visita     INTEGER PRIMARY KEY AUTOINCREMENT,
  id_empresa    INTEGER NOT NULL REFERENCES empresa (id_empresa),
  id_visitante  INTEGER NOT NULL REFERENCES visitante (id_visitante),
  id_anfitriao  INTEGER NOT NULL REFERENCES usuario (id_usuario),
  id_recurso    INTEGER NOT NULL REFERENCES recurso (id_recurso),
  data_prevista TEXT NOT NULL,                              -- AAAA-MM-DDTHH:MM (horário local)
  status        TEXT NOT NULL DEFAULT 'AGENDADA'
                CHECK (status IN ('AGENDADA','AUTORIZADA','REALIZADA','CANCELADA','NEGADA'))
);

-- Interessados que pedem o teste grátis pela landing page (formulário público).
CREATE TABLE IF NOT EXISTS interesse (
  id_interesse INTEGER PRIMARY KEY AUTOINCREMENT,
  nome      TEXT NOT NULL,
  email     TEXT NOT NULL,
  clinica   TEXT,                                           -- nome do condomínio ou empresa
  mensagem  TEXT,
  criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Trilha de auditoria dos cadastros e das liberações: escrita só pela aplicação.
CREATE TABLE IF NOT EXISTS log_auditoria (
  id_log     INTEGER PRIMARY KEY AUTOINCREMENT,
  momento    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  id_usuario INTEGER REFERENCES usuario (id_usuario),
  id_empresa INTEGER,
  acao       TEXT NOT NULL,
  detalhe    TEXT
);
`);

/** Visitante: cifra CPF e telefone antes de gravar e devolve o índice cego do CPF. */
function cifraVisitante(d) {
  return {
    cpf: cripto.cifra(d.cpf, 'visitante.cpf'),
    cpf_idx: cripto.indice(d.cpf, 'visitante.cpf'),
    telefone: cripto.cifra(d.telefone, 'visitante.telefone'),
  };
}
/** Decifra uma linha de visitante lida do banco. */
function decifraVisitante(l) {
  const o = { ...l, cpf: cripto.decifra(l.cpf, 'visitante.cpf'), telefone: cripto.decifra(l.telefone, 'visitante.telefone') };
  delete o.cpf_idx;
  return o;
}

module.exports = db;
module.exports.cifraVisitante = cifraVisitante;
module.exports.decifraVisitante = decifraVisitante;
