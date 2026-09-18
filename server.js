// ═══════════════════════════════════════════════════════════
// SuiviScolaire — Backend local (Node + Express + SQLite)
// ═══════════════════════════════════════════════════════════
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Secret JWT persistant (généré une seule fois, réutilisé aux prochains démarrages)
const SECRET_PATH = path.join(DATA_DIR, '.secret');
let JWT_SECRET;
if (fs.existsSync(SECRET_PATH)) {
  JWT_SECRET = fs.readFileSync(SECRET_PATH, 'utf8').trim();
} else {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_PATH, JWT_SECRET);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
CREATE TABLE IF NOT EXISTS etablissements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nom TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  data TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS prof_access (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  etablissement_id INTEGER NOT NULL,
  classe TEXT NOT NULL,
  matiere TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  UNIQUE(etablissement_id, classe, matiere),
  FOREIGN KEY(etablissement_id) REFERENCES etablissements(id)
);
`);

function defaultData(nom) {
  return {
    eleves: [],
    notes: {},
    appreciations: {},
    envois: {},
    params: { ecole: nom, annee: '2025–2026', mois: 'Septembre', dateLimiteJour: 0 }
  };
}
pool.query(`
  CREATE TABLE IF NOT EXISTS etablissements (
    id SERIAL PRIMARY KEY,
    nom TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS prof_access (
    id SERIAL PRIMARY KEY,
    etablissement_id INTEGER NOT NULL REFERENCES etablissements(id),
    classe TEXT NOT NULL,
    matiere TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    UNIQUE(etablissement_id, classe, matiere)
  );
`).catch(err => console.error('Erreur création tables:', err));

const app = express();

// Vérification de santé pour l'hébergeur
app.get('/health', (req, res) => {
  res.json({ ok: true, app: 'SuiviScolaire' });
});
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ───────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Non authentifié.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session invalide ou expirée.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Réservé à la direction.' });
  next();
}

// ───────────────────────────────────────────────────────────
// ÉTABLISSEMENTS — création / connexion direction
// ───────────────────────────────────────────────────────────

// Liste publique (pour l'écran de connexion professeur : choisir son établissement)
app.get('/api/etablissements', (req, res) => {
  const rows = db.prepare('SELECT id, nom FROM etablissements ORDER BY nom').all();
  res.json(rows);
});

app.post('/api/etablissements', (req, res) => {
  const { nom, email, password } = req.body || {};
  if (!nom || !email || !password) {
    return res.status(400).json({ error: 'Nom, email et mot de passe sont requis.' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 4 caractères.' });
  }
  const existing = db.prepare('SELECT id FROM etablissements WHERE email = ?').get(email.trim().toLowerCase());
  if (existing) return res.status(409).json({ error: 'Un établissement existe déjà avec cet email.' });

  const hash = bcrypt.hashSync(password, 10);
  const data = JSON.stringify(defaultData(nom.trim()));
  const info = db.prepare(
    'INSERT INTO etablissements (nom, email, password_hash, data) VALUES (?, ?, ?, ?)'
  ).run(nom.trim(), email.trim().toLowerCase(), hash, data);

  const token = jwt.sign({ etabId: info.lastInsertRowid, role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, etab: { id: info.lastInsertRowid, nom: nom.trim() } });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const row = db.prepare('SELECT * FROM etablissements WHERE email = ?').get((email || '').trim().toLowerCase());
  if (!row || !bcrypt.compareSync(password || '', row.password_hash)) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  }
  const token = jwt.sign({ etabId: row.id, role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, etab: { id: row.id, nom: row.nom } });
});

// ───────────────────────────────────────────────────────────
// CONNEXION PROFESSEUR — établissement + classe + matière + mot de passe
// ───────────────────────────────────────────────────────────
app.post('/api/login-prof', (req, res) => {
  const { etablissementId, classe, matiere, password } = req.body || {};
  if (!etablissementId || !classe || !matiere || !password) {
    return res.status(400).json({ error: 'Établissement, classe, matière et mot de passe requis.' });
  }
  const etab = db.prepare('SELECT id, nom FROM etablissements WHERE id = ?').get(etablissementId);
  if (!etab) return res.status(404).json({ error: 'Établissement introuvable.' });

  const row = db.prepare(
    'SELECT * FROM prof_access WHERE etablissement_id = ? AND classe = ? AND matiere = ?'
  ).get(etablissementId, classe, matiere);

  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'Mot de passe incorrect pour cette classe/matière, ou accès non configuré par la direction.' });
  }

  const token = jwt.sign(
    { etabId: etab.id, role: 'prof', classe, matiere },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token, etab: { id: etab.id, nom: etab.nom }, classe, matiere });
});

// ───────────────────────────────────────────────────────────
// GESTION DES ACCÈS PROFESSEURS (direction uniquement)
// ───────────────────────────────────────────────────────────
app.get('/api/prof-access', auth, requireAdmin, (req, res) => {
  const rows = db.prepare(
    'SELECT classe, matiere FROM prof_access WHERE etablissement_id = ?'
  ).all(req.user.etabId);
  res.json(rows);
});

app.post('/api/prof-access', auth, requireAdmin, (req, res) => {
  const { classe, matiere, password } = req.body || {};
  if (!classe || !matiere || !password) {
    return res.status(400).json({ error: 'Classe, matière et mot de passe requis.' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 4 caractères.' });
  }
  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`
    INSERT INTO prof_access (etablissement_id, classe, matiere, password_hash)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(etablissement_id, classe, matiere) DO UPDATE SET password_hash = excluded.password_hash
  `).run(req.user.etabId, classe, matiere, hash);
  res.json({ ok: true });
});

app.delete('/api/prof-access', auth, requireAdmin, (req, res) => {
  const { classe, matiere } = req.body || {};
  db.prepare(
    'DELETE FROM prof_access WHERE etablissement_id = ? AND classe = ? AND matiere = ?'
  ).run(req.user.etabId, classe, matiere);
  res.json({ ok: true });
});

// ───────────────────────────────────────────────────────────
// DONNÉES DE L'APPLICATION (blob JSON : élèves, notes, etc.)
// ───────────────────────────────────────────────────────────
function loadBlob(etabId) {
  const row = db.prepare('SELECT data FROM etablissements WHERE id = ?').get(etabId);
  if (!row) return null;
  try { return JSON.parse(row.data); } catch (e) { return defaultData('Établissement'); }
}

function saveBlob(etabId, blob) {
  db.prepare('UPDATE etablissements SET data = ? WHERE id = ?').run(JSON.stringify(blob), etabId);
}

app.get('/api/data', auth, (req, res) => {
  const blob = loadBlob(req.user.etabId);
  if (!blob) return res.status(404).json({ error: 'Établissement introuvable.' });

  if (req.user.role === 'admin') {
    return res.json({ role: 'admin', ...blob });
  }

  // Rôle "prof" : vue filtrée sur sa classe / sa matière uniquement
  const { classe, matiere } = req.user;
  const elevesCl = (blob.eleves || []).filter(e => e.classe === classe);
  const idsCl = new Set(elevesCl.map(e => e.id));

  const notesFiltrees = {};
  for (const [eleveId, parMois] of Object.entries(blob.notes || {})) {
    if (!idsCl.has(Number(eleveId))) continue;
    const out = {};
    for (const [mois, parMatiere] of Object.entries(parMois || {})) {
      if (parMatiere && parMatiere[matiere] !== undefined) {
        out[mois] = { [matiere]: parMatiere[matiere] };
      }
    }
    if (Object.keys(out).length) notesFiltrees[eleveId] = out;
  }

  const appreciationsFiltrees = {};
  for (const [eleveId, parMois] of Object.entries(blob.appreciations || {})) {
    if (!idsCl.has(Number(eleveId))) continue;
    const out = {};
    for (const [mois, parMatiere] of Object.entries(parMois || {})) {
      if (parMatiere && parMatiere[matiere] !== undefined) {
        out[mois] = { [matiere]: parMatiere[matiere] };
      }
    }
    if (Object.keys(out).length) appreciationsFiltrees[eleveId] = out;
  }

  res.json({
    role: 'prof',
    classe,
    matiere,
    eleves: elevesCl,
    notes: notesFiltrees,
    appreciations: appreciationsFiltrees,
    envois: {},
    params: blob.params
  });
});

app.put('/api/data', auth, (req, res) => {
  const blob = loadBlob(req.user.etabId);
  if (!blob) return res.status(404).json({ error: 'Établissement introuvable.' });
  const body = req.body || {};

  if (req.user.role === 'admin') {
    // La direction peut mettre à jour l'ensemble des données
    if (body.eleves !== undefined) blob.eleves = body.eleves;
    if (body.notes !== undefined) blob.notes = body.notes;
    if (body.appreciations !== undefined) blob.appreciations = body.appreciations;
    if (body.envois !== undefined) blob.envois = body.envois;
    if (body.params !== undefined) blob.params = body.params;
    saveBlob(req.user.etabId, blob);
    return res.json({ ok: true });
  }

  // Rôle "prof" : fusion en liste blanche — uniquement notes/appréciations
  // de sa matière, pour des élèves appartenant bien à sa classe.
  const { classe, matiere } = req.user;
  const idsCl = new Set((blob.eleves || []).filter(e => e.classe === classe).map(e => e.id));

  if (body.notes) {
    for (const [eleveId, parMois] of Object.entries(body.notes)) {
      if (!idsCl.has(Number(eleveId))) continue;
      for (const [mois, parMatiere] of Object.entries(parMois || {})) {
        const valeurs = parMatiere ? parMatiere[matiere] : undefined;
        if (valeurs === undefined) continue;
        blob.notes[eleveId] = blob.notes[eleveId] || {};
        blob.notes[eleveId][mois] = blob.notes[eleveId][mois] || {};
        blob.notes[eleveId][mois][matiere] = valeurs;
      }
    }
  }

  if (body.appreciations) {
    for (const [eleveId, parMois] of Object.entries(body.appreciations)) {
      if (!idsCl.has(Number(eleveId))) continue;
      for (const [mois, parMatiere] of Object.entries(parMois || {})) {
        const texte = parMatiere ? parMatiere[matiere] : undefined;
        if (texte === undefined) continue;
        blob.appreciations[eleveId] = blob.appreciations[eleveId] || {};
        blob.appreciations[eleveId][mois] = blob.appreciations[eleveId][mois] || {};
        blob.appreciations[eleveId][mois][matiere] = texte;
      }
    }
  }

  saveBlob(req.user.etabId, blob);
  res.json({ ok: true });
});

// ───────────────────────────────────────────────────────────
// FICHIERS STATIQUES (frontend)
// ───────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n✅ SuiviScolaire est lancé : http://localhost:${PORT}\n`);
});
