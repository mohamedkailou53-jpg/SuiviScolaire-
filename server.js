// ═══════════════════════════════════════════════════════════
// SuiviScolaire — Backend Node + Express + PostgreSQL
// ═══════════════════════════════════════════════════════════

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// ───────────────────────────────────────────────────────────
// JWT SECRET
// ───────────────────────────────────────────────────────────

const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// En production, mettre JWT_SECRET dans les variables d'environnement.
// Le fichier .secret sert seulement de secours en local.
const SECRET_PATH = path.join(DATA_DIR, '.secret');

let JWT_SECRET;

if (process.env.JWT_SECRET) {
  JWT_SECRET = process.env.JWT_SECRET;
} else if (fs.existsSync(SECRET_PATH)) {
  JWT_SECRET = fs.readFileSync(SECRET_PATH, 'utf8').trim();
} else {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_PATH, JWT_SECRET);
}

// ───────────────────────────────────────────────────────────
// POSTGRESQL
// ───────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ───────────────────────────────────────────────────────────
// DONNÉES PAR DÉFAUT
// ───────────────────────────────────────────────────────────

function defaultData(nom) {
  return {
    eleves: [],
    notes: {},
    appreciations: {},
    envois: {},
    params: {
      ecole: nom,
      annee: '2025–2026',
      mois: 'Septembre',
      dateLimiteJour: 0
    }
  };
}

// ───────────────────────────────────────────────────────────
// CRÉATION DES TABLES
// ───────────────────────────────────────────────────────────

async function initDatabase() {
  await pool.query(`
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
  `);

  console.log('✅ Tables PostgreSQL prêtes.');
}

// ───────────────────────────────────────────────────────────
// EXPRESS
// ───────────────────────────────────────────────────────────

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ───────────────────────────────────────────────────────────
// VÉRIFICATION DE SANTÉ
// ───────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    app: 'SuiviScolaire'
  });
});

// ───────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ───────────────────────────────────────────────────────────

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: 'Non authentifié.'
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({
      error: 'Session invalide ou expirée.'
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Réservé à la direction.'
    });
  }

  next();
}

// ───────────────────────────────────────────────────────────
// ÉTABLISSEMENTS — LISTE
// ───────────────────────────────────────────────────────────

app.get('/api/etablissements', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nom FROM etablissements ORDER BY nom'
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: 'Erreur serveur.'
    });
  }
});

// ───────────────────────────────────────────────────────────
// CRÉATION D'UN ÉTABLISSEMENT
// ───────────────────────────────────────────────────────────

app.post('/api/etablissements', async (req, res) => {
  try {
    const { nom, email, password } = req.body || {};

    if (!nom || !email || !password) {
      return res.status(400).json({
        error: 'Nom, email et mot de passe sont requis.'
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        error: 'Le mot de passe doit contenir au moins 4 caractères.'
      });
    }

    const emailNormalise = email.trim().toLowerCase();
    const nomNormalise = nom.trim();

    const existing = await pool.query(
      'SELECT id FROM etablissements WHERE email = $1',
      [emailNormalise]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: 'Un établissement existe déjà avec cet email.'
      });
    }

    const hash = await bcrypt.hash(password, 10);
    const data = defaultData(nomNormalise);

    const result = await pool.query(
      `
      INSERT INTO etablissements
        (nom, email, password_hash, data)
      VALUES
        ($1, $2, $3, $4)
      RETURNING id, nom
      `,
      [
        nomNormalise,
        emailNormalise,
        hash,
        data
      ]
    );

    const etab = result.rows[0];

    const token = jwt.sign(
      {
        etabId: etab.id,
        role: 'admin'
      },
      JWT_SECRET,
      {
        expiresIn: '30d'
      }
    );

    res.json({
      token,
      etab: {
        id: etab.id,
        nom: etab.nom
      }
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Erreur lors de la création de l’établissement.'
    });
  }
});

// ───────────────────────────────────────────────────────────
// CONNEXION DIRECTION
// ───────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    const emailNormalise = (email || '').trim().toLowerCase();

    const result = await pool.query(
      'SELECT * FROM etablissements WHERE email = $1',
      [emailNormalise]
    );

    const row = result.rows[0];

    if (!row || !(await bcrypt.compare(password || '', row.password_hash))) {
      return res.status(401).json({
        error: 'Email ou mot de passe incorrect.'
      });
    }

    const token = jwt.sign(
      {
        etabId: row.id,
        role: 'admin'
      },
      JWT_SECRET,
      {
        expiresIn: '30d'
      }
    );

    res.json({
      token,
      etab: {
        id: row.id,
        nom: row.nom
      }
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Erreur serveur.'
    });
  }
});

// ───────────────────────────────────────────────────────────
// CONNEXION PROFESSEUR
// ───────────────────────────────────────────────────────────

app.post('/api/login-prof', async (req, res) => {
  try {
    const {
      etablissementId,
      classe,
      matiere,
      password
    } = req.body || {};

    if (!etablissementId || !classe || !matiere || !password) {
      return res.status(400).json({
        error: 'Établissement, classe, matière et mot de passe requis.'
      });
    }

    const etabResult = await pool.query(
      'SELECT id, nom FROM etablissements WHERE id = $1',
      [etablissementId]
    );

    const etab = etabResult.rows[0];

    if (!etab) {
      return res.status(404).json({
        error: 'Établissement introuvable.'
      });
    }

    const result = await pool.query(
      `
      SELECT *
      FROM prof_access
      WHERE etablissement_id = $1
        AND classe = $2
        AND matiere = $3
      `,
      [
        etablissementId,
        classe,
        matiere
      ]
    );

    const row = result.rows[0];

    if (
      !row ||
      !(await bcrypt.compare(password, row.password_hash))
    ) {
      return res.status(401).json({
        error:
          'Mot de passe incorrect pour cette classe/matière, ou accès non configuré par la direction.'
      });
    }

    const token = jwt.sign(
      {
        etabId: etab.id,
        role: 'prof',
        classe,
        matiere
      },
      JWT_SECRET,
      {
        expiresIn: '30d'
      }
    );

    res.json({
      token,
      etab: {
        id: etab.id,
        nom: etab.nom
      },
      classe,
      matiere
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Erreur serveur.'
    });
  }
});

// ───────────────────────────────────────────────────────────
// GESTION DES ACCÈS PROFESSEURS
// ───────────────────────────────────────────────────────────

app.get(
  '/api/prof-access',
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT classe, matiere
        FROM prof_access
        WHERE etablissement_id = $1
        `,
        [req.user.etabId]
      );

      res.json(result.rows);

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: 'Erreur serveur.'
      });
    }
  }
);

app.post(
  '/api/prof-access',
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        classe,
        matiere,
        password
      } = req.body || {};

      if (!classe || !matiere || !password) {
        return res.status(400).json({
          error: 'Classe, matière et mot de passe requis.'
        });
      }

      if (password.length < 4) {
        return res.status(400).json({
          error:
            'Le mot de passe doit contenir au moins 4 caractères.'
        });
      }

      const hash = await bcrypt.hash(password, 10);

      await pool.query(
        `
        INSERT INTO prof_access
          (etablissement_id, classe, matiere, password_hash)
        VALUES
          ($1, $2, $3, $4)
        ON CONFLICT (etablissement_id, classe, matiere)
        DO UPDATE SET
          password_hash = EXCLUDED.password_hash
        `,
        [
          req.user.etabId,
          classe,
          matiere,
          hash
        ]
      );

      res.json({
        ok: true
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: 'Erreur serveur.'
      });
    }
  }
);

app.delete(
  '/api/prof-access',
  auth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        classe,
        matiere
      } = req.body || {};

      await pool.query(
        `
        DELETE FROM prof_access
        WHERE etablissement_id = $1
          AND classe = $2
          AND matiere = $3
        `,
        [
          req.user.etabId,
          classe,
          matiere
        ]
      );

      res.json({
        ok: true
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: 'Erreur serveur.'
      });
    }
  }
);

// ───────────────────────────────────────────────────────────
// CHARGER LES DONNÉES
// ───────────────────────────────────────────────────────────

async function loadBlob(etabId) {
  const result = await pool.query(
    'SELECT data FROM etablissements WHERE id = $1',
    [etabId]
  );

  const row = result.rows[0];

  if (!row) {
    return null;
  }

  if (!row.data) {
    return defaultData('Établissement');
  }

  return row.data;
}

// ───────────────────────────────────────────────────────────
// SAUVEGARDER LES DONNÉES
// ───────────────────────────────────────────────────────────

async function saveBlob(etabId, blob) {
  await pool.query(
    'UPDATE etablissements SET data = $1 WHERE id = $2',
    [
      blob,
      etabId
    ]
  );
}

// ───────────────────────────────────────────────────────────
// GET /api/data
// ───────────────────────────────────────────────────────────

app.get('/api/data', auth, async (req, res) => {
  try {
    const blob = await loadBlob(req.user.etabId);

    if (!blob) {
      return res.status(404).json({
        error: 'Établissement introuvable.'
      });
    }

    if (req.user.role === 'admin') {
      return res.json({
        role: 'admin',
        ...blob
      });
    }

    const {
      classe,
      matiere
    } = req.user;

    const elevesCl = (blob.eleves || [])
      .filter(e => e.classe === classe);

    const idsCl = new Set(
      elevesCl.map(e => e.id)
    );

    const notesFiltrees = {};

    for (
      const [eleveId, parMois]
      of Object.entries(blob.notes || {})
    ) {
      if (!idsCl.has(Number(eleveId))) {
        continue;
      }

      const out = {};

      for (
        const [mois, parMatiere]
        of Object.entries(parMois || {})
      ) {
        if (
          parMatiere &&
          parMatiere[matiere] !== undefined
        ) {
          out[mois] = {
            [matiere]: parMatiere[matiere]
          };
        }
      }

      if (Object.keys(out).length) {
        notesFiltrees[eleveId] = out;
      }
    }

    const appreciationsFiltrees = {};

    for (
      const [eleveId, parMois]
      of Object.entries(blob.appreciations || {})
    ) {
      if (!idsCl.has(Number(eleveId))) {
        continue;
      }

      const out = {};

      for (
        const [mois, parMatiere]
        of Object.entries(parMois || {})
      ) {
        if (
          parMatiere &&
          parMatiere[matiere] !== undefined
        ) {
          out[mois] = {
            [matiere]: parMatiere[matiere]
          };
        }
      }

      if (Object.keys(out).length) {
        appreciationsFiltrees[eleveId] = out;
      }
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

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Erreur serveur.'
    });
  }
});

// ───────────────────────────────────────────────────────────
// PUT /api/data
// ───────────────────────────────────────────────────────────

app.put('/api/data', auth, async (req, res) => {
  try {
    const blob = await loadBlob(req.user.etabId);

    if (!blob) {
      return res.status(404).json({
        error: 'Établissement introuvable.'
      });
    }

    const body = req.body || {};

    // ─────────────────────────────
    // ADMIN
    // ─────────────────────────────

    if (req.user.role === 'admin') {
      if (body.eleves !== undefined) {
        blob.eleves = body.eleves;
      }

      if (body.notes !== undefined) {
        blob.notes = body.notes;
      }

      if (body.appreciations !== undefined) {
        blob.appreciations = body.appreciations;
      }

      if (body.envois !== undefined) {
        blob.envois = body.envois;
      }

      if (body.params !== undefined) {
        blob.params = body.params;
      }

      await saveBlob(
        req.user.etabId,
        blob
      );

      return res.json({
        ok: true
      });
    }

    // ─────────────────────────────
    // PROFESSEUR
    // ─────────────────────────────

    const {
      classe,
      matiere
    } = req.user;

    const idsCl = new Set(
      (blob.eleves || [])
        .filter(e => e.classe === classe)
        .map(e => e.id)
    );

    if (body.notes) {
      for (
        const [eleveId, parMois]
        of Object.entries(body.notes)
      ) {
        if (!idsCl.has(Number(eleveId))) {
          continue;
        }

        for (
          const [mois, parMatiere]
          of Object.entries(parMois || {})
        ) {
          const valeurs =
            parMatiere
              ? parMatiere[matiere]
              : undefined;

          if (valeurs === undefined) {
            continue;
          }

          blob.notes[eleveId] =
            blob.notes[eleveId] || {};

          blob.notes[eleveId][mois] =
            blob.notes[eleveId][mois] || {};

          blob.notes[eleveId][mois][matiere] =
            valeurs;
        }
      }
    }

    if (body.appreciations) {
      for (
        const [eleveId, parMois]
        of Object.entries(body.appreciations)
      ) {
        if (!idsCl.has(Number(eleveId))) {
          continue;
        }

        for (
          const [mois, parMatiere]
          of Object.entries(parMois || {})
        ) {
          const texte =
            parMatiere
              ? parMatiere[matiere]
              : undefined;

          if (texte === undefined) {
            continue;
          }

          blob.appreciations[eleveId] =
            blob.appreciations[eleveId] || {};

          blob.appreciations[eleveId][mois] =
            blob.appreciations[eleveId][mois] || {};

          blob.appreciations[eleveId][mois][matiere] =
            texte;
        }
      }
    }

    await saveBlob(
      req.user.etabId,
      blob
    );

    res.json({
      ok: true
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Erreur serveur.'
    });
  }
});

// ───────────────────────────────────────────────────────────
// FICHIERS STATIQUES
// ───────────────────────────────────────────────────────────

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

app.use(
  express.static(__dirname)
);

app.get('*', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'index.html')
  );
});

// ───────────────────────────────────────────────────────────
// DÉMARRAGE
// ───────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, () => {
      console.log(
        `\n✅ SuiviScolaire est lancé sur le port ${PORT}\n`
      );
    });

  } catch (err) {
    console.error(
      '❌ Impossible de démarrer le serveur :',
      err
    );

    process.exit(1);
  }
}

startServer();
