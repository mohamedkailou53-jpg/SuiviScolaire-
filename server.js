// SuiviScolaire — Backend Node.js + Express + PostgreSQL
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL est manquant.');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET est manquant.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000
});

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

function defaultData(nom) {
  return {
    eleves: [], notes: {}, appreciations: {}, envois: {},
    params: { ecole: nom, annee: '2026–2027', mois: 'Septembre', dateLimiteJour: 0 }
  };
}

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
      etablissement_id INTEGER NOT NULL REFERENCES etablissements(id) ON DELETE CASCADE,
      classe TEXT NOT NULL,
      matiere TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      UNIQUE (etablissement_id, classe, matiere)
    );
  `);
  console.log('✅ Tables PostgreSQL vérifiées.');
}

async function getEstablishment(id) {
  const r = await pool.query('SELECT id, nom, email, data FROM etablissements WHERE id=$1', [id]);
  return r.rows[0] || null;
}

async function getData(id) {
  const etab = await getEstablishment(id);
  if (!etab) return null;
  const data = etab.data && typeof etab.data === 'object' ? etab.data : defaultData(etab.nom);
  if (!data.eleves) data.eleves = [];
  if (!data.notes) data.notes = {};
  if (!data.appreciations) data.appreciations = {};
  if (!data.envois) data.envois = {};
  if (!data.params) data.params = defaultData(etab.nom).params;
  if (!data.params.ecole) data.params.ecole = etab.nom;
  return data;
}

async function saveData(id, data) {
  await pool.query('UPDATE etablissements SET data=$1::jsonb WHERE id=$2', [JSON.stringify(data), id]);
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Non authentifié.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Session invalide ou expirée. Veuillez vous reconnecter.' }); }
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Action réservée à la direction.' });
  next();
}

app.get('/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok:true, app:'SuiviScolaire', database:'connected' }); }
  catch (e) { console.error('Health:', e.message); res.status(503).json({ ok:false, app:'SuiviScolaire', database:'error' }); }
});

app.get('/api/etablissements', async (req,res) => {
  try {
    const r = await pool.query('SELECT id, nom FROM etablissements ORDER BY nom ASC');
    res.json(r.rows);
  } catch(e) { console.error(e); res.status(500).json({error:'Impossible de charger les établissements.'}); }
});

app.post('/api/etablissements', async (req,res) => {
  try {
    const nom=String(req.body?.nom||'').trim(), email=String(req.body?.email||'').trim().toLowerCase(), password=String(req.body?.password||'');
    if(!nom||!email||!password) return res.status(400).json({error:'Nom, email et mot de passe sont requis.'});
    if(password.length<4) return res.status(400).json({error:'Le mot de passe doit contenir au moins 4 caractères.'});
    const exists=await pool.query('SELECT id FROM etablissements WHERE email=$1',[email]);
    if(exists.rows.length) return res.status(409).json({error:'Un établissement existe déjà avec cet email.'});
    const hash=await bcrypt.hash(password,10), data=defaultData(nom);
    const r=await pool.query(`INSERT INTO etablissements(nom,email,password_hash,data) VALUES($1,$2,$3,$4::jsonb) RETURNING id,nom`,[nom,email,hash,JSON.stringify(data)]);
    const etab=r.rows[0], token=jwt.sign({etabId:etab.id,role:'admin'},JWT_SECRET,{expiresIn:'30d'});
    res.json({token,etab});
  } catch(e) { console.error(e); res.status(500).json({error:'Impossible de créer l’établissement.'}); }
});

app.post('/api/login', async (req,res) => {
  try {
    const email=String(req.body?.email||'').trim().toLowerCase(), password=String(req.body?.password||'');
    const r=await pool.query('SELECT id,nom,password_hash FROM etablissements WHERE email=$1',[email]);
    const e=r.rows[0];
    if(!e || !(await bcrypt.compare(password,e.password_hash))) return res.status(401).json({error:'Email ou mot de passe incorrect.'});
    const token=jwt.sign({etabId:e.id,role:'admin'},JWT_SECRET,{expiresIn:'30d'});
    res.json({token,etab:{id:e.id,nom:e.nom}});
  } catch(e) { console.error(e); res.status(500).json({error:'Erreur serveur lors de la connexion.'}); }
});

app.post('/api/login-prof', async (req,res) => {
  try {
    const etablissementId=Number(req.body?.etablissementId), classe=String(req.body?.classe||''), matiere=String(req.body?.matiere||''), password=String(req.body?.password||'');
    if(!etablissementId||!classe||!matiere||!password) return res.status(400).json({error:'Établissement, classe, matière et mot de passe requis.'});
    const er=await pool.query('SELECT id,nom FROM etablissements WHERE id=$1',[etablissementId]);
    const etab=er.rows[0];
    if(!etab) return res.status(404).json({error:'Établissement introuvable.'});
    const r=await pool.query('SELECT password_hash FROM prof_access WHERE etablissement_id=$1 AND classe=$2 AND matiere=$3',[etablissementId,classe,matiere]);
    const a=r.rows[0];
    if(!a || !(await bcrypt.compare(password,a.password_hash))) return res.status(401).json({error:'Accès professeur incorrect ou non configuré.'});
    const token=jwt.sign({etabId:etab.id,role:'prof',classe,matiere},JWT_SECRET,{expiresIn:'30d'});
    res.json({token,etab:{id:etab.id,nom:etab.nom},classe,matiere});
  } catch(e) { console.error(e); res.status(500).json({error:'Erreur serveur lors de la connexion professeur.'}); }
});

app.get('/api/prof-access',auth,requireAdmin,async(req,res)=>{
  try { const r=await pool.query('SELECT id,classe,matiere FROM prof_access WHERE etablissement_id=$1 ORDER BY classe,matiere',[req.user.etabId]); res.json(r.rows); }
  catch(e){console.error(e);res.status(500).json({error:'Impossible de charger les accès professeurs.'});}
});

app.post('/api/prof-access',auth,requireAdmin,async(req,res)=>{
  try {
    const classe=String(req.body?.classe||''), matiere=String(req.body?.matiere||''), password=String(req.body?.password||'');
    if(!classe||!matiere||!password) return res.status(400).json({error:'Classe, matière et mot de passe requis.'});
    const hash=await bcrypt.hash(password,10);
    await pool.query(`INSERT INTO prof_access(etablissement_id,classe,matiere,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(etablissement_id,classe,matiere) DO UPDATE SET password_hash=EXCLUDED.password_hash`,[req.user.etabId,classe,matiere,hash]);
    res.json({ok:true});
  } catch(e){console.error(e);res.status(500).json({error:'Impossible d’enregistrer l’accès professeur.'});}
});

app.delete('/api/prof-access',auth,requireAdmin,async(req,res)=>{
  try { await pool.query('DELETE FROM prof_access WHERE etablissement_id=$1 AND classe=$2 AND matiere=$3',[req.user.etabId,String(req.body?.classe||''),String(req.body?.matiere||'')]); res.json({ok:true}); }
  catch(e){console.error(e);res.status(500).json({error:'Impossible de supprimer l’accès professeur.'});}
});

app.get('/api/data',auth,async(req,res)=>{
  try {
    const blob=await getData(req.user.etabId);
    if(!blob) return res.status(404).json({error:'Établissement introuvable.'});
    if(req.user.role==='admin') return res.json({role:'admin',...blob});
    const {classe,matiere}=req.user, eleves=blob.eleves.filter(e=>e.classe===classe), ids=new Set(eleves.map(e=>Number(e.id))), notes={}, appreciations={};
    for(const [id,months] of Object.entries(blob.notes||{})) if(ids.has(Number(id))){const out={}; for(const [m,ms] of Object.entries(months||{})) if(ms&&Object.prototype.hasOwnProperty.call(ms,matiere)) out[m]={[matiere]:ms[matiere]}; if(Object.keys(out).length) notes[id]=out;}
    for(const [id,months] of Object.entries(blob.appreciations||{})) if(ids.has(Number(id))){const out={}; for(const [m,ms] of Object.entries(months||{})) if(ms&&Object.prototype.hasOwnProperty.call(ms,matiere)) out[m]={[matiere]:ms[matiere]}; if(Object.keys(out).length) appreciations[id]=out;}
    res.json({role:'prof',classe,matiere,eleves,notes,appreciations,envois:{},params:blob.params});
  } catch(e){console.error(e);res.status(500).json({error:'Impossible de charger les données.'});}
});

app.put('/api/data',auth,async(req,res)=>{
  try {
    const blob=await getData(req.user.etabId);
    if(!blob) return res.status(404).json({error:'Établissement introuvable.'});
    const b=req.body||{};
    if(req.user.role==='admin'){
      if(b.eleves!==undefined) blob.eleves=b.eleves;
      if(b.notes!==undefined) blob.notes=b.notes;
      if(b.appreciations!==undefined) blob.appreciations=b.appreciations;
      if(b.envois!==undefined) blob.envois=b.envois;
      if(b.params!==undefined) blob.params=b.params;
      await saveData(req.user.etabId,blob); return res.json({ok:true});
    }
    const {classe,matiere}=req.user, ids=new Set(blob.eleves.filter(e=>e.classe===classe).map(e=>Number(e.id)));
    for(const [id,months] of Object.entries(b.notes||{})) if(ids.has(Number(id))) for(const [month,ms] of Object.entries(months||{})) if(ms&&Object.prototype.hasOwnProperty.call(ms,matiere)){blob.notes[id]=blob.notes[id]||{};blob.notes[id][month]=blob.notes[id][month]||{};blob.notes[id][month][matiere]=ms[matiere];}
    for(const [id,months] of Object.entries(b.appreciations||{})) if(ids.has(Number(id))) for(const [month,ms] of Object.entries(months||{})) if(ms&&Object.prototype.hasOwnProperty.call(ms,matiere)){blob.appreciations[id]=blob.appreciations[id]||{};blob.appreciations[id][month]=blob.appreciations[id][month]||{};blob.appreciations[id][month][matiere]=ms[matiere];}
    await saveData(req.user.etabId,blob); res.json({ok:true});
  } catch(e){console.error(e);res.status(500).json({error:'Impossible de sauvegarder les données.'});}
});

// Frontend : fonctionne si index.html est dans /public OU à la racine.
const publicDir=path.join(__dirname,'public'), publicIndex=path.join(publicDir,'index.html'), rootIndex=path.join(__dirname,'index.html');
if(fs.existsSync(publicDir)) app.use(express.static(publicDir));
app.use(express.static(__dirname));
app.get('*',(req,res)=>{
  if(fs.existsSync(publicIndex)) return res.sendFile(publicIndex);
  if(fs.existsSync(rootIndex)) return res.sendFile(rootIndex);
  res.status(404).send('SuiviScolaire : index.html introuvable.');
});

async function startServer(){
  try { await initDatabase(); await pool.query('SELECT 1'); app.listen(PORT,()=>console.log(`✅ SuiviScolaire lancé sur le port ${PORT}`)); }
  catch(e){console.error('❌ Impossible de démarrer SuiviScolaire:',e);process.exit(1);}
}
startServer();
