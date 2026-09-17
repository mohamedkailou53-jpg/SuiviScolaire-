# Déploiement rapide de SuiviScolaire

## Render
1. Importer le projet dans un dépôt GitHub.
2. Sur Render, créer un **Web Service** depuis ce dépôt.
3. Render détecte `render.yaml`, ou utiliser :
   - Build Command : `npm install`
   - Start Command : `npm start`
   - Health Check Path : `/health`
4. Une URL publique `https://...onrender.com` sera fournie.

### Important — SQLite
La version gratuite d'un hébergement web peut avoir un stockage éphémère. Pour conserver durablement les élèves et les notes, il faudra ensuite utiliser un stockage persistant/base de données adaptée.
