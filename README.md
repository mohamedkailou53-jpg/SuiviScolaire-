# SuiviScolaire — Backend local

Application locale (Node.js + Express + SQLite) qui relie le front-end
SuiviScolaire à un vrai backend :

- Chaque **établissement** crée son propre compte (nom, email, mot de passe).
- La **direction** (compte établissement) a accès à tout : élèves, notes,
  paramètres, gestion des accès professeurs.
- Chaque **professeur** ne peut se connecter qu'avec : établissement + classe
  + matière + mot de passe (défini par la direction dans Paramètres →
  "Accès des professeurs"). Une fois connecté, il ne voit et ne peut saisir
  que les notes/appréciations de **sa classe et sa matière** — c'est vérifié
  aussi bien côté interface que côté serveur.

## Installation (une seule fois)

Il faut avoir [Node.js](https://nodejs.org) installé (version 18 ou plus récente).

```bash
cd suiviscolaire-app
npm install
```

## Lancer l'application

```bash
npm start
```

Puis ouvrez votre navigateur sur : **http://localhost:3000**

Les données sont stockées dans un fichier `data/suiviscolaire.db` (SQLite)
créé automatiquement au premier démarrage — rien à configurer.

## Première utilisation

1. Sur l'écran de connexion, cliquez sur **"Créer mon établissement"**
   (onglet Direction), renseignez le nom de l'école, un email et un mot de
   passe.
2. Vous arrivez dans l'application avec un accès complet (direction).
3. Ajoutez vos élèves (page **Élèves**).
4. Allez dans **Paramètres → 🔑 Accès des professeurs** : pour chaque
   classe/matière, définissez un mot de passe et cliquez sur 💾.
5. Donnez à chaque professeur : le nom de l'établissement, sa classe, sa
   matière, et le mot de passe correspondant. Il se connecte via l'onglet
   **"Professeur"** de l'écran de connexion.

## Notes techniques

- Backend : Express + SQLite (`better-sqlite3`), mots de passe hachés avec
  `bcryptjs`, sessions par jeton JWT.
- Le front-end (`public/index.html`) est l'application d'origine, à laquelle
  a été ajouté un écran de connexion et des appels au backend (`fetch`) pour
  charger/sauvegarder les données au lieu du `localStorage` du navigateur.
- Pour arrêter le serveur : `Ctrl + C` dans le terminal.
