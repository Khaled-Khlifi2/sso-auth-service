# SSO Auth Microservice

Auth complète avec **2FA TOTP** et **OAuth2 (Google / GitHub)**.
PostgreSQL local.

**FastAPI · PostgreSQL · Redis · JWT · 2FA TOTP · OAuth2**

---

## Installation manuelle

### 1. Virtualenv et dépendances

```
python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows

pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Base de données

```
psql -U postgres -c "CREATE DATABASE sso_auth;"
```

### 3. Configuration

```
cp .env.example .env
```

Générer la SECRET_KEY :

```
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```

Ouvrir `.env` et remplir au minimum :

```
SECRET_KEY=<valeur générée ci-dessus>
DATABASE_URL=postgresql+asyncpg://postgres:VOTRE_MOT_DE_PASSE@localhost:5432/sso_auth
```

### 4. Migrations

```
alembic upgrade head
```

### 5. Démarrer

```
uvicorn app.main:app --reload
```

→ **http://localhost:8000/docs**

---

## Structure

```
sso-auth/
├── .env.example
├── .gitignore
├── requirements.txt
├── alembic.ini
│
├── app/
│   ├── main.py              Application FastAPI
│   ├── config.py            Paramètres depuis .env
│   ├── database.py          SQLAlchemy async
│   ├── security.py          JWT, bcrypt, rate limiting, dépendances
│   ├── totp_utils.py        2FA TOTP (pyotp) + QR code + codes de secours
│   │
│   ├── models/
│   │   ├── user.py          Table users (avec champs 2FA et oauth_provider)
│   │   ├── token.py         Table refresh_tokens
│   │   └── oauth.py         Table oauth_states (protection CSRF)
│   │
│   ├── schemas/
│   │   └── auth.py          Schémas Pydantic requêtes / réponses
│   │
│   ├── services/
│   │   ├── auth_service.py  Logique auth locale + 2FA
│   │   └── oauth_service.py Logique OAuth2 Google / GitHub
│   │
│   └── routers/
│       ├── auth.py          /api/v1/auth/*
│       ├── users.py         /api/v1/users/*
│       ├── admin.py         /api/v1/admin/*
│       └── oauth2.py        /api/v1/oauth2/*
│
└── alembic/
    ├── env.py
    ├── script.py.mako
    └── versions/
        └── 0001_initial_schema.py
```

---

## Endpoints

### Auth  `/api/v1/auth`

| Méthode | Chemin | Description |
|---------|--------|-------------|
| POST | `/register` | Créer un compte |
| POST | `/login` | Se connecter |
| POST | `/2fa/verify` | Login étape 2 — code TOTP ou backup |
| GET  | `/2fa/setup` | Obtenir secret TOTP + QR code |
| POST | `/2fa/verify-setup` | Activer la 2FA |
| POST | `/2fa/disable` | Désactiver la 2FA |
| POST | `/refresh` | Rafraîchir les tokens |
| POST | `/logout` | Se déconnecter |

### OAuth2  `/api/v1/oauth2`

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/providers` | Providers configurés |
| GET | `/login/google` | Redirection vers Google |
| GET | `/login/github` | Redirection vers GitHub |
| GET | `/callback/google` | Callback automatique |
| GET | `/callback/github` | Callback automatique |

### Profil  `/api/v1/users`

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET    | `/me` | Mon profil |
| PATCH  | `/me` | Modifier profil |
| POST   | `/me/change-password` | Changer le mot de passe |

### Admin  `/api/v1/admin`  *(rôle ADMIN requis)*

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET    | `/stats` | Statistiques |
| GET    | `/users` | Liste paginée |
| GET    | `/users/{id}` | Détail utilisateur |
| PATCH  | `/users/{id}` | Modifier |
| DELETE | `/users/{id}` | Supprimer |
| POST   | `/users/{id}/reset-2fa` | Réinitialiser 2FA |

### Santé

| GET | `/health` | État service + BDD + Redis |
| GET | `/docs`   | Swagger UI |
| GET | `/redoc`  | ReDoc |

---

## Configurer OAuth2

### Google
1. Aller sur https://console.cloud.google.com/apis/credentials
2. Créer des identifiants → OAuth 2.0
3. Ajouter l'URI de redirection : `http://localhost:8000/api/v1/oauth2/callback/google`
4. Copier dans `.env` :
   ```
   GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=GOCSPX-xxx
   ```

### GitHub
1. Aller sur https://github.com/settings/applications/new
2. Callback URL : `http://localhost:8000/api/v1/oauth2/callback/github`
3. Copier dans `.env` :
   ```
   GITHUB_CLIENT_ID=Ov23liXXXXXX
   GITHUB_CLIENT_SECRET=ghp_XXXXXXXX
   ```

Tester en ouvrant dans le navigateur :
- http://localhost:8000/api/v1/oauth2/login/google
- http://localhost:8000/api/v1/oauth2/login/github

> Si non configurés, les providers sont absents de `/api/v1/oauth2/providers` sans aucune erreur.

---

## Activer la 2FA

```
1. GET  /api/v1/auth/2fa/setup
   → { secret, qr_uri, qr_image_base64 }
   → Afficher qr_image_base64 dans <img src="data:image/png;base64,...">
   → Ou scanner qr_uri avec l'appli Authenticator

2. Scanner avec Google Authenticator, Authy ou 1Password

3. POST /api/v1/auth/2fa/verify-setup  { "code": "123456" }
   → { backup_codes: ["A1B2-C3D4", ...] }
   → Sauvegarder ces 8 codes — affichés UNE SEULE FOIS

4. Prochain login → { requires_2fa: true, pending_token: "..." }

5. POST /api/v1/auth/2fa/verify
   { "pending_token": "...", "code": "123456" }
   → { access_token, refresh_token, ... }
```

---

## Variables d'environnement

| Variable | Requis | Défaut | Description |
|----------|--------|--------|-------------|
| `SECRET_KEY` | ✅ | — | Clé JWT ≥ 32 chars |
| `DATABASE_URL` | ✅ | postgres local | URL PostgreSQL |
| `REDIS_URL` | Non | redis local | Rate limiting + blacklist JWT |
| `ENVIRONMENT` | Non | development | development / production |
| `FIRST_ADMIN_EMAIL` | Non | — | Admin créé au démarrage |
| `FIRST_ADMIN_PASSWORD` | Non | — | Mot de passe admin initial |
| `GOOGLE_CLIENT_ID` | Non | — | OAuth2 Google |
| `GOOGLE_CLIENT_SECRET` | Non | — | OAuth2 Google |
| `GITHUB_CLIENT_ID` | Non | — | OAuth2 GitHub |
| `GITHUB_CLIENT_SECRET` | Non | — | OAuth2 GitHub |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Non | 15 | Durée access token |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Non | 7 | Durée refresh token |
| `MAX_LOGIN_ATTEMPTS` | Non | 5 | Tentatives avant verrouillage |
| `LOCKOUT_DURATION_MIN` | Non | 15 | Durée du verrouillage |

---

## Production

Changer dans `.env` :
```
ENVIRONMENT=production
DEBUG=false
BASE_URL=https://votre-domaine.com
CORS_ORIGINS=https://votre-frontend.com
```

Démarrer avec plusieurs workers :
```
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 --loop uvloop
```
