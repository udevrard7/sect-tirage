# sect-tirage — Tirage en ligne « Un serveur, une mission »

Site **statique** pour le **tirage officiel des sujets du projet individuel** du cours de
**L3 Sécurité informatique** (projet « Un serveur, une mission », 60 % de la note).

Conçu pour être projeté en classe, déployé gratuitement sur **Vercel**, puis retiré
à la fin de la session.

## Principe

Chaque étudiant reçoit, **sans remise** (aucun doublon dans la promotion) :

| Axe | Éléments |
|---|---|
| **Module** (E1–E7) | Pare-feu Linux · Serveur Web durci · BDD durcie · Authentification centralisée · SIEM (Wazuh) · IDS (Suricata) · Audit & sauvegarde |
| **Contexte métier** (X1–X7) | PME e-commerce · Clinique privée · Microfinance · École privée · ONG · Administration communale · Startup fintech |
| **Contrainte technique** (C1–C7) | 2 Go RAM · Connexion intermittente · ARM64 · Fenêtre nocturne · Zéro mot de passe · Journalisation 12 mois · Budget nul |

Soit **7 × 7 × 7 = 343 combinaisons possibles**, dont les combinaisons
techniquement infaisables (ex. *SIEM Wazuh* × *2 Go de RAM*) sont **écartées d'office**
par le moteur de tirage.

## Caractéristiques

- **Équité vérifiable** : aléatoire cryptographique (`crypto.getRandomValues`), graine
  publique de 128 bits, dérivation déterministe (xorshift128), empreinte **SHA-256** du
  résultat — le tirage est rejouable à l'identique et infalsifiable.
- **Aucun doublon** : modules, contextes et contraintes distribués sans remise.
- **100 % côté client** : aucun serveur, aucune donnée envoyée (les noms restent dans le
  navigateur), fonctionne hors ligne une fois la page chargée.
- **Exports** : CSV (compatible Excel francophone), impression / PDF, récapitulatif
  copiable (pour WhatsApp ou e-mail).
- **Rejeu en ligne de commande** : `node tools/rejouer.js` redonne le tirage à partir
  de la graine (utile en cas de contestation).
- **Aucune dépendance** : HTML + CSS + JS purs, aucune construction, aucun CDN.

## Structure du dépôt

```
sect-tirage/
├── index.html          # page unique (interface française)
├── css/style.css       # thème sombre, styles d'impression
├── js/data.js          # ← SEUL fichier à modifier (listes, règles, session)
├── js/app.js           # moteur de tirage + interface (navigateur et Node)
├── tools/rejouer.js    # rejeu / vérification d'un tirage depuis sa graine
├── README.md
├── LICENSE             # MIT
└── .gitignore
```

## Personnalisation

Tout est centralisé dans **`js/data.js`** :

- `modules`, `contextes`, `contraintes` : les trois listes (code, titre, description) ;
- `incompatibilites` : les combinaisons à écarter (chaque règle peut cibler un
  `module`, un `contexte` et/ou une `contrainte`) ;
- `session`, `filiere`, `projet` : textes d'affichage ;
- `nbEtudiants` : nombre d'étudiants (≤ 7 ; au-delà, il faudrait des listes plus longues).

> Après modification de `js/data.js`, redéployez (push Git → Vercel redéploie
> automatiquement) : les graines déjà publiées ne rejoueront plus à l'identique,
> ce qui est précisément le rôle du dépôt versionné.

## Tester en local

```bash
cd sect-tirage
python3 -m http.server 8000
# puis ouvrir http://localhost:8000
```

(Ouvrir directement `index.html` dans un navigateur fonctionne aussi.)

## Déployer sur Vercel

### Méthode A — depuis GitHub (recommandée, sans ligne de commande)

1. Ce dépôt est sur votre compte GitHub.
2. Ouvrez <https://vercel.com/new> et connectez-vous avec GitHub.
3. Cliquez sur **Import** en face du dépôt `sect-tirage`.
4. Framework Preset : **Other** — aucun build, aucune variable d'environnement.
5. **Deploy** : le site est en ligne en quelques secondes
   (URL du type `sect-tirage-xxxx.vercel.app`).

Chaque `git push` sur la branche `main` redéploie automatiquement le site.

### Méthode B — en ligne de commande (CLI Vercel)

```bash
npm i -g vercel
vercel          # déploiement de prévisualisation
vercel --prod   # déploiement en production
```

### Retirer le site après la session

Vercel → projet `sect-tirage` → **Settings** → **Delete Project**.
Le code reste dans le dépôt GitHub pour la traçabilité des tirages.

## Bonnes pratiques de sécurité

- Ne committez **jamais** de secret (jeton GitHub, clé API, `.env`) dans un dépôt.
- Après un usage partagé d'un *Personal Access Token*, révoquez-le sur
  <https://github.com/settings/tokens>.
- Ce site ne collecte rien : les noms saisis restent dans le `localStorage`
  du navigateur qui a servi au tirage.

## Auteur

udevrard7 (Ulrich DOUH) — ulrichdouh@gmail.com

## Licence

MIT — voir [LICENSE](LICENSE).
