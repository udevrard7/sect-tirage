/* =====================================================================
   Configuration du tirage — « Un serveur, une mission »
   L3 Sécurité informatique
   ---------------------------------------------------------------------
   C'est le SEUL fichier à modifier pour adapter le tirage :
   listes (modules, contextes, contraintes), règles d'incompatibilité,
   session, nombre d'étudiants.
   ===================================================================== */

const CONFIG = {
  projet: "Un serveur, une mission",
  filiere: "L3 Sécurité informatique",
  session: "2026–2027",
  nbEtudiants: 7,

  /* ---- Modules E1–E7 : un et un seul par étudiant, sans remise ---- */
  modules: [
    { code: "E1", titre: "Pare-feu Linux",
      desc: "Filtrage périmétrique nftables : zones, anti-spoofing, journalisation des rejets" },
    { code: "E2", titre: "Serveur Web durci",
      desc: "Nginx durci, HTTPS avec PKI interne, en-têtes de sécurité, WAF (ModSecurity)" },
    { code: "E3", titre: "Base de données durcie",
      desc: "MariaDB : moindre privilège, comptes cloisonnés, chiffrement, exports protégés" },
    { code: "E4", titre: "Authentification centralisée",
      desc: "FreeIPA : annuaire 389-DS, Kerberos, PKI interne, intégration SSH" },
    { code: "E5", titre: "Supervision / SIEM",
      desc: "Wazuh : collecte centralisée, règles de détection, alertes, tableau de bord" },
    { code: "E6", titre: "Détection d'intrusion",
      desc: "Suricata : IDS périmétrique, signatures, réaction aux alertes" },
    { code: "E7", titre: "Audit et sauvegarde",
      desc: "auditd + Borg/Restic : pistes d'audit, politique 3-2-1, restauration testée" }
  ],

  /* ---- Contextes métier X1–X7 : un par étudiant, sans remise ---- */
  contextes: [
    { code: "X1", titre: "PME e-commerce",
      desc: "Boutique en ligne, paiements mobile money, disponibilité critique le soir" },
    { code: "X2", titre: "Clinique privée",
      desc: "Dossiers patients, secret médical, accès soignants 24 h/24" },
    { code: "X3", titre: "Institution de microfinance",
      desc: "Opérations financières quotidiennes, exigences d'audit externe" },
    { code: "X4", titre: "École supérieure privée",
      desc: "Notes et dossiers étudiants, pics de charge aux inscriptions" },
    { code: "X5", titre: "ONG humanitaire",
      desc: "Coordination terrain, liaisons coûteuses, équipes itinérantes" },
    { code: "X6", titre: "Administration communale",
      desc: "Actes d'état civil, service au public, archivage légal" },
    { code: "X7", titre: "Startup fintech",
      desc: "API de paiement, croissance rapide, exigence de disponibilité" }
  ],

  /* ---- Contraintes techniques C1–C7 : une par étudiant, sans remise ---- */
  contraintes: [
    { code: "C1", titre: "Mémoire plafonnée à 2 Go",
      desc: "Le serveur ne dispose que de 2 Go de RAM" },
    { code: "C2", titre: "Connexion Internet intermittente",
      desc: "Lien instable : documentation et mises à jour à préparer hors ligne" },
    { code: "C3", titre: "ARM64 uniquement",
      desc: "Serveur OCI A1 (ARM64) : paquets et images doivent exister en arm64" },
    { code: "C4", titre: "Fenêtre de maintenance nocturne",
      desc: "Interventions autorisées uniquement entre 23 h et 1 h" },
    { code: "C5", titre: "Zéro mot de passe",
      desc: "Clés SSH + second facteur uniquement (TOTP autorisé)" },
    { code: "C6", titre: "Journalisation exigée sur 12 mois",
      desc: "Journaux conservés, intègres et prouvables pendant un an" },
    { code: "C7", titre: "Budget nul",
      desc: "Matériel de récupération et logiciels libres uniquement" }
  ],

  /* ---- Combinaisons écartées automatiquement par le moteur.
         Chaque règle peut cibler un module, un contexte et/ou une
         contrainte ; tous les champs présents doivent correspondre. ---- */
  incompatibilites: [
    { module: "E5", contrainte: "C1",
      raison: "Wazuh (manager + indexeur) exige au moins 4 Go de RAM : infaisable sous un plafond de 2 Go." },
    { module: "E4", contrainte: "C1",
      raison: "FreeIPA (annuaire 389-DS, Kerberos, PKI) exige à lui seul environ 3 Go de RAM." }
  ]
};

/* Export Node.js (tests automatiques et tools/rejouer.js). */
if (typeof module !== "undefined" && module.exports) {
  module.exports = { CONFIG: CONFIG };
}
