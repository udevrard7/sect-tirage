#!/usr/bin/env node
"use strict";

/* =====================================================================
   rejouer.js — revérifier un tirage à partir de sa graine
   ---------------------------------------------------------------------
   Usage :
     node tools/rejouer.js <graine> "Nom 1, Nom 2, …" [--fixe]

   - <graine>  : la graine de 128 bits affichée/exportée par le site
   - les noms  : dans l'ORDRE DE SAISIE utilisé le jour du tirage
   - --fixe    : si l'option « ordre d'appel aléatoire » était décochée
                 (par défaut : mélange activé)

   Reproduit exactement le tirage, à condition d'utiliser la même
   version des listes (js/data.js) — d'où l'intérêt du dépôt Git.
   ===================================================================== */

var app = require("../js/app.js");
var CFG = app.CFG;

var args = process.argv.slice(2);
var graine = args[0];
var nomsArg = args[1];
var melanger = !args.includes("--fixe");

function usage() {
  console.error("Usage : node tools/rejouer.js <graine> \"Nom 1, Nom 2, …\" [--fixe]");
  process.exit(1);
}

if (!graine || !/^[0-9a-f]{32}$/i.test(graine)) {
  console.error("Erreur : graine invalide (32 caractères hexadécimaux attendus).");
  usage();
}
if (!nomsArg) {
  console.error("Erreur : fournissez les noms dans l'ordre de saisie, séparés par des virgules.");
  usage();
}

var noms = nomsArg.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
if (noms.length !== CFG.nbEtudiants) {
  console.error("Erreur : " + noms.length + " nom(s) fourni(s), " + CFG.nbEtudiants +
    " attendu(s) (CONFIG.nbEtudiants dans js/data.js).");
  process.exit(1);
}

var t = app.tirageDepuisGraine(graine.toLowerCase(), { melanger: melanger, nb: noms.length });
if (!t) {
  console.error("Aucun tirage valide pour cette graine : les listes (js/data.js) ont probablement changé depuis le tirage.");
  process.exit(2);
}

console.log("Tirage rejoué — « " + CFG.projet + " » (" + CFG.filiere + ", session " + CFG.session + ")");
console.log("Graine : " + graine.toLowerCase());
console.log("Ordre d'appel aléatoire : " + (melanger ? "oui" : "non"));
console.log("---");
t.ordre.forEach(function (idx, pos) {
  var m = CFG.modules[t.modules[pos]];
  var x = CFG.contextes[t.contextes[pos]];
  var c = CFG.contraintes[t.contraintes[pos]];
  console.log((pos + 1) + ". " + noms[idx] + " — " + m.code + " " + m.titre +
    " | " + x.code + " " + x.titre +
    " | " + c.code + " " + c.titre);
});
