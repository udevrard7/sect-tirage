"use strict";

/* =====================================================================
   « Un serveur, une mission » — moteur de tirage + interface
   ---------------------------------------------------------------------
   Site 100 % côté client : aucun nom, aucun résultat ne quitte le
   navigateur. Le moteur est utilisable aussi bien sous le navigateur
   que sous Node (tests automatiques, tools/rejouer.js).
   ===================================================================== */

/* ---------- Configuration (js/data.js) ---------- */
var CFG = (typeof CONFIG !== "undefined") ? CONFIG : require("./data.js").CONFIG;

/* =====================================================================
   1. ALÉATOIRE — graine cryptographique + dérivation déterministe
   ===================================================================== */

/* Graine de 128 bits (32 caractères hexadécimaux). */
function nouvelleGraine() {
  var octets = new Uint8Array(16);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(octets);
  } else {
    for (var i = 0; i < octets.length; i++) octets[i] = Math.floor(Math.random() * 256);
  }
  var sortie = "";
  for (var j = 0; j < octets.length; j++) {
    sortie += octets[j].toString(16).padStart(2, "0");
  }
  return sortie;
}

/* xorshift128 : PRNG déterministe de période 2^128 - 1.
   Une même graine produit exactement la même suite — le tirage est
   donc rejouable à l'identique (vérification, contestations). */
function prngDepuisGraine(hex) {
  var a = (parseInt(hex.slice(0, 8), 16) || 0x9e3779b9) >>> 0;
  var b = (parseInt(hex.slice(8, 16), 16) || 0x243f6a88) >>> 0;
  var c = (parseInt(hex.slice(16, 24), 16) || 0xb7e15162) >>> 0;
  var d = (parseInt(hex.slice(24, 32), 16) || 0x7f4a7c15) >>> 0;
  if (a === 0 && b === 0 && c === 0 && d === 0) a = 1;
  return function () {
    var t = (a ^ ((a << 11) >>> 0)) >>> 0;
    var u = (t ^ (t >>> 8)) >>> 0;
    a = b; b = c; c = d;
    d = ((d ^ (d >>> 19)) ^ u) >>> 0;
    return d / 4294967296;
  };
}

/* Mélange de Fisher–Yates (uniforme, ne modifie pas l'original). */
function melanger(tableau, rng) {
  var t = tableau.slice();
  for (var i = t.length - 1; i > 0; i--) {
    var j = Math.floor(rng() * (i + 1));
    var tmp = t[i]; t[i] = t[j]; t[j] = tmp;
  }
  return t;
}

/* =====================================================================
   2. SHA-256 autonome
   ---------------------------------------------------------------------
   Implémentation complète en JavaScript, sans dépendance : fonctionne
   y compris hors contexte sécurisé (fichier local ouvert directement).
   ===================================================================== */

var SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha256Hex(texte) {
  var data = new TextEncoder().encode(texte);
  var l = data.length;
  var nbBlocs = Math.ceil((l + 9) / 64);
  var tampon = new Uint8Array(nbBlocs * 64);
  tampon.set(data);
  tampon[l] = 0x80;
  var vue = new DataView(tampon.buffer);
  var bitsTotal = l * 8; /* nos messages sont très loin de 2^32 bits */
  vue.setUint32(tampon.length - 8, Math.floor(bitsTotal / 0x100000000));
  vue.setUint32(tampon.length - 4, bitsTotal >>> 0);

  var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  var w = new Uint32Array(64);
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  for (var bloc = 0; bloc < tampon.length; bloc += 64) {
    var i;
    for (i = 0; i < 16; i++) w[i] = vue.getUint32(bloc + 4 * i);
    for (i = 16; i < 64; i++) {
      var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (i = 0; i < 64; i++) {
      var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      var ch = (e & f) ^ (~e & g);
      var t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map(function (x) { return x.toString(16).padStart(8, "0"); })
    .join("");
}

/* =====================================================================
   3. MOTEUR DE TIRAGE
   ===================================================================== */

/* Renvoie la liste des règles d'incompatibilité violées par le trio. */
function reglesViolées(codeModule, codeContexte, codeContrainte) {
  return CFG.incompatibilites.filter(function (r) {
    if (r.module && r.module !== codeModule) return false;
    if (r.contexte && r.contexte !== codeContexte) return false;
    if (r.contrainte && r.contrainte !== codeContrainte) return false;
    return true;
  });
}

/* Vrai si aucune règle n'est violée sur l'ensemble des positions. */
function tirageValide(modules, contextes, contraintes) {
  for (var i = 0; i < modules.length; i++) {
    if (reglesViolées(CFG.modules[modules[i]].code,
                      CFG.contextes[contextes[i]].code,
                      CFG.contraintes[contraintes[i]].code).length > 0) {
      return false;
    }
  }
  return true;
}

/* Filet de sécurité : si le pur hasard n'aboutit pas (règles très
   contraintes), on répare par échanges de paires. */
function reparerTirage(modules, contextes, contraintes) {
  function conflit(i) {
    return reglesViolées(CFG.modules[modules[i]].code,
                         CFG.contextes[contextes[i]].code,
                         CFG.contraintes[contraintes[i]].code).length > 0;
  }
  for (var passe = 0; passe < 100; passe++) {
    var mauvais = [];
    for (var i = 0; i < modules.length; i++) if (conflit(i)) mauvais.push(i);
    if (mauvais.length === 0) return true;
    var resolu = false;
    for (var m = 0; m < mauvais.length && !resolu; m++) {
      var pos = mauvais[m];
      for (var j = 0; j < modules.length && !resolu; j++) {
        if (j === pos) continue;
        var axes = [contraintes, contextes, modules];
        for (var k = 0; k < axes.length && !resolu; k++) {
          var axe = axes[k];
          var ti = axe[pos], tj = axe[j];
          axe[pos] = tj; axe[j] = ti;
          if (!conflit(pos) && !conflit(j)) { resolu = true; break; }
          axe[pos] = ti; axe[j] = tj; /* annule l'échange */
        }
      }
    }
    if (!resolu) return false;
  }
  return false;
}

/* Tirage complet, déterministe depuis une graine.
   Renvoie { ordre, modules, contextes, contraintes } ou null si
   aucune combinaison valable n'existe avec les règles actuelles.
   - ordre[i]       : indice de l'étudiant appelé en position i
   - modules[i]     : indice du module attribué en position i, etc. */
function tirageDepuisGraine(graine, options) {
  var opts = options || {};
  var nb = opts.nb || CFG.nbEtudiants;
  if (nb > CFG.modules.length || nb > CFG.contextes.length || nb > CFG.contraintes.length) return null;

  var rng = prngDepuisGraine(graine);
  function indices(n) {
    var t = [];
    for (var i = 0; i < n; i++) t.push(i);
    return t;
  }

  var ordre = opts.melanger ? melanger(indices(nb), rng) : indices(nb);

  var essai;
  for (essai = 0; essai < 300; essai++) {
    var modules = melanger(indices(CFG.modules.length), rng).slice(0, nb);
    var contextes = melanger(indices(CFG.contextes.length), rng).slice(0, nb);
    var contraintes = melanger(indices(CFG.contraintes.length), rng).slice(0, nb);
    if (tirageValide(modules, contextes, contraintes)) {
      return { ordre: ordre, modules: modules, contextes: contextes, contraintes: contraintes };
    }
  }

  /* Dernier recours : un tirage de plus, réparé par échanges. */
  var modules2 = melanger(indices(CFG.modules.length), rng).slice(0, nb);
  var contextes2 = melanger(indices(CFG.contextes.length), rng).slice(0, nb);
  var contraintes2 = melanger(indices(CFG.contraintes.length), rng).slice(0, nb);
  if (reparerTirage(modules2, contextes2, contraintes2)) {
    return { ordre: ordre, modules: modules2, contextes: contextes2, contraintes: contraintes2 };
  }
  return null;
}

/* Tirage officiel : graine fraîche (aléa cryptographique) puis
   dérivation déterministe. */
function effectuerTirage(options) {
  var graine = nouvelleGraine();
  var t = tirageDepuisGraine(graine, options);
  if (!t) return null;
  t.graine = graine;
  return t;
}

/* =====================================================================
   4. EXPORTS NODE (tests automatiques, tools/rejouer.js)
   ===================================================================== */
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    CFG: CFG,
    nouvelleGraine: nouvelleGraine,
    prngDepuisGraine: prngDepuisGraine,
    melanger: melanger,
    sha256Hex: sha256Hex,
    reglesViolées: reglesViolées,
    tirageValide: tirageValide,
    tirageDepuisGraine: tirageDepuisGraine,
    effectuerTirage: effectuerTirage
  };
}

/* =====================================================================
   5. INTERFACE NAVIGATEUR
   ===================================================================== */
if (typeof document !== "undefined" && typeof window !== "undefined" &&
    document.getElementById("btn-tirage")) {
  (function () {

    var $ = function (id) { return document.getElementById(id); };
    var CLE_NOMS = "sect-tirage:noms";
    var CLE_TIRAGE = "sect-tirage:dernier";
    var dernierTirage = null; /* { noms, opts, t, empreinte, horodatageISO } */
    var enCours = false;

    /* ---------- stockage local (tolère le mode privé) ---------- */
    function lireStockage(cle) {
      try { return JSON.parse(localStorage.getItem(cle)); } catch (e) { return null; }
    }
    function ecrireStockage(cle, valeur) {
      try { localStorage.setItem(cle, JSON.stringify(valeur)); } catch (e) { /* ignoré */ }
    }

    function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
    function prefereMouvementReduit() {
      return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    }
    function formaterDate(iso) {
      try {
        return new Intl.DateTimeFormat("fr-FR", { dateStyle: "full", timeStyle: "short" }).format(new Date(iso));
      } catch (e) {
        return new Date(iso).toLocaleString("fr-FR");
      }
    }

    /* ---------- remplissage statique ---------- */
    $("txt-filiere").textContent = CFG.filiere;
    $("txt-filiere-2").textContent = CFG.filiere;
    $("txt-session").textContent = CFG.session;
    $("txt-projet").textContent = CFG.projet;

    /* ---------- étape 1 : liste des étudiants ---------- */
    var conteneurNoms = $("liste-etudiants");
    var nomsSauves = lireStockage(CLE_NOMS) || [];
    for (var i = 0; i < CFG.nbEtudiants; i++) {
      var label = document.createElement("label");
      label.className = "champ-nom";
      var numero = document.createElement("span");
      numero.className = "numero";
      numero.textContent = String(i + 1).padStart(2, "0");
      var champ = document.createElement("input");
      champ.type = "text";
      champ.id = "nom-" + i;
      champ.placeholder = "Étudiant·e " + (i + 1);
      champ.value = (nomsSauves && typeof nomsSauves[i] === "string") ? nomsSauves[i] : "";
      champ.autocomplete = "off";
      champ.spellcheck = false;
      label.appendChild(numero);
      label.appendChild(champ);
      conteneurNoms.appendChild(label);
      champ.addEventListener("input", sauverNoms);
    }
    function lireNomsBruts() {
      var t = [];
      for (var i = 0; i < CFG.nbEtudiants; i++) t.push($("nom-" + i).value.trim());
      return t;
    }
    function lireNoms() {
      return lireNomsBruts().map(function (v, i) {
        return v || ("Étudiant·e " + (i + 1));
      });
    }
    function sauverNoms() { ecrireStockage(CLE_NOMS, lireNomsBruts()); }

    function montreAvertissement(msg) {
      var a = $("avertissement-noms");
      a.textContent = msg;
      a.hidden = false;
    }
    function cacheAvertissement() { $("avertissement-noms").hidden = true; }

    /* ---------- annexe : tableau des règles ---------- */
    (function remplirRegles() {
      var corps = $("corps-regles");
      CFG.incompatibilites.forEach(function (r) {
        var m = CFG.modules.find(function (x) { return x.code === r.module; });
        var c = CFG.contraintes.find(function (x) { return x.code === r.contrainte; });
        var tr = document.createElement("tr");

        var td1 = document.createElement("td");
        td1.textContent = m ? (m.code + " — " + m.titre) : (r.module || "—");
        var td2 = document.createElement("td");
        td2.textContent = c ? (c.code + " — " + c.titre) : (r.contrainte || "—");
        var td3 = document.createElement("td");
        td3.className = "cell-desc";
        td3.textContent = r.raison;

        tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
        corps.appendChild(tr);
      });
    })();

    /* ---------- empreinte SHA-256 du tirage ---------- */
    function empreinteDuTirage(d) {
      var canon = {
        projet: CFG.projet,
        filiere: CFG.filiere,
        session: CFG.session,
        graine: d.t.graine,
        ordreAppelAleatoire: d.opts.melanger,
        etudiants: d.noms, /* ordre de saisie */
        affectations: d.t.ordre.map(function (idx, pos) {
          return {
            etudiant: d.noms[idx],
            module: CFG.modules[d.t.modules[pos]].code,
            contexte: CFG.contextes[d.t.contextes[pos]].code,
            contrainte: CFG.contraintes[d.t.contraintes[pos]].code
          };
        })
      };
      return sha256Hex(JSON.stringify(canon));
    }

    /* ---------- lancement ---------- */
    $("btn-tirage").addEventListener("click", function () {
      if (enCours || dernierTirage) return;

      var noms = lireNoms();
      var doublons = [];
      noms.forEach(function (v, i) { if (noms.indexOf(v) !== i && doublons.indexOf(v) === -1) doublons.push(v); });
      if (doublons.length) {
        montreAvertissement("Noms en double dans la liste : " + doublons.join(", ") + ". Corrigez avant de lancer le tirage.");
        return;
      }
      cacheAvertissement();

      var opts = { melanger: $("opt-melanger").checked, nb: CFG.nbEtudiants };
      var t = effectuerTirage(opts);
      if (!t) {
        montreAvertissement("Aucun tirage valide n'est possible avec les règles actuelles (voir js/data.js).");
        return;
      }
      dernierTirage = { noms: noms, opts: opts, t: t, horodatageISO: new Date().toISOString() };
      dernierTirage.empreinte = empreinteDuTirage(dernierTirage);
      ecrireStockage(CLE_NOMS, lireNomsBruts());
      ecrireStockage(CLE_TIRAGE, dernierTirage);

      var animer = $("opt-animation").checked && !prefereMouvementReduit();
      afficherResultats({ animer: animer, restaure: false });
    });

    /* ---------- affichage des résultats ---------- */
    function ligneVide(pos, nom) {
      var tr = document.createElement("tr");
      var td0 = document.createElement("td"); /* N° */
      td0.className = "mono";
      td0.textContent = String(pos + 1);
      var td1 = document.createElement("td"); /* Étudiant·e */
      td1.className = "cell-nom";
      td1.textContent = nom;
      tr.appendChild(td0);
      tr.appendChild(td1);
      for (var k = 0; k < 3; k++) { /* module, contexte, contrainte */
        var td = document.createElement("td");
        td.textContent = "…";
        tr.appendChild(td);
      }
      return tr;
    }

    function celluleBadge(code, titre, desc) {
      return '<span class="badge" data-code="' + code + '">' + code + '</span>' +
             '<span class="cell-titre">' + titre + '</span>' +
             '<span class="cell-desc">' + desc + '</span>';
    }
    function cellulePuce(code, titre, desc) {
      return '<span class="code-chip">' + code + '</span>' +
             '<span class="cell-titre">' + titre + '</span>' +
             '<span class="cell-desc">' + desc + '</span>';
    }

    function remplirLigne(tr, pos) {
      var d = dernierTirage;
      var idx = d.t.ordre[pos];
      var m = CFG.modules[d.t.modules[pos]];
      var x = CFG.contextes[d.t.contextes[pos]];
      var c = CFG.contraintes[d.t.contraintes[pos]];
      tr.children[1].textContent = d.noms[idx];
      tr.children[2].innerHTML = celluleBadge(m.code, m.titre, m.desc);
      tr.children[3].innerHTML = cellulePuce(x.code, x.titre, x.desc);
      tr.children[4].innerHTML = cellulePuce(c.code, c.titre, c.desc);
      tr.classList.add("deverrouille");
    }

    /* Effet « roulette » sur la colonne module avant de figer la ligne. */
    function scintillement(tr) {
      var cible = tr.children[2];
      var debut = Date.now();
      return new Promise(function (fin) {
        var minuteur = setInterval(function () {
          if (Date.now() - debut >= 520) {
            clearInterval(minuteur);
            fin();
            return;
          }
          var m = CFG.modules[Math.floor(Math.random() * CFG.modules.length)];
          cible.innerHTML = '<span class="badge incertain">' + m.code + '</span>';
        }, 62);
      });
    }

    function afficherResultats(options) {
      var anim = options && options.animer;
      var d = dernierTirage;
      enCours = true;
      $("btn-tirage").disabled = true;
      desactiverActions();

      var section = $("section-resultats");
      section.hidden = false;
      $("trace").hidden = true;
      var corps = $("corps-tirage");
      corps.textContent = "";

      $("horodatage").textContent = "Tirage effectué le " + formaterDate(d.horodatageISO) +
        (options && options.restaure ? " — dernier tirage restauré depuis ce navigateur" : "");

      if (!options || !options.restaure) {
        section.scrollIntoView({ behavior: anim ? "smooth" : "auto", block: "start" });
      }

      var positions = [];
      for (var p = 0; p < d.t.ordre.length; p++) positions.push(p);

      return positions.reduce(function (chaine, pos) {
        return chaine.then(function () {
          var tr = ligneVide(pos, d.noms[d.t.ordre[pos]]);
          corps.appendChild(tr);
          var etape = Promise.resolve();
          if (anim) {
            tr.classList.add("reveal");
            etape = scintillement(tr);
          }
          return etape.then(function () {
            remplirLigne(tr, pos);
            return anim ? sleep(420) : Promise.resolve();
          });
        });
      }, Promise.resolve()).then(function () {
        remplirTrace();
        activerActions();
        enCours = false;
      });
    }

    function remplirTrace() {
      var d = dernierTirage;
      var trace = $("trace");
      trace.hidden = false;
      trace.textContent = "";

      var ligneTitre = document.createElement("div");
      ligneTitre.className = "ligne";
      var fort = document.createElement("strong");
      fort.textContent = "Traçabilité du tirage";
      ligneTitre.appendChild(fort);
      trace.appendChild(ligneTitre);

      var lignes = [
        ["Projet", CFG.projet + " — " + CFG.filiere],
        ["Session", CFG.session],
        ["Horodatage", formaterDate(d.horodatageISO)],
        ["Ordre d'appel aléatoire", d.opts.melanger ? "oui" : "non"],
        ["Graine (128 bits)", d.t.graine],
        ["Empreinte SHA-256", d.empreinte]
      ];
      lignes.forEach(function (paire) {
        var l = document.createElement("div");
        l.className = "ligne";
        var c = document.createElement("span");
        c.className = "cle";
        c.textContent = paire[0] + " :";
        var v = document.createElement("span");
        v.className = "valeur";
        v.textContent = paire[1];
        l.appendChild(c); l.appendChild(v);
        trace.appendChild(l);
      });

      var note = document.createElement("div");
      note.className = "note";
      note.textContent = "Tirage rejouable à l'identique avec cette graine et le code du dépôt (node tools/rejouer.js). Toute modification du résultat romprait l'empreinte.";
      trace.appendChild(note);
    }

    function activerActions() {
      ["btn-csv", "btn-print", "btn-copy", "btn-relancer"].forEach(function (id) { $(id).disabled = false; });
      $("btn-tirage").disabled = true;
    }
    function desactiverActions() {
      ["btn-csv", "btn-print", "btn-copy", "btn-relancer"].forEach(function (id) { $(id).disabled = true; });
    }

    /* ---------- exports ---------- */
    function escCSV(v) {
      v = String(v);
      return /[;"\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
    }

    $("btn-csv").addEventListener("click", function () {
      var d = dernierTirage;
      if (!d) return;
      var L = [];
      L.push(["N°", "Étudiant", "Code module", "Module", "Code contexte", "Contexte", "Code contrainte", "Contrainte"].map(escCSV).join(";"));
      d.t.ordre.forEach(function (idx, pos) {
        var m = CFG.modules[d.t.modules[pos]];
        var x = CFG.contextes[d.t.contextes[pos]];
        var c = CFG.contraintes[d.t.contraintes[pos]];
        L.push([pos + 1, d.noms[idx], m.code, m.titre, x.code, x.titre, c.code, c.titre].map(escCSV).join(";"));
      });
      L.push("");
      L.push("Traçabilité");
      L.push(["Graine (128 bits)", d.t.graine].map(escCSV).join(";"));
      L.push(["Empreinte SHA-256", d.empreinte].map(escCSV).join(";"));
      L.push(["Horodatage (ISO 8601)", d.horodatageISO].map(escCSV).join(";"));
      L.push(["Ordre d'appel aléatoire", d.opts.melanger ? "oui" : "non"].map(escCSV).join(";"));
      L.push(["Projet", CFG.projet].map(escCSV).join(";"));
      L.push(["Filière", CFG.filiere].map(escCSV).join(";"));
      L.push(["Session", CFG.session].map(escCSV).join(";"));

      var blob = new Blob(["\ufeff" + L.join("\r\n")], { type: "text/csv;charset=utf-8" });
      var lien = document.createElement("a");
      lien.href = URL.createObjectURL(blob);
      lien.download = "tirage-" + d.horodatageISO.slice(0, 10) + "-un-serveur-une-mission.csv";
      document.body.appendChild(lien);
      lien.click();
      lien.remove();
      setTimeout(function () { URL.revokeObjectURL(lien.href); }, 4000);
    });

    function construireRecap() {
      var d = dernierTirage;
      var lignes = [];
      lignes.push("TIRAGE — « " + CFG.projet + " »");
      lignes.push(CFG.filiere + " — Session " + CFG.session);
      lignes.push("Date : " + formaterDate(d.horodatageISO));
      lignes.push("");
      d.t.ordre.forEach(function (idx, pos) {
        var m = CFG.modules[d.t.modules[pos]];
        var x = CFG.contextes[d.t.contextes[pos]];
        var c = CFG.contraintes[d.t.contraintes[pos]];
        lignes.push((pos + 1) + ". " + d.noms[idx] + " — " + m.code + " " + m.titre +
                    " | " + x.titre + " | " + c.titre);
      });
      lignes.push("");
      lignes.push("Graine : " + d.t.graine);
      lignes.push("Empreinte SHA-256 : " + d.empreinte);
      return lignes.join("\n");
    }

    $("btn-copy").addEventListener("click", function () {
      var d = dernierTirage;
      if (!d) return;
      var texte = construireRecap();
      function retour() {
        $("lbl-copy").textContent = "Copié !";
        setTimeout(function () { $("lbl-copy").textContent = "Copier le récapitulatif"; }, 1800);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(texte).then(retour, function () { copieSecours(texte); retour(); });
      } else {
        copieSecours(texte);
        retour();
      }
    });
    function copieSecours(texte) {
      var ta = document.createElement("textarea");
      ta.value = texte;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (e) { /* ignoré */ }
      ta.remove();
    }

    $("btn-print").addEventListener("click", function () { window.print(); });

    $("btn-relancer").addEventListener("click", function () {
      if (!dernierTirage) return;
      var ok = window.confirm(
        "Un tirage a déjà été enregistré (" + formaterDate(dernierTirage.horodatageISO) + ").\n" +
        "En refaire un autre effacera cette trace dans ce navigateur.\nContinuer ?"
      );
      if (!ok) return;
      try { localStorage.removeItem(CLE_TIRAGE); } catch (e) { /* ignoré */ }
      dernierTirage = null;
      $("section-resultats").hidden = true;
      $("corps-tirage").textContent = "";
      $("trace").textContent = "";
      $("trace").hidden = true;
      $("horodatage").textContent = "";
      desactiverActions();
      $("btn-tirage").disabled = false;
      window.scrollTo({ top: 0, behavior: "smooth" });
    });

    /* ---------- restauration du dernier tirage ---------- */
    (function restaurer() {
      var sauve = lireStockage(CLE_TIRAGE);
      if (sauve && sauve.t && sauve.t.ordre && sauve.noms) {
        dernierTirage = sauve;
        afficherResultats({ animer: false, restaure: true });
      }
    })();

  })();
}
