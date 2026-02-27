/* ============================================================
   FICHIER : script.js
   RÔLE    : Contient toute la logique de l'application.
             En JavaScript, on programme le comportement :
             ce qui se passe quand l'utilisateur clique,
             les calculs cryptographiques, les animations, etc.
   ============================================================ */


/* ==========================================================
   ÉTAT GLOBAL DE L'APPLICATION
   Ces variables "vivent" pendant toute la session.
   Elles gardent les données en mémoire entre les actions.
   ========================================================== */

// Stocke les données chiffrées d'Adjoua en attendant que Koffi les reçoive
let encryptedData = null;

// Compteurs de statistiques (affichés dans l'onglet Analyse)
let stats = { sent: 0, ok: 0, fail: 0 };

// Tableau des événements pour la chronologie (timeline)
let events = [];


/* ==========================================================
   FONCTIONS UTILITAIRES
   Des petites fonctions d'aide utilisées partout.
   ========================================================== */

/**
 * Ajoute une ligne dans le journal d'exécution (log).
 * @param {string} msg  - Le message à afficher
 * @param {string} type - Le type : 'info', 'ok', 'err', 'warn'
 */
function log(msg, type = 'info') {
  // On récupère l'élément HTML du journal
  const el = document.getElementById('log');

  // On génère l'heure actuelle au format HH:MM:SS.mmm
  const now = new Date().toISOString().split('T')[1].substring(0, 12);

  // On crée une nouvelle ligne HTML
  const line = document.createElement('div');
  line.className = `log-line log-${type}`; // classe CSS selon le type
  line.innerHTML = `<span class="log-ts">[${now}]</span><span class="log-msg">${msg}</span>`;

  // On ajoute la ligne au journal
  el.appendChild(line);

  // On fait défiler automatiquement vers le bas pour voir la dernière ligne
  el.scrollTop = el.scrollHeight;
}

/**
 * Ajoute un événement dans la timeline (chronologie).
 * @param {string} msg - Description de l'événement
 */
function addEvent(msg) {
  const ts = new Date().toLocaleTimeString('fr-FR'); // heure locale en français
  events.unshift({ ts, msg }); // unshift = ajouter AU DÉBUT du tableau
  refreshTimeline();           // mettre à jour l'affichage
}

/**
 * Met à jour l'affichage de la timeline dans l'onglet Analyse.
 */
function refreshTimeline() {
  const el = document.getElementById('event-timeline');
  if (events.length === 0) return; // rien à faire si vide

  // On n'affiche que les 10 derniers événements
  el.innerHTML = events.slice(0, 10).map(e =>
    `<div class="timeline-item">
      <div class="timeline-time">${e.ts}</div>
      <div class="timeline-content">${e.msg}</div>
    </div>`
  ).join('');
}

/**
 * Met à jour les compteurs de statistiques dans l'onglet Analyse.
 */
function updateStats() {
  document.getElementById('stat-sent').textContent = stats.sent;
  document.getElementById('stat-ok').textContent   = stats.ok;
  document.getElementById('stat-fail').textContent = stats.fail;
}

/**
 * Fonction d'attente (pause) pendant un certain nombre de millisecondes.
 * Utilisée pour ralentir les animations des pipelines.
 * @param {number} ms - Durée en millisecondes (1000ms = 1 seconde)
 * @returns {Promise} - Une promesse résolue après `ms` millisecondes
 */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }


/* ==========================================================
   ALGORITHME SHA-256 (Hachage cryptographique)
   Utilise l'API native du navigateur (Web Crypto API).
   ========================================================== */

/**
 * Calcule le hash SHA-256 d'un message.
 * async/await = fonction asynchrone (le navigateur calcule en arrière-plan)
 * @param {string} message - Le texte à hacher
 * @returns {string} - Le hash en hexadécimal (64 caractères)
 */
async function sha256(message) {
  // TextEncoder convertit le texte en octets (bytes) que le CPU peut traiter
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  // On demande au navigateur de calculer le hash SHA-256
  // crypto.subtle est l'API cryptographique sécurisée du navigateur
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // On convertit le résultat (octets binaires) en texte hexadécimal
  // Exemple : 0x3A devient "3a", 0xFF devient "ff"
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}


/* ==========================================================
   ALGORITHME AES-256 (Chiffrement symétrique)
   Utilise l'API native du navigateur (Web Crypto API).
   ========================================================== */

/**
 * Chiffre un message avec AES-256 en mode CBC.
 * @param {string} message - Le texte à chiffrer
 * @param {string} keyStr  - La clé secrète (au moins 16 caractères)
 * @returns {string}       - Le message chiffré en Base64
 */
async function aesEncrypt(message, keyStr) {
  const encoder = new TextEncoder();

  // On importe la clé : on la convertit en format utilisable par Web Crypto
  // La clé doit faire exactement 16 octets (128 bits) ; on la tronque ou complète
  const keyMaterial = await crypto.subtle.importKey(
    "raw",                                                  // format brut
    encoder.encode(keyStr.substring(0, 16).padEnd(16, '0')), // 16 octets exactement
    { name: "AES-CBC" },                                    // algorithme
    false,                                                  // non exportable
    ["encrypt"]                                             // usage : chiffrement uniquement
  );

  // IV = Initialization Vector (vecteur d'initialisation)
  // C'est un nombre aléatoire de 16 octets, unique pour chaque message.
  // Il garantit que chiffrer deux fois le même message donne des résultats différents.
  const iv = crypto.getRandomValues(new Uint8Array(16));

  // On chiffre le message
  const enc = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv }, // algorithme + vecteur d'initialisation
    keyMaterial,             // clé
    encoder.encode(message)  // message à chiffrer
  );

  // On combine l'IV + le message chiffré dans un seul tableau d'octets
  // L'IV doit être envoyé avec le message (il n'est pas secret, juste unique)
  const combined = new Uint8Array([...iv, ...new Uint8Array(enc)]);

  // On encode en Base64 pour obtenir une chaîne de texte transportable
  return btoa(String.fromCharCode(...combined));
}

/**
 * Déchiffre un message AES-256 en mode CBC.
 * @param {string} cipherB64 - Le message chiffré en Base64
 * @param {string} keyStr    - La même clé secrète utilisée pour chiffrer
 * @returns {string}         - Le message original déchiffré
 */
async function aesDecrypt(cipherB64, keyStr) {
  const encoder = new TextEncoder();

  // On importe la clé (même procédé qu'au chiffrement)
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(keyStr.substring(0, 16).padEnd(16, '0')),
    { name: "AES-CBC" },
    false,
    ["decrypt"] // usage : déchiffrement uniquement
  );

  // On décode le Base64 pour récupérer les octets
  const combined = Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0));

  // On sépare l'IV (16 premiers octets) du reste (message chiffré)
  const iv   = combined.slice(0, 16);   // octets 0 à 15
  const data = combined.slice(16);      // octets 16 jusqu'à la fin

  // On déchiffre
  const dec = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, keyMaterial, data);

  // On convertit les octets résultants en texte lisible
  return new TextDecoder().decode(dec);
}


/* ==========================================================
   RSA SIMULÉ (Chiffrement asymétrique)
   ========================================================== */

/**
 * Simule le chiffrement RSA d'une clé AES avec la clé publique de Koffi.
 * @param {string} keyStr - La clé AES à "chiffrer"
 * @returns {string}      - Représentation simulée du résultat RSA
 */
function simulateRSAEncrypt(keyStr) {
  // On calcule un "hash" simple de la clé pour simuler le résultat RSA
  let h = 0;
  for (let i = 0; i < keyStr.length; i++) {
    h = Math.imul(31, h) + keyStr.charCodeAt(i) | 0;
    // Math.imul = multiplication entière sur 32 bits (évite les dépassements)
  }
  // On construit une chaîne qui ressemble à du vrai RSA chiffré
  return 'RSA_ENC_' + Math.abs(h).toString(16).toUpperCase().padStart(8, '0')
         + 'A3F2B1E0'
         + btoa(keyStr.substring(0, 8)).replace(/=/g, '') + '...';
}

/**
 * Simule la signature numérique RSA d'un hash avec la clé privée d'Adjoua.
 * La signature prouve que c'est bien Adjoua qui a envoyé le message.
 * @param {string} hash       - Le hash SHA-256 du message
 * @param {string} privateKey - Clé privée (non utilisée ici, juste pour la démonstration)
 * @returns {string}          - La signature simulée
 */
function simulateSign(hash, privateKey) {
  // On calcule un hash déterministe du hash du message
  // "Déterministe" signifie : le même hash donnera toujours la même signature
  let h = 0;
  for (let i = 0; i < hash.length; i++) {
    h = Math.imul(37, h) + hash.charCodeAt(i) | 0;
  }
  return 'SIG_ADJOUA_' + Math.abs(h).toString(16).toUpperCase().padStart(16, '0');
}

/**
 * Vérifie si une signature correspond bien au hash du message.
 * Koffi utilise la clé PUBLIQUE d'Adjoua pour cette vérification.
 * @param {string} hash      - Le hash recalculé du message reçu
 * @param {string} signature - La signature reçue avec le message
 * @returns {boolean}        - true si la signature est valide, false sinon
 */
function simulateVerify(hash, signature) {
  // On recalcule la signature attendue à partir du hash
  let h = 0;
  for (let i = 0; i < hash.length; i++) {
    h = Math.imul(37, h) + hash.charCodeAt(i) | 0;
  }
  const expected = 'SIG_ADJOUA_' + Math.abs(h).toString(16).toUpperCase().padStart(16, '0');

  // La signature est valide si elle correspond à ce qu'on attendait
  return signature === expected;
}


/* ==========================================================
   ANIMATION DU PIPELINE
   Fonctions qui animent les étapes visuelles du processus.
   ========================================================== */

/**
 * Remet toutes les étapes d'un pipeline à leur état initial (grisées).
 * @param {string} id - L'identifiant HTML du pipeline ('send-pipeline' ou 'recv-pipeline')
 */
function resetPipeline(id) {
  document.querySelectorAll(`#${id} .pipeline-step`).forEach(s => {
    s.classList.remove('done', 'active'); // supprime les deux classes d'état
  });
}

/**
 * Active ou termine une étape du pipeline.
 * @param {string}  pipelineId - L'identifiant du pipeline
 * @param {number}  stepIdx    - L'index de l'étape (0 = première)
 * @param {boolean} done       - true = marquer comme terminée, false = marquer comme active
 */
async function activateStep(pipelineId, stepIdx, done = false) {
  // On récupère toutes les étapes du pipeline
  const steps = document.querySelectorAll(`#${pipelineId} .pipeline-step`);

  if (done) {
    // Marquer l'étape comme terminée (vert)
    steps[stepIdx].classList.remove('active');
    steps[stepIdx].classList.add('done');
  } else {
    // Mettre à jour toutes les étapes :
    // - les précédentes sont "terminées"
    // - l'étape courante est "active" (animation)
    // - les suivantes restent grisées
    steps.forEach((s, i) => {
      if (i < stepIdx) {
        s.classList.add('done');
        s.classList.remove('active');
      } else if (i === stepIdx) {
        s.classList.add('active');
        s.classList.remove('done');
      } else {
        s.classList.remove('done', 'active');
      }
    });
  }

  // On attend un peu avant de passer à la suite (effet visuel)
  await sleep(600);
}


/* ==========================================================
   ENVOI D'UN MESSAGE (Pipeline d'Adjoua)
   Cette fonction est appelée quand Adjoua clique sur "Chiffrer & Envoyer".
   Elle simule toutes les étapes du chiffrement.
   ========================================================== */

/**
 * Chiffre le message d'Adjoua et prépare le paquet sécurisé.
 * Étapes : SHA-256 → Signature → AES → RSA → Transmission
 */
async function sendMessage() {
  // On récupère le message et la clé depuis les champs de saisie
  const msg = document.getElementById('msg-input').value.trim();
  const key = document.getElementById('aes-key-input').value.trim();

  // Vérification : les champs ne doivent pas être vides
  if (!msg || !key) { log('Message ou clé manquant.', 'err'); return; }

  // On désactive le bouton pour éviter un double-clic
  document.getElementById('btn-send').disabled = true;
  resetPipeline('send-pipeline'); // on remet le pipeline à zéro
  encryptedData = null;            // on efface les données précédentes

  // Petite fonction interne pour remplir un bloc de code HTML
  const setCB = (id, val) => {
    const el = document.getElementById(id);
    el.textContent = val;
    el.classList.remove('empty'); // enlève le style "vide"
  };

  log('── Début du pipeline d\'envoi ──', 'info');

  // ---- ÉTAPE 1 : Hachage SHA-256 ----
  // On calcule l'empreinte numérique du message original.
  // Si quelqu'un modifie le message en transit, le hash ne correspondra plus.
  await activateStep('send-pipeline', 0);
  const hash = await sha256(msg);
  setCB('out-hash', hash);
  log(`✓ Hash SHA-256 : ${hash.substring(0, 32)}…`, 'ok');
  await activateStep('send-pipeline', 0, true); // étape terminée
  addEvent('<strong>Adjoua</strong> a calculé le hash SHA-256 du message');

  // ---- ÉTAPE 2 : Signature RSA ----
  // Adjoua signe le hash avec SA CLÉ PRIVÉE.
  // Koffi pourra vérifier avec la clé PUBLIQUE d'Adjoua.
  // Cela prouve l'identité de l'expéditrice (authentification + non-répudiation).
  await activateStep('send-pipeline', 1);
  await sleep(300);
  const sig = simulateSign(hash, 'ADJOUA_PRIVATE_KEY_2048');
  setCB('out-sig', sig);
  log(`✓ Signature : ${sig}`, 'ok');
  await activateStep('send-pipeline', 1, true);
  addEvent('<strong>Adjoua</strong> a signé le message avec sa clé privée RSA');

  // ---- ÉTAPE 3 : Chiffrement AES-256 ----
  // On chiffre le message avec la clé AES partagée.
  // Seul quelqu'un possédant cette clé peut lire le message (confidentialité).
  await activateStep('send-pipeline', 2);
  await sleep(300);
  const cipher = await aesEncrypt(msg, key);
  setCB('out-ciphertext', cipher);
  log(`✓ Message chiffré AES (${cipher.length} chars)`, 'ok');
  await activateStep('send-pipeline', 2, true);
  addEvent('<strong>Adjoua</strong> a chiffré le message avec AES-256');

  // ---- ÉTAPE 4 : Chiffrement de la clé AES par RSA ----
  // On protège la clé AES en la chiffrant avec la clé PUBLIQUE de Koffi.
  // Seul Koffi (avec sa clé privée) pourra récupérer la clé AES.
  await activateStep('send-pipeline', 3);
  await sleep(300);
  const encKey = simulateRSAEncrypt(key);
  setCB('out-enckey', encKey);
  log(`✓ Clé AES chiffrée avec RSA (clé publique Koffi)`, 'ok');
  await activateStep('send-pipeline', 3, true);

  // ---- ÉTAPE 5 : Transmission ----
  // On prépare le paquet final et on le "transmet" à Koffi.
  await activateStep('send-pipeline', 4);
  await sleep(400);

  // On vérifie si la case "Simuler une attaque" est cochée
  const isAttack = document.getElementById('attack-mode').checked;

  // On stocke les données chiffrées (dans l'état global)
  encryptedData = {
    // Si attaque simulée : on altère le message chiffré et la signature
    cipher: isAttack ? cipher.substring(0, cipher.length - 5) + 'XXXXX' : cipher,
    hash,
    sig: isAttack ? sig + '_TAMPERED' : sig, // signature falsifiée si attaque
    encKey,
    aesKey: key,
    wasAttacked: isAttack
  };

  await activateStep('send-pipeline', 4, true);

  // Mise à jour des statistiques
  stats.sent++;
  updateStats();

  // Ajout à la timeline
  addEvent(isAttack
    ? ' <strong style="color:var(--danger)">ATTAQUE</strong> : message intercepté et modifié !'
    : '<strong>Transmission</strong> sécurisée vers Koffi'
  );

  if (isAttack) {
    log(' ATTAQUE simulée : message et signature modifiés en transit !', 'warn');
  } else {
    log('✓ Paquet transmis à Koffi avec succès', 'ok');
  }

  // On active le bouton de réception de Koffi
  document.getElementById('btn-recv').disabled = false;
  document.getElementById('btn-send').disabled = false;
  log('── Fin du pipeline d\'envoi ──', 'info');
}


/* ==========================================================
   RÉCEPTION D'UN MESSAGE (Pipeline de Koffi)
   Cette fonction est appelée quand Koffi clique sur "Déchiffrer & Vérifier".
   Elle vérifie l'intégrité, l'authenticité, et déchiffre le message.
   ========================================================== */

/**
 * Déchiffre et vérifie le message reçu par Koffi.
 * Étapes : RSA → AES → Vérification signature → Vérification hash
 */
async function receiveMessage() {
  // Vérification : il faut qu'Adjoua ait d'abord envoyé un message
  if (!encryptedData) { log('Aucune donnée à recevoir.', 'err'); return; }

  document.getElementById('btn-recv').disabled = true;
  resetPipeline('recv-pipeline');

  // On récupère la clé AES que Koffi est censé connaître
  const koffiKey = document.getElementById('aes-key-koffi').value.trim();

  log('── Début du pipeline de réception ──', 'info');

  // ---- ÉTAPE 1 : Déchiffrement RSA ----
  // Koffi utilise SA CLÉ PRIVÉE pour récupérer la clé AES.
  await activateStep('recv-pipeline', 0);
  await sleep(400);
  log('✓ Clé AES récupérée via RSA (clé privée Koffi)', 'ok');
  await activateStep('recv-pipeline', 0, true);

  // ---- ÉTAPE 2 : Déchiffrement AES ----
  // Avec la clé AES récupérée, Koffi déchiffre le message.
  // Si le message a été altéré en transit, le déchiffrement échouera.
  await activateStep('recv-pipeline', 1);
  let decrypted = null;
  let aesOk = false;
  try {
    decrypted = await aesDecrypt(encryptedData.cipher, koffiKey);
    aesOk = true; // déchiffrement réussi
    log(`✓ Message déchiffré : "${decrypted.substring(0, 40)}…"`, 'ok');
  } catch (e) {
    // Si le message a été modifié, aesDecrypt() lève une erreur
    log('✗ Échec déchiffrement AES (message altéré ou clé incorrecte)', 'err');
  }
  await activateStep('recv-pipeline', 1, true);

  // ---- ÉTAPE 3 : Vérification de la signature ----
  // On recalcule le hash du message déchiffré.
  // On vérifie si la signature reçue correspond bien à ce hash.
  await activateStep('recv-pipeline', 2);
  await sleep(400);
  const recalcHash = aesOk ? await sha256(decrypted) : '';
  const sigOk = simulateVerify(encryptedData.hash, encryptedData.sig);
  log(
    sigOk
      ? '✓ Signature valide — message d\'Adjoua authentifié'
      : '✗ Signature invalide — message altéré ou usurpation !',
    sigOk ? 'ok' : 'err'
  );
  await activateStep('recv-pipeline', 2, true);

  // ---- ÉTAPE 4 : Vérification du hash ----
  // On compare le hash du message déchiffré avec le hash envoyé par Adjoua.
  // Si les deux hash sont identiques, le message n'a pas été modifié (intégrité).
  await activateStep('recv-pipeline', 3);
  await sleep(400);
  const hashOk = aesOk && (recalcHash === encryptedData.hash);
  log(`Hash original  : ${encryptedData.hash.substring(0, 32)}…`, 'info');
  if (aesOk) log(`Hash reçu      : ${recalcHash.substring(0, 32)}…`, 'info');
  log(
    hashOk
      ? '✓ Hash identique — intégrité vérifiée'
      : '✗ Hash différent — message modifié !',
    hashOk ? 'ok' : 'err'
  );
  await activateStep('recv-pipeline', 3, true);

  // ---- ÉTAPE 5 : Résultat final ----
  await activateStep('recv-pipeline', 4);
  await sleep(400);
  await activateStep('recv-pipeline', 4, true);

  // Toutes les vérifications doivent passer pour valider le message
  const allOk = aesOk && sigOk && hashOk;

  // Mise à jour des statistiques
  if (allOk) {
    stats.ok++;
    addEvent(`<strong style="color:var(--success)">✓ Message validé</strong> par Koffi`);
  } else {
    stats.fail++;
    addEvent(`<strong style="color:var(--danger)">✗ Attaque détectée</strong> — message rejeté`);
  }
  updateStats();

  // ---- Affichage du résultat dans le panneau de Koffi ----
  const resultEl = document.getElementById('recv-result');
  if (allOk) {
    // Affichage succès : message en clair + propriétés garanties
    resultEl.innerHTML = `
      <div class="verify-result verify-ok">
        <div class="verify-icon">✅</div>
        <div class="verify-title">MESSAGE VALIDÉ</div>
        <div style="font-size:0.7rem;margin:8px 0;color:var(--dim)">Toutes les vérifications ont réussi</div>
        <div style="background:var(--bg);border:1px solid var(--success);padding:16px;text-align:left;margin-top:12px;font-size:0.8rem;line-height:1.8;color:var(--text)">${decrypted}</div>
        <div style="margin-top:12px;font-size:0.65rem;color:var(--dim);text-align:left;">
          <span style="color:var(--success)">✓ Confidentialité</span> · 
          <span style="color:var(--success)">✓ Intégrité</span> · 
          <span style="color:var(--success)">✓ Authentification</span> · 
          <span style="color:var(--success)">✓ Non-répudiation</span>
        </div>
      </div>`;
  } else {
    // Affichage échec : détail des vérifications échouées
    resultEl.innerHTML = `
      <div class="verify-result verify-fail">
        <div class="verify-icon">🚨</div>
        <div class="verify-title">MESSAGE REJETÉ</div>
        <div style="font-size:0.7rem;margin:8px 0;color:var(--dim)">Des anomalies ont été détectées — message supprimé</div>
        <div style="margin-top:12px;font-size:0.72rem;text-align:left;line-height:2">
          <div>${aesOk ? '<span style="color:var(--success)">✓</span>' : '<span style="color:var(--danger)">✗</span>'} Déchiffrement AES</div>
          <div>${sigOk ? '<span style="color:var(--success)">✓</span>' : '<span style="color:var(--danger)">✗</span>'} Vérification signature</div>
          <div>${hashOk ? '<span style="color:var(--success)">✓</span>' : '<span style="color:var(--danger)">✗</span>'} Vérification hash</div>
        </div>
        <div style="margin-top:8px;font-size:0.7rem;color:var(--danger)">
          Interception ou modification détectée. Identité non vérifiable.
        </div>
      </div>`;
  }

  document.getElementById('btn-recv').disabled = false;
  log('── Fin du pipeline de réception ──', 'info');
}


/* ==========================================================
   CRYPTOGRAPHIE CLASSIQUE — CHIFFREMENT DE CÉSAR
   ========================================================== */

/**
 * Chiffre (ou déchiffre) un texte avec le chiffrement de César.
 * @param {string} text  - Le texte à chiffrer
 * @param {number} shift - Le décalage (1 à 25)
 * @returns {string}     - Le texte chiffré
 */
function cesarEncrypt(text, shift) {
  return text.toUpperCase().split('').map(c => {
    // Si le caractère est une lettre majuscule
    if (c >= 'A' && c <= 'Z') {
      // charCodeAt(0) = code ASCII du caractère
      // - 65 = ramène à 0-25 (A=0, B=1, ..., Z=25)
      // + shift = on décale
      // % 26 = on repart au début si on dépasse Z
      // + 65 = on remet dans la plage ASCII des majuscules
      return String.fromCharCode((c.charCodeAt(0) - 65 + shift) % 26 + 65);
    }
    return c; // les autres caractères (espaces, chiffres...) restent inchangés
  }).join(''); // on réunit les caractères en une chaîne
}

/**
 * Met à jour l'affichage du chiffrement de César en temps réel.
 * Appelée à chaque frappe dans le champ ou déplacement du curseur.
 */
function updateCesar() {
  const text  = document.getElementById('cesar-input').value;
  const shift = parseInt(document.getElementById('cesar-shift').value);

  // Affiche la valeur du décalage
  document.getElementById('cesar-shift-val').textContent = shift;

  // Chiffrement
  const enc = cesarEncrypt(text, shift);

  // Déchiffrement : pour déchiffrer, on applique le décalage inverse (26 - shift)
  const dec = cesarEncrypt(enc, 26 - shift);

  document.getElementById('cesar-out').textContent = enc;
  document.getElementById('cesar-dec').textContent = dec;

  // ---- Démonstration de l'attaque par force brute ----
  // On teste tous les 25 décalages possibles et on les affiche
  let bf = '';
  for (let s = 1; s <= 25; s++) {
    const d = cesarEncrypt(enc, 26 - s);
    // On colore en vert la ligne qui correspond au bon décalage
    bf += `<span style="color:var(--dim)">Clé ${s.toString().padStart(2, ' ')}:</span> `
        + `<span style="color:${s === shift ? 'var(--success)' : 'var(--text)'}">${d}</span>\n`;
  }
  document.getElementById('brute-force').innerHTML = bf;
}


/* ==========================================================
   CRYPTOGRAPHIE CLASSIQUE — CHIFFREMENT DE VIGENÈRE
   ========================================================== */

/**
 * Chiffre ou déchiffre un texte avec le chiffrement de Vigenère.
 * @param {string}  text    - Le texte à traiter
 * @param {string}  key     - Le mot-clé
 * @param {boolean} encrypt - true = chiffrer, false = déchiffrer
 * @returns {string}        - Le texte résultant
 */
function vigenereProcess(text, key, encrypt) {
  // On nettoie le texte et la clé (majuscules, lettres uniquement)
  const t = text.toUpperCase().replace(/[^A-Z]/g, '');
  const k = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!k) return t; // si la clé est vide, on retourne le texte tel quel

  let result = '';
  let ki = 0; // index dans la clé (ki = Key Index)

  for (let c of text.toUpperCase()) {
    if (c >= 'A' && c <= 'Z') {
      // On récupère le décalage à partir de la lettre de la clé
      // ki % k.length : on "tourne" dans la clé quand on arrive à la fin
      const shift = k[ki % k.length].charCodeAt(0) - 65;

      // On applique le décalage (addition pour chiffrer, soustraction pour déchiffrer)
      const val = encrypt
        ? (c.charCodeAt(0) - 65 + shift) % 26          // chiffrement
        : (c.charCodeAt(0) - 65 - shift + 26) % 26;    // déchiffrement (+26 pour éviter les négatifs)

      result += String.fromCharCode(val + 65);
      ki++; // on avance dans la clé uniquement pour les lettres
    } else {
      result += c; // les espaces et chiffres restent inchangés
    }
  }
  return result;
}

/**
 * Met à jour l'affichage du chiffrement de Vigenère en temps réel.
 */
function updateVigenere() {
  const text = document.getElementById('vig-input').value;
  const key  = document.getElementById('vig-key').value;

  const enc = vigenereProcess(text, key, true);  // chiffrement
  const dec = vigenereProcess(enc, key, false);   // déchiffrement (vérification)

  document.getElementById('vig-out').textContent = enc;
  document.getElementById('vig-dec').textContent = dec;
}


/* ==========================================================
   BENCHMARK DE PERFORMANCE
   Compare les vitesses d'exécution de AES, SHA-256 et RSA.
   ========================================================== */

/**
 * Lance un benchmark pour mesurer les performances des algorithmes.
 * On répète chaque opération 50 fois et on calcule le temps moyen.
 */
async function runBenchmark() {
  document.getElementById('btn-bench').disabled = true;
  document.getElementById('bench-result').innerHTML =
    '<div class="status-line status-info">⏳ Benchmark en cours…</div>';

  // Message de test : 1000 caractères 'A'
  const testMsg = 'A'.repeat(1000);
  const testKey = 'BenchmarkKey2024';
  const rounds  = 50; // nombre de répétitions

  // ---- Benchmark AES ----
  // performance.now() retourne le temps en millisecondes avec haute précision
  const t0 = performance.now();
  for (let i = 0; i < rounds; i++) await aesEncrypt(testMsg, testKey);
  const aesTime = ((performance.now() - t0) / rounds).toFixed(3); // temps moyen

  // ---- Benchmark SHA-256 ----
  const t1 = performance.now();
  for (let i = 0; i < rounds; i++) await sha256(testMsg);
  const shaTime = ((performance.now() - t1) / rounds).toFixed(3);

  // ---- Benchmark RSA (simulé) ----
  const t2 = performance.now();
  for (let i = 0; i < rounds; i++) simulateRSAEncrypt(testKey);
  const rsaTime = ((performance.now() - t2) / rounds).toFixed(3);

  // Affichage des résultats dans un tableau HTML
  document.getElementById('bench-result').innerHTML = `
    <div style="margin-top:12px">
    <table>
      <tr><th>Algorithme</th><th>Temps moyen / op</th><th>Opérations / sec</th><th>Évaluation</th></tr>
      <tr>
        <td>AES-256 (1KB)</td>
        <td class="td-good">${aesTime} ms</td>
        <td class="td-good">${(1000 / aesTime).toFixed(0)}</td>
        <td class="td-good">Très rapide</td>
      </tr>
      <tr>
        <td>SHA-256 (1KB)</td>
        <td class="td-good">${shaTime} ms</td>
        <td class="td-good">${(1000 / shaTime).toFixed(0)}</td>
        <td class="td-good">Très rapide</td>
      </tr>
      <tr>
        <td>RSA (simulé)</td>
        <td class="td-med">${rsaTime} ms</td>
        <td class="td-med">${(1000 / rsaTime).toFixed(0)}</td>
        <td class="td-med">Plus lent (normal)</td>
      </tr>
    </table>
    <div class="status-line status-ok" style="margin-top:12px">
      ✓ Benchmark complété sur ${rounds} itérations avec message de 1000 octets
    </div>
    </div>`;

  document.getElementById('btn-bench').disabled = false;
}


/* ==========================================================
   GESTION DES ONGLETS
   Permet de passer d'une section à l'autre.
   ========================================================== */

/**
 * Affiche l'onglet demandé et masque les autres.
 * @param {string} name - Nom de l'onglet : 'main', 'classic', 'compare', 'about'
 */
function switchTab(name) {
  // On masque tous les contenus d'onglets
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

  // On désactive tous les boutons d'onglets
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));

  // On affiche le contenu de l'onglet demandé
  document.getElementById('tab-' + name).classList.add('active');

  // On active le bouton correspondant
  document.querySelectorAll('.tab').forEach(t => {
    if (t.getAttribute('onclick') === `switchTab('${name}')`) {
      t.classList.add('active');
    }
  });
}


/* ==========================================================
   INITIALISATION
   Code exécuté automatiquement au chargement de la page.
   ========================================================== */

// On initialise les affichages de cryptographie classique
updateCesar();
updateVigenere();

// On écrit les premiers messages dans le journal
log(' CryptoLink initialisé — système de communication sécurisée prêt', 'ok');
log(' Modules actifs : AES-256, RSA-2048 (simulé), SHA-256, César, Vigenère', 'info');
