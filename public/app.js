// Juss Protect Me — Protect Checkup app logic.
// Answers live in localStorage only. No network calls, no tracking.
const GROUPS = [
  { title: 'Device Safety', sub: 'Keep your devices secure and in your hands.', items: [
    ['My phone has a screen lock (PIN, fingerprint, or face)', 'Open Settings and turn on a screen lock — it is the single strongest everyday protection a phone has.'],
    ['My phone and computer are on the latest system update', 'Updates patch the holes attackers actually use. Turn on automatic updates and let them run overnight.'],
    ['Find My (or Find My Device) is turned on', 'If the device is ever lost or taken, this is how you find it, lock it, or wipe it from another device.'],
    ['My photos and files back up automatically', 'With backup on, a lost phone is an inconvenience — not the loss of your pictures and documents.'],
  ]},
  { title: 'Identity Protection', sub: 'Help keep your personal information safe.', items: [
    ['My email has two-factor authentication on', 'Your email is the master key to every password reset. Protect it first: authenticator app or text code.'],
    ['My bank and money apps have two-factor on', 'Turn it on inside each money app\u2019s security settings — it stops most account takeovers cold.'],
    ['My email password is unique — not reused anywhere', 'One leaked password should never open five doors. A password manager makes this painless.'],
    ['I have credit alerts or a credit freeze', 'A freeze is free at all three bureaus and blocks new accounts opened in your name.'],
  ]},
  { title: 'Everyday Safety', sub: 'Feel safer at home, on the go, and online.', items: [
    ['I have reviewed who can see my location', 'Check location sharing in your phone settings — share with the people you choose, nobody else.'],
    ['My emergency contacts are set on my lock screen', 'Add them under Medical ID / emergency information so help can reach your people fast.'],
    ['My kids\u2019 devices have their own passcode I know', 'A passcode you know keeps their device theirs — and lets you step in when it matters.'],
    ['My home Wi-Fi has a strong, changed password', 'If it is still the sticker password from the router, change it in the router or provider app today.'],
  ]},
  { title: 'Privacy First', sub: 'You control your information.', items: [
    ['I reviewed app permissions in the last month', 'Camera, microphone, and location should belong only to apps that truly need them. Revoke the rest.'],
    ['My social profiles are set to friends/private', 'Public profiles hand strangers your routine, your kids, and your location history. Set them private.'],
    ['My browser blocks third-party cookies', 'One settings toggle stops a large share of cross-site tracking.'],
    ['I closed accounts I no longer use', 'Every forgotten account is a stored copy of your information. Close the ones you do not use.'],
  ]},
];
const KEY = 'jpm-checkup-v1';
let state = {};
try { state = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch { state = {}; }

const groupsEl = document.getElementById('groups');
GROUPS.forEach((g, gi) => {
  const div = document.createElement('section');
  div.className = 'group rise2';
  div.innerHTML = `<h2>${g.title}</h2><p>${g.sub}</p>`;
  g.items.forEach(([label, tip], ii) => {
    const id = `${gi}-${ii}`;
    const row = document.createElement('div');
    row.className = 'item' + (state[id] ? '' : ' open');
    row.innerHTML = `<input type="checkbox" id="c${id}" ${state[id] ? 'checked' : ''}><div><label for="c${id}">${label}</label><div class="tip">How: ${tip}</div></div>`;
    row.querySelector('input').addEventListener('change', (e) => {
      state[id] = e.target.checked;
      localStorage.setItem(KEY, JSON.stringify(state));
      row.classList.toggle('open', !state[id]);
      render();
    });
    div.appendChild(row);
  });
  groupsEl.appendChild(div);
});

function render() {
  const total = GROUPS.reduce((n, g) => n + g.items.length, 0);
  const done = Object.values(state).filter(Boolean).length;
  const pct = Math.round((done / total) * 100);
  document.getElementById('score').textContent = pct + '%';
  document.getElementById('score-label').textContent =
    pct === 100 ? 'Fully checked up — strong work' : pct >= 50 ? 'More than halfway there' : 'Start your checkup';
  document.getElementById('score-note').textContent =
    pct === 100 ? 'Every protection on this list is in place. Re-run the checkup every few months — settings drift.' :
    `${done} of ${total} protections in place. Anything unticked shows you exactly how to set it up.`;
}
document.getElementById('reset').addEventListener('click', () => {
  localStorage.removeItem(KEY);
  location.reload();
});
render();

// Installability: service worker + install prompt.
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
let deferred = null;
addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferred = e;
  document.getElementById('install').hidden = false;
});
document.getElementById('install').addEventListener('click', async () => {
  if (deferred) { deferred.prompt(); deferred = null; document.getElementById('install').hidden = true; }
});
