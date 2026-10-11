// Qassas site: a small hash routed app over one data bundle.
// Every visible string comes from the bundle in both languages; nothing is hard coded here.
import * as core from './core.js';

const S = { lang: 'ar', data: null, sigs: null, zone: 'kuwait', route: [] };
const app = document.getElementById('app');
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};

// ---------------------------------------------------------------- helpers

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const L = (pair) => (pair ? pair[S.lang] ?? pair.en : '');
function t(key, vars) {
  const entry = S.data.ui[key];
  if (!entry) { console.error('missing ui key', key); return key; }
  let s = entry[S.lang];
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, v);
  return s;
}
const num = (n) => String(n);
const img = (id, small = true, alt = '') => `<img src="media/scenes/${esc(id)}${small ? '-sm' : ''}.jpg" alt="${esc(alt)}" loading="lazy" decoding="async" width="${small ? 672 : 1344}" height="${small ? 376 : 752}">`;
const byId = (list, id) => list.find((x) => x.id === id);
const icon = (name) => `<svg class="ico" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const link = (href, text, cls = '') => `<a href="${href}"${cls ? ` class="${cls}"` : ''}>${text}</a>`;

function trail(n, cls = '') {
  // Footprints as plain geometry: pairs of offset ovals, the signature mark of the site.
  let marks = '';
  for (let i = 0; i < n; i++) {
    const x = 14 + i * 26;
    const y = i % 2 ? 9 : 21;
    marks += `<ellipse cx="${x}" cy="${y}" rx="5" ry="8" transform="rotate(${i % 2 ? 12 : -12} ${x} ${y})" style="--i:${i}"/>`;
  }
  return `<svg class="trail ${cls}" viewBox="0 0 ${n * 26 + 10} 32" aria-hidden="true">${marks}</svg>`;
}

// ---------------------------------------------------------------- chrome

function applyChrome() {
  const html = document.documentElement;
  html.lang = S.lang;
  html.dir = S.lang === 'ar' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-t]').forEach((el) => { el.textContent = t(el.dataset.t); });
  document.querySelectorAll('[data-t-aria]').forEach((el) => { el.setAttribute('aria-label', t(el.dataset.tAria)); });
  const toggle = document.getElementById('lang');
  toggle.textContent = S.lang === 'ar' ? 'English' : 'العربية';
  toggle.lang = S.lang === 'ar' ? 'en' : 'ar';
  document.querySelectorAll('nav.main a').forEach((a) => {
    const target = a.getAttribute('href').slice(2);
    a.toggleAttribute('aria-current', S.route[0] === target || (target === '' && !S.route[0]));
    if (a.hasAttribute('aria-current')) a.setAttribute('aria-current', 'page');
  });
}

function setLang(lang) {
  S.lang = lang;
  store.set('qassas.lang', lang);
  render();
}

// ---------------------------------------------------------------- views

function home() {
  const d = S.data;
  const mods = d.modules;
  const hours = mods.reduce((a, m) => a + m.hours, 0);
  const stages = ['identify', 'preserve', 'acquire', 'analyse', 'present'];
  return `
  <section class="hero" aria-labelledby="hero-title">
    <picture class="hero-img">${img('01-hero-tracker', false, t('hero.alt'))}</picture>
    <div class="hero-body wrap">
      <h1 id="hero-title">${t('hero.title')}</h1>
      <p class="lede">${t('hero.lede', { m: num(mods.length), h: num(hours), l: num(d.labs.length) })}</p>
      <div class="actions">
        ${link('#/learn', t('hero.start') + icon('arrow'), 'btn primary')}
        ${link('#/case', t('hero.case'), 'btn ghost')}
      </div>
      ${trail(12, 'hero-trail')}
    </div>
  </section>

  <section class="band ink" aria-labelledby="watch-title">
    <div class="wrap split">
      <div>
        <h2 id="watch-title">${t('watch.title')}</h2>
        <p>${t('watch.lede')}</p>
        <p class="fine">${t('watch.credit')}</p>
      </div>
      ${video()}
    </div>
  </section>

  <section class="wrap section" aria-labelledby="stages-title">
    <h2 id="stages-title">${t('stages.title')}</h2>
    <ol class="stakes">
      ${stages.map((s, i) => `<li><span class="stake" aria-hidden="true"></span><strong>${t('stage.' + s)}</strong><span>${t('stage.' + s + '.d')}</span><span class="n">${i + 1}</span></li>`).join('')}
    </ol>
  </section>

  <section class="wrap section" aria-labelledby="trail-title">
    <div class="section-head"><h2 id="trail-title">${t('learn.title')}</h2>${link('#/learn', t('learn.all') + icon('arrow'), 'more')}</div>
    <p class="measure">${t('learn.lede')}</p>
    ${moduleTrail(mods)}
  </section>

  <section class="band sand" aria-labelledby="labs-title">
    <div class="wrap">
      <div class="section-head"><h2 id="labs-title">${t('labs.title')}</h2>${link('#/labs', t('labs.all') + icon('arrow'), 'more')}</div>
      ${labLedger()}
    </div>
  </section>

  <section class="wrap section case-teaser" aria-labelledby="case-title">
    <div>
      <h2 id="case-title">${L(d.case.title)}</h2>
      ${d.case.brief.slice(0, 2).map((p) => `<p>${esc(L(p))}</p>`).join('')}
      ${link('#/case', t('case.open') + icon('arrow'), 'btn primary')}
    </div>
    <figure>${img('04-evidence-bag', true, t('case.alt'))}<figcaption>${esc(d.case.ref)}</figcaption></figure>
  </section>

  <section class="band ink" aria-labelledby="kit-title">
    <div class="wrap split">
      <div>
        <h2 id="kit-title">${t('kit.title')}</h2>
        <p>${t('kit.lede')}</p>
        <ul class="ticks">${['kit.p1', 'kit.p2', 'kit.p3'].map((k) => `<li>${t(k)}</li>`).join('')}</ul>
      </div>
      <pre class="code" dir="ltr"><code>${esc(d.install)}</code></pre>
    </div>
  </section>

  <section class="wrap section" aria-labelledby="law-title">
    <div class="section-head"><h2 id="law-title">${t('law.title')}</h2>${link('#/law', t('law.all') + icon('arrow'), 'more')}</div>
    <p class="measure">${t('law.lede')}</p>
    <ul class="counts">${countryCounts()}</ul>
  </section>`;
}

function video() {
  const v = S.data.videos[S.lang];
  return `<figure class="player">
    <video controls preload="none" playsinline poster="media/explainer/poster.jpg" width="1920" height="1080">
      <source src="${esc(v.src)}" type="video/mp4">
      <track kind="captions" src="${esc(v.vtt)}" srclang="${S.lang}" label="${esc(t('lang.name'))}" default>
    </video>
    <figcaption>${t('watch.caption', { d: num(v.seconds) })}</figcaption>
  </figure>`;
}

function moduleTrail(mods) {
  return `<ol class="trail-list">${mods.map((m) => `
    <li>
      <a href="#/learn/${m.id}">
        <span class="step" aria-hidden="true">${String(m.n).padStart(2, '0')}</span>
        <span class="tl-body"><strong>${esc(L(m.title))}</strong><span>${esc(L(m.summary))}</span></span>
        <span class="tl-meta">${t('learn.hours', { h: num(m.hours) })}${m.lab ? ` <span class="tag">${t('learn.haslab')}</span>` : ''}</span>
      </a>
    </li>`).join('')}</ol>`;
}

function labLedger() {
  return `<table class="ledger"><thead><tr><th scope="col">${t('labs.col.lab')}</th><th scope="col">${t('labs.col.do')}</th><th scope="col">${t('labs.col.module')}</th></tr></thead><tbody>
  ${S.data.labs.map((l) => {
    const m = byId(S.data.modules, l.module);
    return `<tr><th scope="row">${link('#/labs/' + l.id, esc(L(l.title)))}</th><td>${esc(L(l.does))}</td><td>${m ? link('#/learn/' + m.id, esc(L(m.title))) : ''}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function countryCounts() {
  const order = ['KW', 'SA', 'AE', 'QA', 'BH', 'OM', 'INTL'];
  return order.map((c) => {
    const n = S.data.legal.filter((r) => r.country === c).length;
    return `<li>${link('#/law/' + c, `<strong>${num(n)}</strong><span>${t('country.' + c)}</span>`)}</li>`;
  }).join('');
}

function learn() {
  return `<section class="wrap page">
    <h1>${t('learn.title')}</h1>
    <p class="measure">${t('learn.lede')}</p>
    ${moduleTrail(S.data.modules)}
  </section>`;
}

function moduleView(id) {
  const d = S.data;
  const m = byId(d.modules, id);
  if (!m) return notFound();
  const i = d.modules.indexOf(m);
  const prev = d.modules[i - 1];
  const next = d.modules[i + 1];
  const lab = m.lab ? byId(d.labs, m.lab) : null;
  return `<article class="module">
    <header class="module-head">
      <picture>${img(m.image, false, '')}</picture>
      <div class="wrap">
        <p class="crumbs">${link('#/learn', t('learn.title'))} <span aria-hidden="true">/</span> ${t('learn.module', { n: num(m.n) })}</p>
        <h1>${esc(L(m.title))}</h1>
        <p class="lede">${esc(L(m.summary))}</p>
      </div>
    </header>
    <div class="wrap module-grid">
      <aside class="module-side">
        <h2>${t('mod.objectives')}</h2>
        <ul class="ticks">${m.objectives.map((o) => `<li>${esc(L(o))}</li>`).join('')}</ul>
        <p class="fine">${t('learn.hours', { h: num(m.hours) })}</p>
        ${lab ? link('#/labs/' + lab.id, t('mod.openlab', { lab: esc(L(lab.title)) }) + icon('arrow'), 'btn primary') : ''}
      </aside>
      <div class="prose">
        <h2>${t('mod.lesson')}</h2>
        ${m.lesson.map((p) => `<p>${esc(L(p))}</p>`).join('')}
        <h2>${t('mod.steps')}</h2>
        <ol class="steps">${m.steps.map((s) => `<li>${esc(L(s))}</li>`).join('')}</ol>
        <h2>${t('mod.pitfalls')}</h2>
        <ul class="pitfalls">${m.pitfalls.map((p) => `<li>${icon('warn')}<span>${esc(L(p))}</span></li>`).join('')}</ul>
        <div class="kuwait-note"><h2>${t('mod.kuwait')}</h2><p>${esc(L(m.kuwait))}</p></div>
        ${m.commands.length ? `<h2>${t('mod.commands')}</h2><pre class="code" dir="ltr"><code>${m.commands.map(esc).join('\n')}</code></pre>` : ''}
        ${refs(m)}
        <h2>${t('mod.quiz')}</h2>
        <div class="quiz">${m.quiz.map((q, qi) => quizItem(m, q, qi)).join('')}</div>
      </div>
    </div>
    <nav class="wrap pager" aria-label="${esc(t('mod.pager'))}">
      ${prev ? link('#/learn/' + prev.id, `<span>${t('mod.prev')}</span><strong>${esc(L(prev.title))}</strong>`, 'prev') : '<span></span>'}
      ${next ? link('#/learn/' + next.id, `<span>${t('mod.next')}</span><strong>${esc(L(next.title))}</strong>`, 'next') : '<span></span>'}
    </nav>
  </article>`;
}

function refs(m) {
  const d = S.data;
  const laws = m.law_refs.map((r) => byId(d.legal, r)).filter(Boolean);
  const tools = m.tools.map((r) => byId(d.tools.tools, r)).filter(Boolean);
  const terms = m.terms.map((r) => byId(d.glossary, r)).filter(Boolean);
  return `<div class="refs">
    ${laws.length ? `<div><h3>${t('mod.law')}</h3><ul>${laws.map((r) => `<li>${link('#/law/' + r.country + '/' + r.id, esc(L(r.title)))}</li>`).join('')}</ul></div>` : ''}
    ${tools.length ? `<div><h3>${t('mod.tools')}</h3><ul class="chips">${tools.map((x) => `<li>${link('#/tools/' + x.id, esc(x.name))}</li>`).join('')}</ul></div>` : ''}
    ${terms.length ? `<div><h3>${t('mod.terms')}</h3><ul class="chips">${terms.map((x) => `<li>${link('#/glossary/' + x.id, esc(L(x.term)))}</li>`).join('')}</ul></div>` : ''}
  </div>`;
}

function quizItem(m, q, qi) {
  const name = `${m.id}-${qi}`;
  return `<fieldset class="q" data-answer="${q.answer}">
    <legend>${esc(L(q.q))}</legend>
    ${q.options.map((o, oi) => `<label><input type="radio" name="${name}" value="${oi}"><span>${esc(L(o))}</span></label>`).join('')}
    <p class="why" hidden data-ok="${esc(t('quiz.right'))}" data-bad="${esc(t('quiz.wrong'))}"><strong></strong> ${esc(L(q.why))}</p>
  </fieldset>`;
}

function bindQuiz() {
  app.querySelectorAll('fieldset.q').forEach((fs) => {
    fs.addEventListener('change', (e) => {
      const right = Number(e.target.value) === Number(fs.dataset.answer);
      const why = fs.querySelector('.why');
      why.hidden = false;
      why.querySelector('strong').textContent = right ? why.dataset.ok : why.dataset.bad;
      fs.classList.toggle('right', right);
      fs.classList.toggle('wrong', !right);
    });
  });
}

// ---------------------------------------------------------------- labs

function labs() {
  return `<section class="wrap page"><h1>${t('labs.title')}</h1><p class="measure">${t('labs.lede')}</p>${labLedger()}
    <p class="fine">${t('labs.private')}</p></section>`;
}

function labShell(id, body) {
  const l = byId(S.data.labs, id);
  const m = byId(S.data.modules, l.module);
  return `<section class="wrap page lab">
    <p class="crumbs">${link('#/labs', t('labs.title'))} <span aria-hidden="true">/</span> ${link('#/learn/' + m.id, esc(L(m.title)))}</p>
    <h1>${esc(L(l.title))}</h1>
    <p class="measure">${esc(L(l.intro))}</p>
    <div class="console">${body}</div>
    <p class="fine">${t('labs.private')}</p>
  </section>`;
}

function dropZone(id, accept = '') {
  return `<div class="drop" data-drop="${id}">
    <label class="btn ghost">${icon('file')}<span>${t('lab.choose')}</span><input type="file" ${accept ? `accept="${accept}"` : ''} hidden></label>
    <span class="fine">${t('lab.drop')}</span>
  </div>`;
}

function samples(list) {
  return `<div class="samples"><span class="fine">${t('lab.samples')}</span>${list.map((s) => `<button type="button" class="chip" data-sample="${esc(s)}" dir="ltr">${esc(s.split('/').pop())}</button>`).join('')}</div>`;
}

function onFile(root, handler) {
  const zone = root.querySelector('.drop');
  const input = zone.querySelector('input');
  const take = async (file) => handler(new Uint8Array(await file.arrayBuffer()), file.name);
  input.addEventListener('change', () => input.files[0] && take(input.files[0]));
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('over'); if (e.dataTransfer.files[0]) take(e.dataTransfer.files[0]); });
  root.querySelectorAll('[data-sample]').forEach((b) => b.addEventListener('click', async () => {
    const res = await fetch('labs/case-01/' + b.dataset.sample);
    handler(new Uint8Array(await res.arrayBuffer()), b.dataset.sample.split('/').pop());
  }));
}

function hexView(bytes, hiStart = 0, hiLen = 0, count = 48) {
  let rows = '';
  for (let o = 0; o < Math.min(bytes.length, count); o += 16) {
    let hx = '';
    let tx = '';
    for (let i = o; i < Math.min(o + 16, bytes.length, count); i++) {
      const on = i >= hiStart && i < hiStart + hiLen;
      const b = bytes[i];
      hx += `<span${on ? ' class="hi"' : ''}>${b.toString(16).padStart(2, '0')}</span> `;
      tx += `<span${on ? ' class="hi"' : ''}>${b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : '.'}</span>`;
    }
    rows += `<div><span class="off">${o.toString(16).padStart(8, '0')}</span><span class="hx">${hx}</span><span class="tx">${tx}</span></div>`;
  }
  return `<div class="hexview evidence" dir="ltr">${rows}</div>`;
}

const LABS = {
  hash: {
    body: () => `
      <label class="field"><span>${t('hash.input')}</span><textarea id="hash-text" rows="3" dir="auto">${esc(t('hash.sample'))}</textarea></label>
      <div class="row"><button type="button" class="btn ghost" id="flip">${t('hash.flip')}</button>${dropZone('hash')}</div>
      <div id="hash-out" aria-live="polite"></div>`,
    bind(root) {
      const ta = root.querySelector('#hash-text');
      const out = root.querySelector('#hash-out');
      let before = null;
      const show = async (bytes, label) => {
        const h = await core.hashAll(bytes);
        let diff = '';
        if (before && before.label === label) {
          const n = core.bitDiff(before.sha256, h.sha256);
          const marked = [...h.sha256].map((c, i) => (c !== before.sha256[i] ? `<b>${c}</b>` : c)).join('');
          diff = `<p class="avalanche">${t('hash.changed', { n: num(n) })}</p><p class="digest" dir="ltr">${marked}</p>`;
        }
        out.innerHTML = `<dl class="kv" dir="ltr"><dt>bytes</dt><dd>${bytes.length}</dd><dt>MD5</dt><dd>${h.md5}</dd><dt>SHA-1</dt><dd>${h.sha1}</dd><dt>SHA-256</dt><dd>${h.sha256}</dd></dl>${diff}`;
        before = { ...h, label };
      };
      const fromText = () => show(new TextEncoder().encode(ta.value), 'text');
      ta.addEventListener('input', fromText);
      root.querySelector('#flip').addEventListener('click', () => {
        const v = ta.value;
        if (!v) return;
        const c = v.charCodeAt(v.length - 1);
        ta.value = v.slice(0, -1) + String.fromCharCode(c ^ 1);
        fromText();
      });
      onFile(root, (bytes, name) => show(bytes, 'file:' + name));
      fromText();
    },
  },
  signature: {
    body: () => `${dropZone('sig')}${samples(['evidence/Documents/invoice_0921.jpg', 'evidence/Pictures/IMG_2038.jpg', 'evidence/Documents/Tender_2026_Final.pdf', 'evidence/Recent/Tender_Update.lnk', 'evidence/Network/capture.pcap'])}<div id="sig-out" aria-live="polite"></div>`,
    bind(root) {
      const out = root.querySelector('#sig-out');
      onFile(root, (bytes, name) => {
        const v = core.identify(S.sigs, bytes.slice(0, 40960), name);
        const verdict = { match: t('sig.match'), mismatch: t('sig.mismatch'), unknown: t('sig.unknown') }[v.status];
        out.innerHTML = `<p class="verdict ${v.status}">${icon(v.status === 'match' ? 'ok' : 'warn')}<span>${verdict}</span></p>
          <dl class="kv"><dt>${t('sig.name')}</dt><dd dir="ltr">${esc(name)}</dd><dt>${t('sig.detected')}</dt><dd dir="ltr">${esc(v.description || '?')}</dd>
          <dt>${t('sig.expected')}</dt><dd dir="ltr">${esc(v.expected.filter(Boolean).map((e) => '.' + e).join('  '))}</dd></dl>
          <h3>${t('sig.first')}</h3>${hexView(bytes, v.magicOffset, v.magicLength)}`;
      });
    },
  },
  exif: {
    body: () => `${dropZone('exif', 'image/jpeg')}${samples(['evidence/Pictures/IMG_2038.jpg', 'carved/deleted_photo.jpg'])}<div id="exif-out" aria-live="polite"></div>`,
    bind(root) {
      const out = root.querySelector('#exif-out');
      onFile(root, (bytes, name) => {
        const m = core.readExif(bytes);
        if (!m) { out.innerHTML = `<p class="verdict mismatch">${icon('warn')}<span>${t('exif.notjpeg')}</span></p>`; return; }
        if (!Object.keys(m).length) { out.innerHTML = `<p class="verdict unknown">${icon('warn')}<span>${t('exif.none')}</span></p>`; return; }
        const when = core.exifToUtc(m.datetime_original, m.offset_time_original);
        let place = `<p class="fine">${t('exif.nogps')}</p>`;
        if (m.gps) {
          const near = core.nearestAreas(S.data.areas, m.gps.lat, m.gps.lon);
          const max = Math.max(...near.map((a) => a.km), 1);
          place = `<h3>${t('exif.near')}</h3><ol class="near">${near.map((a, i) => `<li${i ? '' : ' class="best"'}><span>${esc(L(a.name))}</span><span class="bar" style="--w:${Math.max(4, 100 - (a.km / max) * 96)}%"></span><span dir="ltr">${a.km} km</span></li>`).join('')}</ol>
            <p class="fine">${t('exif.approx')}</p>`;
        }
        out.innerHTML = `<dl class="kv"><dt>${t('sig.name')}</dt><dd dir="ltr">${esc(name)}</dd>
          <dt>${t('exif.device')}</dt><dd dir="ltr">${esc([m.make, m.model].filter(Boolean).join(' ') || '?')}</dd>
          <dt>${t('exif.taken')}</dt><dd dir="ltr">${esc(m.datetime_original || '?')} ${esc(m.offset_time_original || '')}</dd>
          <dt>UTC</dt><dd dir="ltr">${when ? esc(when.utc) : '?'}${when && when.assumed ? ` <em>${t('exif.nooffset')}</em>` : ''}</dd>
          ${m.gps ? `<dt>GPS</dt><dd dir="ltr">${m.gps.lat}, ${m.gps.lon}</dd>` : ''}</dl>${place}`;
      });
    },
  },
  custody: {
    body: () => `<div class="row"><button type="button" class="btn primary" id="verify">${icon('ok')}<span>${t('cus.verify')}</span></button>
      <button type="button" class="btn ghost" id="load-archive">${t('cus.archive')}</button><button type="button" class="btn ghost" id="reset">${t('cus.reset')}</button></div>
      <p class="fine">${t('cus.howto')}</p><div id="cus-status" aria-live="polite"></div><ol class="custody" id="cus-list"></ol>`,
    async bind(root) {
      const list = root.querySelector('#cus-list');
      const status = root.querySelector('#cus-status');
      let entries = [];
      const load = async (file) => {
        const text = await (await fetch('labs/case-01/custody/' + file)).text();
        entries = text.trim().split('\n').map((l) => JSON.parse(l));
        draw([]);
        status.innerHTML = '';
      };
      const draw = (problems) => {
        const bad = new Map();
        problems.forEach((p) => bad.set(p.seq, [...(bad.get(p.seq) || []), p.code]));
        list.innerHTML = entries.map((e, i) => `<li class="${bad.has(e.seq) ? 'broken' : ''}">
          <span class="seq">${e.seq}</span>
          <div><p class="head"><strong>${esc(t('act.' + e.action))}</strong> <span class="fine" dir="ltr">${esc(e.item)}</span></p>
            <div class="fields">
            <label class="inline"><span>${t('cus.time')}</span><input data-i="${i}" data-k="time_utc" value="${esc(e.time_utc)}" dir="ltr"></label>
            <label class="inline"><span>${t('cus.by')}</span><input data-i="${i}" data-k="by" value="${esc(e.by)}" dir="ltr"></label>
            <label class="inline wide"><span>${t('cus.note')}</span><input data-i="${i}" data-k="note" value="${esc(e.note || '')}" dir="ltr"></label>
            </div>
            <code class="h" dir="ltr">SHA-256 ${esc(e.hash.slice(0, 24))}...</code>
            ${bad.has(e.seq) ? `<p class="why-bad">${bad.get(e.seq).map((c) => esc(L(S.data.custodyText[c]))).join(' / ')}</p>` : ''}
          </div></li>`).join('');
        list.querySelectorAll('input').forEach((inp) => inp.addEventListener('change', () => {
          const e = entries[Number(inp.dataset.i)];
          e[inp.dataset.k] = inp.value === '' && inp.dataset.k === 'note' ? null : inp.value;
        }));
      };
      root.querySelector('#verify').addEventListener('click', async () => {
        const p = await core.verifyCustody(entries);
        draw(p);
        status.innerHTML = p.length
          ? `<p class="verdict mismatch">${icon('warn')}<span>${t('cus.broken', { n: num(new Set(p.map((x) => x.seq)).size) })}</span></p>`
          : `<p class="verdict match">${icon('ok')}<span>${t('cus.intact', { n: num(entries.length) })}</span></p>`;
      });
      root.querySelector('#load-archive').addEventListener('click', () => load('custody_archive_copy.jsonl'));
      root.querySelector('#reset').addEventListener('click', () => load('custody.jsonl'));
      await load('custody.jsonl');
    },
  },
  timeline: {
    body: () => `<div class="row"><div class="seg" role="group" aria-label="${esc(t('tl.zone'))}">
      <button type="button" data-zone="kuwait" aria-pressed="true">${t('tl.kuwait')}</button><button type="button" data-zone="utc" aria-pressed="false">UTC</button></div>
      <label class="check"><input type="checkbox" id="pivots" checked> ${t('tl.pivots')}</label></div>
      <div id="tl-strip"></div><div class="chips" id="tl-filter"></div><ol class="tl" id="tl-list"></ol>`,
    bind(root) {
      const ev = S.data.timeline;
      const sources = [...new Set(ev.map((e) => e.source))];
      const on = new Set(sources);
      const filter = root.querySelector('#tl-filter');
      filter.innerHTML = sources.map((s) => `<button type="button" class="chip src-${s}" data-src="${s}" aria-pressed="true">${t('src.' + s)}</button>`).join('');
      const draw = () => {
        const pivotsOnly = root.querySelector('#pivots').checked;
        const rows = ev.filter((e) => on.has(e.source) && (!pivotsOnly || e.pivot));
        root.querySelector('#tl-list').innerHTML = rows.map((e) => `<li class="src-${e.source}${e.pivot ? ' pivot' : ''}">
          <time dir="ltr" datetime="${e.time_utc}">${core.toZone(e.time_utc, S.zone)}</time>
          <span class="src">${t('src.' + e.source)}</span><span class="d evidence" dir="ltr">${esc(e.description)}</span>
          ${e.pivot ? `<span class="pv">${esc(L(S.data.pivotText[e.pivot]))}</span>` : ''}</li>`).join('');
        root.querySelector('#tl-strip').innerHTML = strip(ev.filter((e) => on.has(e.source)));
      };
      filter.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
        const s = b.dataset.src;
        if (on.has(s)) on.delete(s); else on.add(s);
        b.setAttribute('aria-pressed', on.has(s));
        draw();
      }));
      root.querySelectorAll('[data-zone]').forEach((b) => b.addEventListener('click', () => {
        S.zone = b.dataset.zone;
        root.querySelectorAll('[data-zone]').forEach((x) => x.setAttribute('aria-pressed', x === b));
        draw();
      }));
      root.querySelector('#pivots').addEventListener('change', draw);
      draw();
    },
  },
  case: {
    body: () => caseBody(true),
    bind: bindCase,
  },
};

// The morning of 4 October as a strip: one lane per source, one tick per event.
function strip(events) {
  const day = events.filter((e) => e.time_utc.startsWith('2026-10-04'));
  const start = Date.parse('2026-10-04T04:30:00Z');
  const end = Date.parse('2026-10-04T07:00:00Z');
  const lanes = [...new Set(S.data.timeline.map((e) => e.source))];
  const W = 1000;
  const lh = 18;
  const H = lanes.length * lh + 26;
  const x = (iso) => ((Date.parse(iso) - start) / (end - start)) * W;
  let ticks = '';
  for (let h = 0; h <= 5; h++) {
    const tx = (h / 5) * W;
    const tt = new Date(start + (h / 5) * (end - start));
    const label = S.zone === 'utc' ? tt.toISOString().slice(11, 16) : new Date(tt.getTime() + 3 * 3600000).toISOString().slice(11, 16);
    const anchor = h === 0 ? 'start' : h === 5 ? 'end' : 'middle';
    ticks += `<line x1="${tx}" x2="${tx}" y1="0" y2="${H - 18}" class="grid"/><text x="${tx}" y="${H - 4}" class="lbl" text-anchor="${anchor}">${label}</text>`;
  }
  const marks = day.filter((e) => Date.parse(e.time_utc) >= start && Date.parse(e.time_utc) <= end).map((e) => {
    const y = lanes.indexOf(e.source) * lh + 4;
    return `<rect x="${x(e.time_utc).toFixed(1)}" y="${y}" width="${e.pivot ? 4 : 2}" height="${lh - 6}" class="src-${e.source}${e.pivot ? ' pivot' : ''}"><title>${esc(core.toZone(e.time_utc, S.zone))} ${esc(e.description)}</title></rect>`;
  }).join('');
  return `<figure class="strip evidence"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(t('tl.strip'))}" dir="ltr">${ticks}${marks}</svg>
    <figcaption>${t('tl.strip')}</figcaption></figure>`;
}

function caseBody(compact) {
  const c = S.data.case;
  return `${compact ? '' : `<div class="brief">${c.brief.map((p) => `<p>${esc(L(p))}</p>`).join('')}<p class="fine">${esc(L(c.synthetic))}</p></div>`}
    <div class="row"><a class="btn primary" href="labs/case-01.zip" download>${icon('file')}<span>${t('case.download', { mb: c.zipMB })}</span></a>
    <span class="fine" dir="ltr">SHA-256 ${esc(c.zipSha256.slice(0, 16))}...</span></div>
    <h2>${t('case.evidence')}</h2>
    <table class="ledger"><tbody>${c.evidence.map((e) => `<tr><th scope="row" dir="ltr">${esc(e.path)}</th><td>${esc(L(e))}</td></tr>`).join('')}</tbody></table>
    <h2>${t('case.questions')}</h2>
    <form class="answers" id="answers">
      ${c.questions.map((q, i) => `<div class="qa" data-id="${q.id}">
        <label for="a-${q.id}"><span class="n">${i + 1}</span>${esc(L(q))}</label>
        <input id="a-${q.id}" name="${q.id}" autocomplete="off" dir="auto">
        <span class="mark" aria-live="polite"></span>
        <details><summary>${t('case.hint')}</summary><code dir="ltr">${esc(q.command)}</code></details>
      </div>`).join('')}
      <div class="row"><button class="btn primary" type="submit">${t('case.check')}</button><output id="score" aria-live="polite"></output></div>
    </form>`;
}

function bindCase(root) {
  const form = root.querySelector('#answers');
  const saved = JSON.parse(store.get('qassas.case01') || '{}');
  form.querySelectorAll('input').forEach((i) => { if (saved[i.name]) i.value = saved[i.name]; });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    let score = 0;
    const keep = {};
    for (const q of S.data.case.questions) {
      const box = form.querySelector(`[data-id="${q.id}"]`);
      const val = box.querySelector('input').value;
      keep[q.id] = val;
      const mark = box.querySelector('.mark');
      if (!val.trim()) { mark.textContent = ''; box.className = 'qa'; continue; }
      const ok = q.answer_sha256.includes(await core.answerHash(S.data.case.id, q.id, val));
      if (ok) score++;
      box.className = 'qa ' + (ok ? 'right' : 'wrong');
      mark.textContent = ok ? t('quiz.right') : t('quiz.wrong');
    }
    store.set('qassas.case01', JSON.stringify(keep));
    form.querySelector('#score').textContent = t('case.score', { n: num(score), of: num(S.data.case.questions.length) });
  });
}

function labView(id) {
  const lab = LABS[id];
  if (!lab || !byId(S.data.labs, id)) return null;
  return { html: labShell(id, lab.body()), bind: lab.bind };
}

function caseView() {
  const c = S.data.case;
  return {
    html: `<section class="wrap page lab"><p class="crumbs" dir="ltr">${esc(c.ref)}</p><h1>${esc(L(c.title))}</h1><div class="console">${caseBody(false)}</div></section>`,
    bind: bindCase,
  };
}

// ---------------------------------------------------------------- reference pages

function watch() {
  const d = S.data;
  return `<section class="wrap page"><h1>${t('watch.title')}</h1><p class="measure">${t('watch.lede')}</p>
    ${video()}
    <p class="fine">${t('watch.credit')}</p>
    <h2>${t('watch.scenes')}</h2>
    <ul class="gallery">${d.media.map((m) => `<li><figure>${img(m.id, true, L(m.caption))}<figcaption>${esc(L(m.caption))}</figcaption></figure></li>`).join('')}</ul>
  </section>`;
}

function law(country, focus) {
  const d = S.data;
  const order = ['KW', 'SA', 'AE', 'QA', 'BH', 'OM', 'INTL'];
  const pick = order.includes(country) ? country : 'KW';
  const rows = d.legal.filter((r) => r.country === pick);
  return `<section class="wrap page"><h1>${t('law.title')}</h1><p class="measure">${t('law.lede')}</p>
    <p class="notice">${icon('warn')}<span>${t('law.notadvice')}</span></p>
    <nav class="tabs" aria-label="${esc(t('law.countries'))}">${order.map((c) => link('#/law/' + c, `${t('country.' + c)} <span>${d.legal.filter((r) => r.country === c).length}</span>`, c === pick ? 'on' : '')).join('')}</nav>
    <ol class="register">${rows.map((r) => `<li id="${r.id}"${r.id === focus ? ' class="focus"' : ''}>
      <div class="reg-meta"><span>${r.year}</span><span>${t('type.' + r.type)}</span></div>
      <div><h2>${esc(L(r.title))}</h2><p>${esc(L(r.summary))}</p>
      <details><summary>${t('law.notes')}</summary><ul lang="en" dir="ltr">${r.notes_en.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>${r.caveat_en ? `<p class="fine" lang="en" dir="ltr">${esc(r.caveat_en)}</p>` : ''}</details>
      <p class="src">${link(esc(r.source.url), t('law.source') + ` <span dir="ltr">${esc(r.source.name)}</span>`)}</p></div></li>`).join('')}</ol>
  </section>`;
}

function tools(focus) {
  const d = S.data.tools;
  return `<section class="wrap page"><h1>${t('tools.title')}</h1><p class="measure">${esc(L(d.method))}</p>
    ${d.categories.map((c) => {
      const list = d.tools.filter((x) => x.category === c.id);
      return `<h2>${esc(L(c.name))}</h2><table class="ledger tools"><tbody>${list.map((x) => `<tr id="${x.id}"${x.id === focus ? ' class="focus"' : ''}>
        <th scope="row">${link(esc(x.url), esc(x.name))}</th><td>${esc(L(x.desc))}</td><td dir="ltr" class="fine">${esc(x.license)}<br>${esc(x.platform)}</td></tr>`).join('')}</tbody></table>`;
    }).join('')}</section>`;
}

function glossary(focus) {
  const g = [...S.data.glossary].sort((a, b) => L(a.term).localeCompare(L(b.term), S.lang));
  return `<section class="wrap page"><h1>${t('glo.title')}</h1>
    <label class="field search"><span>${t('glo.search')}</span><input id="glo-q" type="search" dir="auto"></label>
    <dl class="glossary">${g.map((x) => `<div id="${x.id}" data-k="${esc((x.term.en + ' ' + x.term.ar + ' ' + x.def.en + ' ' + x.def.ar).toLowerCase())}"${x.id === focus ? ' class="focus"' : ''}>
      <dt>${esc(L(x.term))} <span class="other" lang="${S.lang === 'ar' ? 'en' : 'ar'}">${esc(S.lang === 'ar' ? x.term.en : x.term.ar)}</span></dt>
      <dd>${esc(L(x.def))} ${link('#/learn/' + x.module, t('glo.module'))}</dd></div>`).join('')}</dl></section>`;
}

function bindGlossary(root) {
  const q = root.querySelector('#glo-q');
  q.addEventListener('input', () => {
    const v = q.value.trim().toLowerCase();
    root.querySelectorAll('.glossary > div').forEach((d) => { d.hidden = v && !d.dataset.k.includes(v); });
  });
}

function about() {
  const d = S.data;
  return `<section class="wrap page prose"><h1>${t('about.title')}</h1>
    ${['about.p1', 'about.p2', 'about.p3'].map((k) => `<p>${t(k)}</p>`).join('')}
    <h2>${t('about.media')}</h2><p>${t('about.media.p')}</p>
    <h2>${t('about.author')}</h2><p>${esc(L(d.author))}</p>
    <h2>${t('about.license')}</h2><p>${t('about.license.p')}</p>
    <h2>${t('about.contribute')}</h2><p>${t('about.contribute.p')}</p>
    <p>${link('https://github.com/SiteQ8/Qassas', 'github.com/SiteQ8/Qassas')}</p>
    <p class="fine" dir="ltr">v${esc(d.version)}</p></section>`;
}

function notFound() {
  return `<section class="wrap page"><h1>${t('nf.title')}</h1><p>${t('nf.body')}</p>${link('#/', t('nav.home'), 'btn primary')}</section>`;
}

// ---------------------------------------------------------------- router

function render() {
  const raw = location.hash.replace(/^#\/?/, '');
  S.route = raw.split('/').filter(Boolean).map(decodeURIComponent);
  const [a, b, c] = S.route;
  let html;
  let bind = null;
  let title = t('site.title');
  if (!a) html = home();
  else if (a === 'learn' && b) { html = moduleView(b); const m = byId(S.data.modules, b); if (m) title = L(m.title); }
  else if (a === 'learn') { html = learn(); title = t('learn.title'); }
  else if (a === 'labs' && b) { const v = labView(b); if (v) { html = v.html; bind = v.bind; title = L(byId(S.data.labs, b).title); } else html = notFound(); }
  else if (a === 'labs') { html = labs(); title = t('labs.title'); }
  else if (a === 'case') { const v = caseView(); html = v.html; bind = v.bind; title = L(S.data.case.title); }
  else if (a === 'watch') { html = watch(); title = t('watch.title'); }
  else if (a === 'law') { html = law(b, c); title = t('law.title'); }
  else if (a === 'tools') { html = tools(b); title = t('tools.title'); }
  else if (a === 'glossary') { html = glossary(b); bind = bindGlossary; title = t('glo.title'); }
  else if (a === 'about') { html = about(); title = t('about.title'); }
  else html = notFound();
  app.innerHTML = html;
  applyChrome();
  document.title = title === t('site.title') ? title : `${title} | ${t('site.short')}`;
  bindQuiz();
  if (bind) bind(app);
  const focus = app.querySelector('.focus');
  if (focus) focus.scrollIntoView({ block: 'center' });
  else window.scrollTo(0, 0);
  const h1 = app.querySelector('h1');
  if (h1 && S.focusOnRender) { h1.tabIndex = -1; h1.focus({ preventScroll: true }); }
  S.focusOnRender = true;
}

async function boot() {
  const res = await fetch('data/bundle.json');
  S.data = await res.json();
  S.sigs = core.prepareSignatures(S.data.signatures);
  const param = new URLSearchParams(location.search).get('lang');
  const saved = store.get('qassas.lang');
  const nav = (navigator.language || '').toLowerCase().startsWith('ar') ? 'ar' : 'en';
  S.lang = ['ar', 'en'].includes(param) ? param : ['ar', 'en'].includes(saved) ? saved : nav;
  document.getElementById('lang').addEventListener('click', () => setLang(S.lang === 'ar' ? 'en' : 'ar'));
  window.addEventListener('hashchange', render);
  render();
  document.documentElement.classList.add('ready');
}

boot().catch((err) => {
  console.error(err);
  app.innerHTML = '<p class="wrap page">Qassas could not load its data. قصّاص لم يتمكن من تحميل بياناته</p>';
});
