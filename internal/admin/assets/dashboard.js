function setupProtection(panel) {
  const title = panel.querySelector('[data-status-title]');
  const icon = panel.querySelector('.protection-icon');
  const active = panel.querySelector('[data-active-copy]');
  const timed = panel.querySelector('[data-timed-copy]');
  const indefinite = panel.querySelector('[data-indefinite-copy]');
  const countdown = panel.querySelector('[data-countdown]');
  const resumeTime = panel.querySelector('[data-resume-time]');
  const resume = panel.querySelector('[data-resume]');
  const options = panel.querySelector('.pause-options');
  const summary = options.querySelector('summary');
  const clock = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  let deadline = 0;
  let checking = false;

  function showStatus(paused, until, remainingSeconds) {
    const timedPause = paused && remainingSeconds > 0;
    const focusResume = paused && options.contains(document.activeElement);
    const focusPause = !paused && resume.contains(document.activeElement);
    const label = paused ? 'Blocking paused' : 'Blocking active';
    if (title.textContent !== label) title.textContent = label;
    icon.classList.toggle('paused', paused);
    active.hidden = paused;
    timed.hidden = !timedPause;
    indefinite.hidden = !paused || timedPause;
    options.hidden = paused;
    resume.hidden = !paused;
    if (paused) options.open = false;
    if (focusResume) resume.querySelector('button').focus();
    if (focusPause) summary.focus();
    deadline = timedPause ? performance.now() + remainingSeconds * 1000 : 0;
    if (timedPause) {
      resumeTime.dateTime = until;
      resumeTime.textContent = clock.format(new Date(until));
      countdown.hidden = false;
      tick();
    }
  }

  async function refresh() {
    if (checking || document.hidden) return;
    checking = true;
    try {
      const response = await fetch('/blocking', { headers: { Accept: 'application/json' } });
      if (response.ok && response.headers.get('Content-Type')?.startsWith('application/json')) {
        const status = await response.json();
        showStatus(status.paused, status.until, status.remainingSeconds);
      }
    } catch {
      // Keep the current countdown when the console is temporarily unreachable.
    } finally {
      checking = false;
    }
  }

  function tick() {
    if (!deadline) return;
    const seconds = Math.ceil((deadline - performance.now()) / 1000);
    if (seconds <= 0) {
      showStatus(false, '', 0);
      void refresh();
      return;
    }
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor(seconds / 60) % 60;
    const rest = seconds % 60;
    const remaining = hours ? `${hours}h ${minutes}m ${rest}s` : minutes ? `${minutes}m ${rest}s` : `${rest}s`;
    const label = `${remaining} remaining.`;
    if (countdown.textContent !== label) countdown.textContent = label;
  }

  document.addEventListener('click', (event) => {
    if (!options.contains(event.target)) options.open = false;
  });
  options.addEventListener('keydown', (event) => {
    if (options.open && event.key === 'Escape') {
      options.open = false;
      summary.focus();
    }
  });
  document.addEventListener('visibilitychange', refresh);
  window.addEventListener('pageshow', refresh);
  showStatus(!resume.hidden, resumeTime.dateTime, Number(panel.dataset.remaining));
  setInterval(tick, 250);
  setInterval(refresh, 15000);
}

function setupTraffic(canvas) {
  const context = canvas.getContext('2d');
  if (!context) return;
  const queries = [...canvas.querySelectorAll('[data-queries]')].map((cell) => Number(cell.dataset.queries));
  const blocks = [...canvas.querySelectorAll('[data-blocks]')].map((cell) => Number(cell.dataset.blocks));
  const ticks = 4;
  const roughStep = Math.max(1, Math.max(...queries, ...blocks) / ticks);
  const magnitude = 10 ** Math.floor(Math.log10(roughStep));
  const step = [1, 2, 5, 10].find((factor) => factor * magnitude >= roughStep) * magnitude;
  const format = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });

  function draw() {
    const { width, height } = canvas.getBoundingClientRect();
    if (!width || !height) return;
    const scale = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    context.scale(scale, scale);
    const style = getComputedStyle(canvas);
    const left = 40;
    const right = width - 6;
    const top = 9;
    const bottom = height - 8;
    const x = (i) => left + (right - left) * i / (queries.length - 1);
    const y = (value) => bottom - (bottom - top) * value / (ticks * step);
    context.font = `11px ${style.fontFamily}`;
    context.textAlign = 'right';
    context.textBaseline = 'middle';
    context.strokeStyle = style.getPropertyValue('--border').trim();
    context.fillStyle = style.getPropertyValue('--muted').trim();
    for (let i = 0; i <= ticks; i++) {
      const value = i * step;
      const line = y(value);
      context.beginPath();
      context.moveTo(left, line);
      context.lineTo(right, line);
      context.stroke();
      context.fillText(format.format(value), left - 7, line, left - 7);
    }

    function series(values, color, area) {
      if (values.every((value) => value === 0)) return;
      const path = new Path2D();
      path.moveTo(x(0), y(values[0]));
      for (let i = 1; i < values.length; i++) path.lineTo(x(i), y(values[i]));
      if (area) {
        const fill = new Path2D(path);
        fill.lineTo(right, bottom);
        fill.lineTo(left, bottom);
        fill.closePath();
        context.fillStyle = color;
        context.globalAlpha = 0.12;
        context.fill(fill);
        context.globalAlpha = 1;
      }
      context.strokeStyle = color;
      context.lineWidth = 2;
      context.lineJoin = 'round';
      context.stroke(path);
    }

    series(queries, style.getPropertyValue('--accent').trim(), true);
    series(blocks, style.getPropertyValue('--query-blocked').trim(), false);
  }

  new ResizeObserver(draw).observe(canvas);
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', draw);
}

// Rankings for a busy day take a few seconds on small devices. While they are
// being calculated the page shows older rankings or a notice, then swaps in the
// new rankings when they are ready. Polling stops once they arrive.
function setupRankings(section) {
  const delay = 3000;
  const maxAttempts = 40;
  let attempts = 0;
  let timer = 0;
  let busy = false;

  const updating = () => section.hasAttribute('data-rankings-updating');
  const schedule = () => {
    if (!timer && updating() && attempts < maxAttempts) timer = setTimeout(check, delay);
  };

  async function check() {
    timer = 0;
    if (document.hidden || busy) return;
    busy = true;
    attempts++;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(window.location.href, { redirect: 'error', signal: controller.signal });
      if (!response.ok) throw new Error('Dashboard request failed.');
      const page = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = page.querySelector('[data-rankings]');
      if (next && !next.hasAttribute('data-rankings-updating')) {
        section.replaceWith(next);
        section = next;
        return;
      }
    } catch {
      // Keep the rankings already shown and try again on the next attempt.
    } finally {
      clearTimeout(timeout);
      busy = false;
    }
    if (attempts >= maxAttempts) {
      const status = section.querySelector('[data-rankings-status]');
      if (status) status.textContent = 'Rankings are taking longer than usual. Refresh the page to try again.';
      return;
    }
    schedule();
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) schedule();
  });
  schedule();
}

const protection = document.querySelector('[data-protection]');
if (protection) setupProtection(protection);
const rankings = document.querySelector('[data-rankings]');
if (rankings) setupRankings(rankings);
const traffic = document.querySelector('[data-traffic-chart]');
if (traffic) setupTraffic(traffic);
