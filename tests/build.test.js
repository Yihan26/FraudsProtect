const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { collectArticles, compareArticles, normalizeSection } = require('../build.js');
const { renderMarkdown, videoEmbedUrl, completeRegistration } = require('../content-utils.js');

test('normalizeSection accepts the three text sections only', () => {
  assert.equal(normalizeSection('Articles'), 'articles');
  assert.equal(normalizeSection('reports'), 'reports');
  assert.equal(normalizeSection('HONORS'), 'honors');
  assert.throws(() => normalizeSection('videos'), /Unsupported section/);
});

test('compareArticles puts pinned and lower manual order first', () => {
  const items = [
    { pinned: false, order: 0, publishedAt: '2026-02-01' },
    { pinned: true, order: 2, publishedAt: '2026-03-01' },
    { pinned: true, order: 1, publishedAt: '2026-01-01' },
  ];
  items.sort(compareArticles);
  assert.deepEqual(items.map((item) => [item.pinned, item.order]), [
    [true, 1],
    [true, 2],
    [false, 0],
  ]);
});

test('collectArticles reads section/article/index.md and meta.json', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'charity-content-'));
  const articleDir = path.join(root, 'articles', 'one');
  fs.mkdirSync(path.join(articleDir, 'images'), { recursive: true });
  fs.writeFileSync(path.join(articleDir, 'index.md'), '# Body\n\nHello.');
  fs.writeFileSync(path.join(articleDir, 'meta.json'), JSON.stringify({
    id: 'one', title: 'One', summary: 'Summary', publishedAt: '2026-01-01', pinned: false, order: 0,
  }));

  const articles = collectArticles(root);
  assert.equal(articles.length, 1);
  assert.equal(articles[0].section, 'articles');
  assert.equal(articles[0].markdown, '# Body\n\nHello.');
  assert.equal(articles[0].assetBase, 'content/articles/one/');
});

test('renderMarkdown supports safe rich markdown and blocks raw HTML', () => {
  const html = renderMarkdown('# Heading\n\n- [x] Done\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n![Alt](images/a.png)\n\n<script>alert(1)</script>');
  assert.match(html, /<h1>Heading<\/h1>/);
  assert.match(html, /type="checkbox" checked disabled/);
  assert.match(html, /<table>/);
  assert.match(html, /src="images\/a.png"/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});

test('videoEmbedUrl parses Bilibili and YouTube links', () => {
  assert.match(videoEmbedUrl('https://www.bilibili.com/video/BV1LN411o7YY'), /player\.bilibili\.com.*BV1LN411o7YY/);
  assert.equal(videoEmbedUrl('https://youtu.be/dQw4w9WgXcQ'), 'https://www.youtube.com/embed/dQw4w9WgXcQ?autoplay=1');
  assert.equal(videoEmbedUrl('https://example.com/video'), '');
});

test('completeRegistration resets the submitted form and opens the success modal', () => {
  let resetCalled = false;
  const form = { reset() { resetCalled = true; } };
  const modal = { classList: { active: false, add(name) { this[name] = true; } } };

  completeRegistration(form, modal);

  assert.equal(resetCalled, true);
  assert.equal(modal.classList.active, true);
});

test('homepage editor setup source handles an iframe that is already loaded', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'admin.js'), 'utf8');
  assert.match(source, /frame\.contentDocument\?\.readyState === 'complete'/);
  assert.match(source, /activateHomepageFrame\(frame\)/);
});

test('homepage editor blocks navigation inside its preview frame', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'admin.js'), 'utf8');
  assert.match(source, /event\.target\.closest\('a, button, form'\)/);
  assert.match(source, /event\.preventDefault\(\)/);
});

test('Worker applies the configured CORS origin to preflight and API responses', async () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'workers', 'src', 'index.js'), 'utf8');
  const { default: worker } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  const env = { ALLOWED_ORIGIN: 'https://yihan26.github.io' };
  for (const [route, method, body, status] of [
    ['/api/login', 'OPTIONS', undefined, 204],
    ['/', 'GET', undefined, 200],
    ['/api/login', 'POST', {}, 400],
    ['/api/register', 'POST', {}, 400],
    ['/api/me', 'GET', undefined, 401],
    ['/api/admin/publish', 'POST', {}, 403],
    ['/api/admin/delete', 'POST', {}, 403],
    ['/missing', 'GET', undefined, 404],
  ]) {
    const response = await worker.fetch(new Request(`https://api.example.invalid${route}`, {
      method,
      headers: { Origin: env.ALLOWED_ORIGIN, 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }), env, {});
    assert.equal(response.status, status, route);
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), env.ALLOWED_ORIGIN, route);
    assert.equal(response.headers.get('Vary'), 'Origin', route);
  }
});
