import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

function loadIndexModules() {
  const html = fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf8');
  const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(scriptMatch, 'index.html must contain an inline <script>');

  let code = scriptMatch[1];
  // Expose internal modules before closing the IIFE without modifying index.html
  const tailMarker = 'if (document.readyState === "loading")';
  const idx = code.indexOf(tailMarker);
  assert.ok(idx !== -1, 'Could not locate bootstrap tail marker');
  code =
    code.slice(0, idx) +
    'return { Config, Validators, ImageTools, Countdown };\n  })();';

  const stubEl = {
    style: {},
    classList: { add() {}, remove() {}, toggle() {} },
    setAttribute() {},
    getAttribute() { return ''; },
    addEventListener() {},
    querySelectorAll() { return []; },
    appendChild() {},
    getContext() {
      return {
        setTransform() {},
        clearRect() {},
        fillRect() {},
        fillText() {},
        beginPath() {},
        arc() {},
        fill() {},
        moveTo() {},
        lineTo() {},
        stroke() {}
      };
    }
  };

  const sandbox: Record<string, unknown> = {
    URL,
    TextEncoder,
    Uint8Array,
    Math,
    Number,
    String,
    Array,
    JSON,
    Object,
    Promise,
    Error,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    performance: { now: () => 1000 },
    navigator: { hardwareConcurrency: 8, deviceMemory: 8 },
    window: {
      localStorage: {
        getItem: () => null,
        setItem: () => {},
        removeItem: () => {}
      },
      matchMedia: () => ({ matches: false }),
      addEventListener: () => {},
      requestAnimationFrame: () => 1
    },
    document: {
      readyState: 'complete',
      body: { setAttribute() {}, classList: { toggle() {} } },
      documentElement: { style: { setProperty() {} } },
      getElementById: () => stubEl,
      querySelectorAll: () => [],
      addEventListener: () => {},
      createElement: () => stubEl,
      createTextNode: (t: string) => ({ nodeValue: t })
    }
  };
  sandbox.globalThis = sandbox;

  // Evaluate the modified IIFE directly so it returns the module dictionary
  const wrapped = code.replace(/^\s*\(function\s*\(\)\s*\{/, '(function () {');
  return vm.runInNewContext(wrapped, sandbox) as {
    Config: {
      DEFAULT_EXAMPLE_URL: string;
      DEFAULT_TELEGRAM_URL: string;
      getDefaultSettings: (reducedMotion: boolean) => Record<string, any>;
    };
    Validators: {
      validateTelegramUrl: (raw: string) => {
        valid: boolean;
        normalized: string;
        error: string;
        isExample: boolean;
      };
      migrateSettings: (raw: unknown, reducedMotion: boolean) => Record<string, any>;
    };
    ImageTools: {
      detectSignature: (bytes: Uint8Array) => string | null;
    };
    Countdown: {
      CIRCUMFERENCE: number;
      computeDisplay: (remMs: number, totMs: number) => { secondsLeft: number; offset: number };
    };
  };
}

const mods = loadIndexModules();

test('validateTelegramUrl accepts valid channels, invites, and normalizes host/slash', () => {
  const r1 = mods.Validators.validateTelegramUrl('  HTTPS://T.ME/CyberSec_Lab/  ');
  assert.equal(r1.valid, true);
  assert.equal(r1.normalized, 'https://t.me/CyberSec_Lab');
  assert.equal(r1.isExample, false);

  const r2 = mods.Validators.validateTelegramUrl('https://telegram.me/legaltech_hq/42');
  assert.equal(r2.valid, true);
  assert.equal(r2.normalized, 'https://telegram.me/legaltech_hq/42');

  const r3 = mods.Validators.validateTelegramUrl('https://t.me/+AbCdEfGh123456');
  assert.equal(r3.valid, true);
  assert.equal(r3.normalized, 'https://t.me/+AbCdEfGh123456');

  const r4 = mods.Validators.validateTelegramUrl('https://t.me/joinchat/AbCdEfGh123456');
  assert.equal(r4.valid, true);
  assert.equal(r4.normalized, 'https://t.me/joinchat/AbCdEfGh123456');

  const r5 = mods.Validators.validateTelegramUrl('https://t.me/\u200Bcybersec_lab');
  assert.equal(r5.valid, true);
  assert.equal(r5.normalized, 'https://t.me/cybersec_lab');

  const rExample = mods.Validators.validateTelegramUrl('https://t.me/yourchannel');
  assert.equal(rExample.valid, true);
  assert.equal(rExample.isExample, true);

  const rChannel = mods.Validators.validateTelegramUrl('https://t.me/igmaxtcc');
  assert.equal(rChannel.valid, true);
  assert.equal(rChannel.normalized, 'https://t.me/igmaxtcc');
  assert.equal(rChannel.isExample, false);
});

test('validateTelegramUrl blocks unsafe schemes, lookalikes, homographs, ports, and query redirects', () => {
  const cases = [
    '',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'tg://resolve?domain=cybersec',
    'http://t.me/cybersec_lab',
    'https://t.me.evil.com/cybersec_lab',
    'https://t-me.com/cybersec_lab',
    'https://xn--t-me.com/cybersec_lab',
    'https://t.m\u0435/cybersec_lab',
    'https://user:pass@t.me/cybersec_lab',
    'https://t.me:8443/cybersec_lab',
    'https://t.me/cybersec_lab?start=redirect',
    'https://t.me/cybersec_lab#frag',
    'https://t.me/ab',
    'https://t.me/1notstartingwithletter'
  ];

  for (const bad of cases) {
    const res = mods.Validators.validateTelegramUrl(bad);
    assert.equal(res.valid, false, `Expected failure for ${bad}`);
    assert.ok(res.error.length > 0);
  }
});

test('migrateSettings clamps out-of-range values, sanitizes fields, and rejects bad URLs', () => {
  const migrated = mods.Validators.migrateSettings(
    {
      telegramUrl: 'http://evil.example/steal',
      buttonText: '   ',
      buttonColor: 'not-a-color',
      buttonSize: 'giant',
      countdown: 99,
      heading: 'A'.repeat(100),
      background: { zoom: 999, posX: -20, blur: 50, overlayOpacity: 200 },
      style: { neonColor: '#123456', cardBlur: -5, cardOpacity: 10 },
      pinAuth: { salt: 'bad', hash: 'bad' }
    },
    false
  );

  assert.equal(migrated.telegramUrl, mods.Config.DEFAULT_TELEGRAM_URL);
  assert.equal(migrated.buttonText, 'Join Telegram Channel');
  assert.equal(migrated.buttonColor, '#00FF75');
  assert.equal(migrated.buttonSize, 'medium');
  assert.equal(migrated.countdown, 5);
  assert.equal(migrated.heading.length, 60);
  assert.equal(migrated.background.zoom, 300);
  assert.equal(migrated.background.posX, 0);
  assert.equal(migrated.background.blur, 20);
  assert.equal(migrated.background.overlayOpacity, 90);
  assert.equal(migrated.style.neonColor, '#123456');
  assert.equal(migrated.style.cardBlur, 0);
  assert.equal(migrated.style.cardOpacity, 20);
  assert.equal(migrated.pinAuth, null);
});

test('ImageTools.detectSignature validates JPEG, PNG, WebP magic bytes and rejects spoofs', () => {
  const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
  const webp = new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]);
  const spoof = new Uint8Array([0x3c, 0x73, 0x76, 0x67, 0x3e, 0, 0, 0, 0, 0, 0, 0]);

  assert.equal(mods.ImageTools.detectSignature(jpeg), 'jpeg');
  assert.equal(mods.ImageTools.detectSignature(png), 'png');
  assert.equal(mods.ImageTools.detectSignature(webp), 'webp');
  assert.equal(mods.ImageTools.detectSignature(spoof), null);
});

test('Countdown.computeDisplay accurately converts remaining ms to seconds and dashoffset', () => {
  const full = mods.Countdown.computeDisplay(5000, 5000);
  assert.equal(full.secondsLeft, 5);
  assert.ok(Math.abs(full.offset) < 0.01);

  const half = mods.Countdown.computeDisplay(2500, 5000);
  assert.equal(half.secondsLeft, 3);
  assert.ok(Math.abs(half.offset - mods.Countdown.CIRCUMFERENCE * 0.5) < 0.1);

  const done = mods.Countdown.computeDisplay(0, 5000);
  assert.equal(done.secondsLeft, 0);
  assert.ok(Math.abs(done.offset - mods.Countdown.CIRCUMFERENCE) < 0.01);
});
