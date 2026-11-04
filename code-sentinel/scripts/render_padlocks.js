// Renderiza assets/padlocks/level-N.svg -> level-N.png (fundo transparente).
// Requer Playwright + Chromium. Uso: node scripts/render_padlocks.js [dir] [tamanho]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const dir = process.argv[2] || path.join(__dirname, '..', 'assets', 'padlocks');
  const size = Number(process.argv[3] || 512);
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: size, height: size } });
  for (let lv = 1; lv <= 5; lv++) {
    const svg = fs.readFileSync(path.join(dir, `level-${lv}.svg`), 'utf8')
      .replace('width="512" height="512"', `width="${size}" height="${size}"`);
    await page.setContent(`<html><body style="margin:0;background:transparent">${svg}</body></html>`);
    await page.locator('svg').screenshot({ path: path.join(dir, `level-${lv}.png`), omitBackground: true });
    console.log(`renderizado level-${lv}.png`);
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
