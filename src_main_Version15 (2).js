// Counterfeit Detector - authorized or public use only
import { Actor } from 'apify';
import { CheerioCrawler, PlaywrightCrawler, Dataset, KeyValueStore } from 'crawlee';
import fetch from 'node-fetch';
import imghash from 'imghash';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import cheerio from 'cheerio';

await Actor.init();

const input = (await Actor.getInput()) ?? {};
const {
  startUrls, mode, brandImageKeys, similarityHammingThreshold,
  saveSuspectImages, maxRequestsPerCrawl, concurrency, enqueueGlobs,
  storagePrefix, userAgent
} = input;

const kv = await KeyValueStore.open();
const dataset = await Dataset.open();

const tmpDir = path.join(os.tmpdir(), 'counterfeit-detector');
await fs.mkdir(tmpDir, { recursive: true });

function hexToBinary(hex) {
  return hex.split('').map(h => parseInt(h, 16).toString(2).padStart(4,'0')).join('');
}
function hammingDistanceHex(aHex, bHex) {
  if (!aHex || !bHex) return Number.MAX_SAFE_INTEGER;
  const maxLen = Math.max(aHex.length, bHex.length);
  const a = aHex.padStart(maxLen, '0'), b = bHex.padStart(maxLen, '0');
  const aBits = hexToBinary(a), bBits = hexToBinary(b);
  let diff = 0;
  for (let i=0;i<aBits.length && i<bBits.length;i++) if (aBits[i] !== bBits[i]) diff++;
  return diff;
}
async function saveBufferToTemp(buf, ext='.jpg') {
  const name = crypto.randomBytes(12).toString('hex') + ext;
  const p = path.join(tmpDir, name); await fs.writeFile(p, buf); return p;
}
async function computePHashFromPath(filepath) {
  try { return await imghash.hash(filepath, 16); } catch { return null; }
}
async function downloadImageBuffer(url) {
  try {
    const res = await fetch(url, { redirect: 'follow', timeout: 30000, headers: userAgent ? { 'User-Agent': userAgent } : {} });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return Buffer.from(await res.arrayBuffer());
  } catch { return null; }
}
async function saveSuspectImageToKVS(buffer, pageUrl) {
  try {
    const key = `${storagePrefix}/suspects/${encodeURIComponent(new URL(pageUrl).hostname)}_${Date.now()}.jpg`;
    await kv.setValue(key, buffer, { contentType: 'image/jpeg' }); return key;
  } catch { return null; }
}
async function loadBrandHashes(keys) {
  const brands = [];
  for (const key of keys) {
    try {
      const val = await kv.getValue(key);
      if (!val) continue;
      if (typeof val === 'string') {
        try {
          const obj = JSON.parse(val);
          if (obj && obj.hash) { brands.push({ key, name: obj.name || key, hash: obj.hash }); continue; }
        } catch {}
      }
      let buffer = null;
      if (Buffer.isBuffer(val)) buffer = val;
      else if (typeof val === 'string') buffer = Buffer.from(val, 'binary');
      else if (typeof val === 'object' && val !== null && val.data) buffer = Buffer.from(val.data);
      if (!buffer) continue;
      const tmpPath = await saveBufferToTemp(buffer);
      const phash = await computePHashFromPath(tmpPath);
      await fs.unlink(tmpPath).catch(()=>{});
      brands.push({ key, name: path.basename(key), hash: phash });
    } catch {}
  }
  return brands;
}
async function analyzeImageUrl(imageUrl, pageUrl, brands, options) {
  const buf = await downloadImageBuffer(imageUrl); if (!buf) return null;
  const ext = path.extname(new URL(imageUrl).pathname) || '.jpg';
  const tmpPath = await saveBufferToTemp(buf, ext);
  const hash = await computePHashFromPath(tmpPath);
  await fs.unlink(tmpPath).catch(()=>{});
  if (!hash) return null;
  for (const b of brands) if (b.hash && hammingDistanceHex(b.hash, hash) <= options.threshold)
    return {
      imageUrl, imageHash: hash,
      brandKey: b.key, brandName: b.name, brandHash: b.hash,
      hammingDistance: hammingDistanceHex(b.hash, hash),
      suspectImageKey: options.saveImages ? await saveSuspectImageToKVS(buf, pageUrl) : null
    };
  return null;
}

async function runHttpMode(brands, options) {
  const crawler = new CheerioCrawler({
    maxRequestsPerCrawl: options.maxRequestsPerCrawl,
    async requestHandler({ $, request, enqueueLinks, log }) {
      const pageUrl = request.loadedUrl;
      log.info('Processing', { pageUrl });
      const imgEls = $('img[src]').toArray();
      for (const el of imgEls) {
        let src = $(el).attr('src') || $(el).attr('data-src') || $(el).attr('data-lazy');
        if (!src) continue;
        try { src = new URL(src, pageUrl).href; } catch { continue; }
        const match = await analyzeImageUrl(src, pageUrl, brands, options);
        if (match) {
          const metadata = { title: $('title').first().text().trim() || null };
          await dataset.pushData({ listingUrl: pageUrl, imageUrl: src, brandName: match.brandName, brandKey: match.brandKey, brandHash: match.brandHash, imageHash: match.imageHash, hammingDistance: match.hammingDistance, suspectImageKey: match.suspectImageKey, metadata, timestamp: new Date().toISOString() });
        }
      }
      await enqueueLinks({ globs: options.enqueueGlobs, allowExternal: false }).catch(()=>{});
    }
  });
  await crawler.run(startUrls);
}

async function runBrowserMode(brands, options) {
  const stateKey = `${storagePrefix}/storageState.json`;
  const storageState = await kv.getValue(stateKey);

  const crawler = new PlaywrightCrawler({
    launchContext: { launchOptions: { headless: true, storageState } },
    maxRequestsPerCrawl: options.maxRequestsPerCrawl,
    maxConcurrency: options.concurrency || 2,
    async requestHandler({ page, request, log }) {
      const url = request.loadedUrl || request.url;
      log.info('Visiting', { url });
      try {
        await page.waitForTimeout(1000);
        const content = await page.content();
        const $ = cheerio.load(content);
        const imgs = $('img[src]').toArray();
        for (const el of imgs) {
          let src = $(el).attr('src') || $(el).attr('data-src') || $(el).attr('data-lazy');
          if (!src) continue;
          try { src = new URL(src, url).href; } catch { continue; }
          const match = await analyzeImageUrl(src, url, brands, options);
          if (match) {
            const metadata = { title: $('title').first().text().trim() || null };
            await dataset.pushData({ listingUrl: url, imageUrl: src, brandName: match.brandName, brandKey: match.brandKey, brandHash: match.brandHash, imageHash: match.imageHash, hammingDistance: match.hammingDistance, suspectImageKey: match.suspectImageKey, metadata, timestamp: new Date().toISOString() });
          }
        }
        const anchors = await page.$$eval('a[href]', as => as.map(a => a.getAttribute('href')));
        const abs = anchors.map(h => { try { return new URL(h, url).href; } catch { return null; } }).filter(Boolean);
        await crawler.enqueueLinks({ urls: abs, transformRequestFunction: req => ({ ...req, uniqueKey: req.url }) }).catch(()=>{});
      } catch (e) { log.warning('Page handler error', e.message); }
    }
  });
  await crawler.run(startUrls);
}

try {
  const brands = await loadBrandHashes(brandImageKeys);
  if (brands.length === 0) throw new Error('No brand hashes loaded.');
  const options = {
    threshold: similarityHammingThreshold,
    saveImages: saveSuspectImages,
    maxRequestsPerCrawl,
    concurrency,
    enqueueGlobs
  };
  if (mode === 'http') await runHttpMode(brands, options);
  else await runBrowserMode(brands, options);
  console.log('Finished.');
} catch (err) {
  console.error('Actor failed', err);
  throw err;
} finally {
  await Actor.exit();
}