// Asset Registry — the websites under protection.
// Enterprise pattern: assets are first-class entities; every scan, finding and
// report links back to an asset. Posture per asset is derived from the event
// store, never stored twice.

import { readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';

function normalizeUrl(raw) {
  try {
    const u = new URL(String(raw).trim());
    if (!/^https?:$/.test(u.protocol)) return null;
    return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`.toLowerCase();
  } catch {
    return null;
  }
}

export class AssetRegistry {
  constructor(dataDir, eventStore) {
    this.dataDir = dataDir;
    this.eventStore = eventStore;
    this.filePath = join(dataDir, 'assets.json');
    this.assets = [];
  }

  async init() {
    if (!existsSync(this.filePath)) return;
    try {
      const raw = await readFile(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      this.assets = Array.isArray(parsed.assets) ? parsed.assets : [];
    } catch (err) {
      console.warn(`[Assets] Failed to load registry: ${err.message}`);
      this.assets = [];
    }
  }

  async _save() {
    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.filePath, JSON.stringify({ assets: this.assets }, null, 2), 'utf-8');
  }

  list() {
    return this.assets.map((a) => this._withDerived(a));
  }

  get(id) {
    const asset = this.assets.find((a) => a.id === id);
    return asset ? this._withDerived(asset) : null;
  }

  findByUrl(url) {
    const norm = normalizeUrl(url);
    if (!norm) return null;
    const asset = this.assets.find((a) => a.url === norm);
    return asset ? this._withDerived(asset) : null;
  }

  async add({ name, url, notes = '' }) {
    const norm = normalizeUrl(url);
    if (!norm) {
      throw new Error('Please enter a valid website URL (http:// or https://).');
    }
    const existing = this.assets.find((a) => a.url === norm);
    if (existing) {
      throw new Error('This website is already registered.');
    }
    const asset = {
      id: `asset-${randomUUID().slice(0, 8)}`,
      name: (name || new URL(norm).host).slice(0, 120),
      url: norm,
      notes: String(notes || '').slice(0, 500),
      tags: [],
      addedAt: Date.now(),
    };
    this.assets.push(asset);
    await this._save();
    this.eventStore.append('asset_added', {
      assetId: asset.id,
      target: asset.url,
      title: `Website added — ${asset.name}`,
    });
    return this._withDerived(asset);
  }

  async update(id, { name, notes, tags } = {}) {
    const asset = this.assets.find((a) => a.id === id);
    if (!asset) return null;
    if (name !== undefined) asset.name = String(name).slice(0, 120);
    if (notes !== undefined) asset.notes = String(notes).slice(0, 500);
    if (tags !== undefined && Array.isArray(tags)) asset.tags = tags.slice(0, 10);
    await this._save();
    this.eventStore.append('asset_updated', {
      assetId: asset.id,
      target: asset.url,
      title: `Website updated — ${asset.name}`,
    });
    return this._withDerived(asset);
  }

  async remove(id) {
    const idx = this.assets.findIndex((a) => a.id === id);
    if (idx === -1) return null;
    const [asset] = this.assets.splice(idx, 1);
    await this._save();
    this.eventStore.append('asset_removed', {
      assetId: asset.id,
      target: asset.url,
      title: `Website removed — ${asset.name}`,
    });
    return asset;
  }

  // Derived view: posture + scan info from the event store.
  _withDerived(asset) {
    const posture = this.eventStore.getAssetPosture(asset.url);
    return {
      ...asset,
      posture,
    };
  }
}
