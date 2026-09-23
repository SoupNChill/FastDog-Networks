import { Router } from 'express';
import {
  listZones,
  readZone,
  writeZone,
  upsertRecord,
  deleteRecord,
  exportBind,
} from './store.js';

export function dnsRouter() {
  const r = Router();

  r.get('/zones', (_req, res) => {
    res.json({ zones: listZones() });
  });

  r.get('/zones/:zone', (req, res) => {
    const z = readZone(req.params.zone);
    if (!z) return res.status(404).json({ error: 'zone_not_found' });
    res.json(z);
  });

  r.put('/zones/:zone', (req, res) => {
    const body = req.body || {};
    const saved = writeZone(req.params.zone, {
      ttl_default: body.ttl_default || 300,
      records: Array.isArray(body.records) ? body.records : [],
    });
    res.json(saved);
  });

  r.post('/zones/:zone/records', (req, res) => {
    const { name, type, content, ttl, comment } = req.body || {};
    if (!name || !type || content === undefined) {
      return res.status(400).json({ error: 'name, type, content required' });
    }
    const saved = upsertRecord(req.params.zone, { name, type: type.toUpperCase(), content, ttl, comment });
    res.status(201).json(saved);
  });

  r.delete('/zones/:zone/records', (req, res) => {
    try {
      const { name, type, content } = { ...req.query, ...req.body };
      const saved = deleteRecord(req.params.zone, { name, type, content });
      if (!saved) return res.status(404).json({ error: 'zone_not_found' });
      res.json(saved);
    } catch (err) {
      res.status(err.status || 500).json({ error: err.message });
    }
  });

  r.get('/zones/:zone/export.bind', (req, res) => {
    const text = exportBind(req.params.zone);
    if (!text) return res.status(404).json({ error: 'zone_not_found' });
    res.type('text/plain').send(text);
  });

  return r;
}
