const test = require('node:test');
const assert = require('node:assert');
const { filtrarKev, fechaDesde, CONFIG } = require('../n8n/code/02_filtro_kev.js');
const kev = require('./fixtures/kev_muestra.json');

const AHORA = new Date('2026-11-16T12:00:00Z');

test('fechaDesde resta días y devuelve YYYY-MM-DD', () => {
  assert.strictEqual(fechaDesde(2, AHORA), '2026-11-14');
});

test('filtra por fecha e inventario, ordenado del más reciente', () => {
  const r = filtrarKev(kev.vulnerabilities, { ...CONFIG, dias: 2, ahora: AHORA });
  assert.deepStrictEqual(r.map(v => v.cveID), [
    'CVE-2026-00005', // Cisco (vendor con espacios/mayúsculas)
    'CVE-2026-00001', // Fortinet
    'CVE-2026-00002', // Microsoft (justo en el límite de la ventana)
  ]);
});

test('una ventana más amplia incluye las antiguas', () => {
  const r = filtrarKev(kev.vulnerabilities, { ...CONFIG, dias: 60, ahora: AHORA });
  assert.ok(r.some(v => v.cveID === 'CVE-2025-00004'));
  assert.ok(!r.some(v => v.vendor === 'Ivanti'));
});

test('mapea los campos limpios y el flag de ransomware', () => {
  const [forti] = filtrarKev(kev.vulnerabilities, { ...CONFIG, dias: 2, ahora: AHORA })
    .filter(v => v.vendor === 'Fortinet');
  assert.deepStrictEqual(forti, {
    cveID: 'CVE-2026-00001',
    vendor: 'Fortinet',
    product: 'FortiOS',
    name: 'Fortinet FortiOS Heap-Based Buffer Overflow',
    description: 'FortiOS SSL-VPN contains a heap-based buffer overflow that allows remote code execution.',
    dateAdded: '2026-11-15',
    dueDate: '2026-12-06',
    ransomware: true,
  });
});

test('entrada inválida lanza un error claro', () => {
  assert.throws(() => filtrarKev(undefined, CONFIG), /vulnerabilities/);
});
