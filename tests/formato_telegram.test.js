const test = require('node:test');
const assert = require('node:assert');
const { formatearMensaje, filaOracleAVulnerabilidad } = require('../n8n/code/05_formato_telegram.js');

test('v2 (sin IA): usa la descripción de CISA y marca "revisar"', () => {
  const msg = formatearMensaje({
    cveID: 'CVE-2026-00001', vendor: 'Fortinet', product: 'FortiOS',
    description: 'Desbordamiento de búfer.', dueDate: '2026-12-06', ransomware: true,
  });
  assert.match(msg, /^⚪ PRIORIDAD REVISAR — CVE-2026-00001/);
  assert.match(msg, /CVSS s\/d {2}\| {2}Ransomware: sí/);
  assert.match(msg, /Qué pasa: Desbordamiento de búfer\./);
});

test('v3+: usa resumen, prioridad, acción y CVSS', () => {
  const msg = formatearMensaje({
    cveID: 'CVE-2026-00001', vendor: 'Fortinet', product: 'FortiOS', cvss: 9.8,
    resumen: 'Permite control remoto.', prioridad: 'alta', accion: 'Actualizar hoy.',
    dueDate: '2026-12-06', ransomware: false,
  });
  assert.strictEqual(msg, [
    '🔴 PRIORIDAD ALTA — CVE-2026-00001',
    'Producto: Fortinet FortiOS  |  CVSS 9.8  |  Ransomware: no',
    'Qué pasa: Permite control remoto.',
    'Qué hacer: Actualizar hoy.',
    'Fecha límite CISA: 2026-12-06',
  ].join('\n'));
});

test('fila de Oracle: ransomware S/N se convierte a booleano', () => {
  const v = filaOracleAVulnerabilidad({ cveID: 'CVE-1', ransomware: 'S', cvss: null, prioridad: 'revisar' });
  assert.strictEqual(v.ransomware, true);
  assert.strictEqual(filaOracleAVulnerabilidad({ cveID: 'CVE-1', ransomware: 'N' }).ransomware, false);
});

test('sin pendientes: la fila { success: true } de Oracle no genera mensaje', () => {
  assert.strictEqual(filaOracleAVulnerabilidad({ success: true }), null);
  assert.strictEqual(filaOracleAVulnerabilidad(null), null);
});

test('fila "revisar" sin texto de la IA: usa descripción y acción genérica', () => {
  const msg = formatearMensaje(filaOracleAVulnerabilidad({
    cveID: 'CVE-1', vendor: 'Cisco', product: 'ASA', description: 'Desc CISA.', dueDate: '2026-12-01',
    ransomware: 'N', cvss: null, resumen: null, prioridad: 'revisar', accion: null,
  }));
  assert.match(msg, /^⚪ PRIORIDAD REVISAR — CVE-1/);
  assert.match(msg, /CVSS s\/d {2}\| {2}Ransomware: no/);
  assert.match(msg, /Qué pasa: Desc CISA\./);
});
