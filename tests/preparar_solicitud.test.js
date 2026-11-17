const test = require('node:test');
const assert = require('node:assert');
const { prepararSolicitud, EntradaInvalidaError, CONFIG } = require('../n8n/code/03_preparar_solicitud.js');

const VULN = {
  cveID: 'CVE-2026-00001', vendor: 'Fortinet', product: 'FortiOS',
  name: 'Fortinet FortiOS Heap-Based Buffer Overflow',
  description: 'FortiOS SSL-VPN allows remote code execution.',
  dateAdded: '2026-11-15', dueDate: '2026-12-06', ransomware: true,
  cvss: null, severidad: null, fuenteCvss: null, motivoSinCvss: 'sin_metricas: x', prioridad: 'alta',
};

test('primer intento: agrega intento 1 y la solicitud para Ollama', () => {
  const r = prepararSolicitud(VULN);
  assert.strictEqual(r.intento, 1);
  assert.strictEqual(r.cveID, VULN.cveID);
  assert.deepStrictEqual(
    { ...r.solicitudOllama, prompt: undefined },
    { model: CONFIG.modelo, stream: false, format: 'json', prompt: undefined, options: { temperature: 0 } },
  );
  assert.match(r.solicitudOllama.prompt, /"cve":"CVE-2026-00001"/);
  assert.match(r.solicitudOllama.prompt, /"usada_en_ransomware":true/);
});

test('el prompt solo incluye CVSS cuando existe', () => {
  assert.doesNotMatch(prepararSolicitud(VULN).solicitudOllama.prompt, /"cvss"/);
  assert.match(prepararSolicitud({ ...VULN, cvss: 9.8 }).solicitudOllama.prompt, /"cvss":9\.8/);
});

test('el prompt entrega la prioridad decidida por reglas y no pide clasificar', () => {
  const prompt = prepararSolicitud({ ...VULN, prioridad: 'media' }).solicitudOllama.prompt;
  assert.match(prompt, /"prioridad":"media"/);
  assert.match(prompt, /La prioridad ya está decidida/);
  assert.doesNotMatch(prompt, /- "prioridad":/);
});

test('el prompt no filtra datos internos (motivo sin CVSS, fuente)', () => {
  assert.doesNotMatch(prepararSolicitud(VULN).solicitudOllama.prompt, /sin_metricas|fuenteCvss/);
});

test('reintento: sube el intento y descarta los campos de control del validador', () => {
  const desdeValidador = { ...VULN, intento: 1, reintentar: true, motivoFallo: 'json_invalido', detalleFallo: 'x' };
  const r = prepararSolicitud(desdeValidador);
  assert.strictEqual(r.intento, 2);
  assert.ok(!('reintentar' in r) && !('motivoFallo' in r) && !('detalleFallo' in r));
  assert.doesNotMatch(r.solicitudOllama.prompt, /json_invalido/);
});

test('no modifica el item de entrada', () => {
  const entrada = { ...VULN };
  prepararSolicitud(entrada);
  assert.deepStrictEqual(entrada, VULN);
});

test('item sin cveID lanza EntradaInvalidaError', () => {
  assert.throws(() => prepararSolicitud({}), EntradaInvalidaError);
  assert.throws(() => prepararSolicitud(null), EntradaInvalidaError);
  assert.throws(() => prepararSolicitud({ ...VULN, cveID: '' }), EntradaInvalidaError);
});
