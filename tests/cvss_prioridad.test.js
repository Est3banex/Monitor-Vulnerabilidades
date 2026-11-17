const test = require('node:test');
const assert = require('node:assert');
const {
  extraerCvss, calcularPrioridad, enriquecerConNvd, MOTIVOS_SIN_CVSS,
} = require('../n8n/code/04_cvss_prioridad.js');
// Respuesta real de NVD (17-nov-2026): solo trae CVSS del fabricante (Secondary) y una métrica SSVC
const nvdReal = require('./fixtures/nvd_cve_2026_20320.json');

const nvd = metrics => ({ totalResults: 1, vulnerabilities: [{ cve: { id: 'CVE-X', metrics } }] });
const v31 = (type, baseScore, baseSeverity = 'HIGH') => ({ source: 's', type, cvssData: { version: '3.1', baseScore, baseSeverity } });

test('respuesta real de NVD: usa el CVSS Secondary e ignora SSVC', () => {
  assert.deepStrictEqual(extraerCvss(nvdReal), { ok: true, cvss: 7.5, severidad: 'HIGH', fuente: 'cvssMetricV31/Secondary' });
});

test('prefiere Primary (NIST) sobre Secondary en la misma versión', () => {
  const r = extraerCvss(nvd({ cvssMetricV31: [v31('Secondary', 7.5), v31('Primary', 9.8, 'CRITICAL')] }));
  assert.deepStrictEqual(r, { ok: true, cvss: 9.8, severidad: 'CRITICAL', fuente: 'cvssMetricV31/Primary' });
});

test('prefiere CVSS 3.1 sobre 4.0 y 2.0', () => {
  const r = extraerCvss(nvd({
    cvssMetricV2: [{ type: 'Primary', baseSeverity: 'LOW', cvssData: { version: '2.0', baseScore: 2 } }],
    cvssMetricV40: [{ type: 'Secondary', cvssData: { version: '4.0', baseScore: 5, baseSeverity: 'MEDIUM' } }],
    cvssMetricV31: [v31('Secondary', 8.1)],
  }));
  assert.strictEqual(r.cvss, 8.1);
});

test('CVSS 2.0 toma la severidad del nivel de la métrica', () => {
  const r = extraerCvss(nvd({ cvssMetricV2: [{ type: 'Primary', baseSeverity: 'HIGH', cvssData: { version: '2.0', baseScore: 7.2 } }] }));
  assert.deepStrictEqual(r, { ok: true, cvss: 7.2, severidad: 'HIGH', fuente: 'cvssMetricV2/Primary' });
});

test('ignora puntajes inválidos y pasa a la siguiente versión', () => {
  const r = extraerCvss(nvd({ cvssMetricV31: [v31('Primary', 11), v31('Secondary', 'alto')], cvssMetricV30: [v31('Primary', 6.1)] }));
  assert.strictEqual(r.cvss, 6.1);
});

const SIN_CVSS = [
  ['error de red o 429 tras los reintentos', { error: 'Request failed with status code 429' }, MOTIVOS_SIN_CVSS.SIN_RESPUESTA],
  ['respuesta nula', null, MOTIVOS_SIN_CVSS.SIN_RESPUESTA],
  ['respuesta sin vulnerabilities', { message: 'x' }, MOTIVOS_SIN_CVSS.SIN_RESPUESTA],
  ['CVE no encontrado (totalResults 0)', { totalResults: 0, vulnerabilities: [] }, MOTIVOS_SIN_CVSS.NO_ENCONTRADO],
  ['CVE sin métricas (recién publicado)', nvd(undefined), MOTIVOS_SIN_CVSS.SIN_METRICAS],
  ['solo métricas que no son CVSS', nvd({ ssvcV203: [{ ssvcData: {} }] }), MOTIVOS_SIN_CVSS.SIN_METRICAS],
  ['listas de CVSS vacías', nvd({ cvssMetricV31: [] }), MOTIVOS_SIN_CVSS.SIN_METRICAS],
];
for (const [nombre, respuesta, motivo] of SIN_CVSS) {
  test(`sin CVSS: ${nombre} -> ${motivo}`, () => {
    const r = extraerCvss(respuesta);
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.motivo, motivo);
    assert.strictEqual(typeof r.detalle, 'string');
  });
}

test('detalle: error como objeto (formato de algunas versiones de n8n) muestra código y mensaje', () => {
  const r = extraerCvss({ error: { httpCode: '404', message: 'The resource you are requesting could not be found' } });
  assert.strictEqual(r.detalle, '404 - The resource you are requesting could not be found');
});

test('detalle: error de Node con solo code (caso real: nombre de header inválido en la credencial)', () => {
  assert.strictEqual(extraerCvss({ error: { code: 'ERR_INVALID_HTTP_TOKEN' } }).detalle, 'ERR_INVALID_HTTP_TOKEN');
});

test('detalle: error como texto se conserva', () => {
  assert.strictEqual(extraerCvss({ error: 'timeout of 30000ms exceeded' }).detalle, 'timeout of 30000ms exceeded');
});

test('detalle: error con formato desconocido o vacío se muestra tal cual (caso real en n8n)', () => {
  assert.strictEqual(extraerCvss({ error: { name: 'NodeApiError', level: 'warning' } }).detalle,
    'error sin mensaje conocido: {"name":"NodeApiError","level":"warning"}');
  assert.strictEqual(extraerCvss({ error: {} }).detalle, 'error sin mensaje conocido: {}');
  assert.strictEqual(extraerCvss({ error: '' }).detalle, 'error sin mensaje: ""');
});

test('detalle: respuesta sin vulnerabilities ni error lista las claves recibidas', () => {
  assert.match(extraerCvss({ message: 'x', status: 403 }).detalle, /claves recibidas: message, status/);
  assert.match(extraerCvss({}).detalle, /claves recibidas: ninguna/);
});

const REGLAS = [
  [{ ransomware: true, cvss: 3.1 }, 'alta'],
  [{ ransomware: true, cvss: null }, 'alta'],
  [{ ransomware: false, cvss: 10 }, 'alta'],
  [{ ransomware: false, cvss: 9.0 }, 'alta'],
  [{ ransomware: false, cvss: 8.9 }, 'media'],
  [{ ransomware: false, cvss: 7.0 }, 'media'],
  [{ ransomware: false, cvss: 6.9 }, 'baja'],
  [{ ransomware: false, cvss: 0 }, 'baja'],
  [{ ransomware: false, cvss: null }, 'revisar'],
];
for (const [datos, esperada] of REGLAS) {
  test(`regla: ransomware=${datos.ransomware}, cvss=${datos.cvss} -> ${esperada}`, () => {
    assert.strictEqual(calcularPrioridad(datos), esperada);
  });
}

test('enriquecerConNvd agrega CVSS y prioridad sin mutar la vulnerabilidad', () => {
  const vuln = { cveID: 'CVE-2026-20320', vendor: 'Cisco', ransomware: false };
  const copia = { ...vuln };
  const r = enriquecerConNvd(vuln, nvdReal);
  assert.deepStrictEqual(r, {
    ...vuln, cvss: 7.5, severidad: 'HIGH', fuenteCvss: 'cvssMetricV31/Secondary', motivoSinCvss: null, prioridad: 'media',
  });
  assert.deepStrictEqual(vuln, copia);
});

test('enriquecerConNvd sin CVSS: prioridad revisar y motivo explicado', () => {
  const r = enriquecerConNvd({ cveID: 'CVE-X', ransomware: false }, { error: 'timeout' });
  assert.strictEqual(r.prioridad, 'revisar');
  assert.strictEqual(r.cvss, null);
  assert.strictEqual(r.motivoSinCvss, 'sin_respuesta: timeout');
});
