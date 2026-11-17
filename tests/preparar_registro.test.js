const test = require('node:test');
const assert = require('node:assert');
const { aRegistroOracle, ajustar, RegistroInvalidoError, LIMITES } = require('../n8n/code/04_preparar_registro.js');

const bytes = s => Buffer.byteLength(s, 'utf8');

const VULN = {
  cveID: 'CVE-2026-20320', vendor: 'Cisco', product: 'BroadWorks', name: 'Cisco BroadWorks Info Disclosure',
  description: 'Permite leer configuración.', dateAdded: '2026-11-10', dueDate: '2026-11-24', ransomware: false,
  cvss: 7.5, severidad: 'HIGH', fuenteCvss: 'cvssMetricV31/Secondary', motivoSinCvss: null, prioridad: 'media',
  resumen: 'Un atacante puede leer datos.', accion: 'Actualizar esta semana.', intento: 1, reintentar: false,
};

test('mapea la vulnerabilidad a las columnas del MERGE', () => {
  assert.deepStrictEqual(aRegistroOracle(VULN), {
    cve_id: 'CVE-2026-20320', vendor: 'Cisco', product: 'BroadWorks', nombre: 'Cisco BroadWorks Info Disclosure',
    descripcion: 'Permite leer configuración.', fecha_kev: '2026-11-10', fecha_limite: '2026-11-24',
    ransomware: 'N', cvss: '7.5', severidad: 'HIGH', resumen_es: 'Un atacante puede leer datos.',
    prioridad: 'media', accion: 'Actualizar esta semana.',
  });
});

test('sin CVSS ni texto de la IA: cadenas vacías (NULL en Oracle)', () => {
  const r = aRegistroOracle({ ...VULN, cvss: null, severidad: null, resumen: null, accion: null, prioridad: 'revisar' });
  assert.strictEqual(r.cvss, '');
  assert.strictEqual(r.severidad, '');
  assert.strictEqual(r.resumen_es, '');
  assert.strictEqual(r.accion, '');
  assert.strictEqual(r.prioridad, 'revisar');
});

test('ransomware true -> S; CVSS entero con un decimal', () => {
  const r = aRegistroOracle({ ...VULN, ransomware: true, cvss: 10 });
  assert.strictEqual(r.ransomware, 'S');
  assert.strictEqual(r.cvss, '10.0');
});

test('ajustar cuenta bytes: texto con tildes que cabe en caracteres pero no en bytes', () => {
  const texto = 'á'.repeat(600); // 600 caracteres, 1200 bytes
  const r = ajustar(texto, 1000);
  assert.ok(bytes(r) <= 1000);
  assert.ok(r.endsWith('...'));
});

test('ajustar no corta un emoji (4 bytes) a la mitad', () => {
  const r = ajustar('🔴'.repeat(10), 10); // 40 bytes
  assert.strictEqual(r, '🔴...');
});

test('ajustar deja intacto el texto que cabe exactamente', () => {
  assert.strictEqual(ajustar('x'.repeat(100), 100), 'x'.repeat(100));
});

test('una descripción enorme de CISA se recorta al tamaño de la columna', () => {
  const r = aRegistroOracle({ ...VULN, description: 'ñ'.repeat(5000) });
  assert.ok(bytes(r.descripcion) <= LIMITES.descripcion);
});

const INVALIDOS = [
  ['sin cveID', { ...VULN, cveID: undefined }],
  ['cveID vacío', { ...VULN, cveID: '' }],
  ['cveID más largo que la columna (20)', { ...VULN, cveID: 'CVE-2026-1234567890123' }],
  ['fecha con otro formato', { ...VULN, dueDate: '24/11/2026' }],
  ['fecha ausente', { ...VULN, dateAdded: undefined }],
  ['prioridad fuera del CHECK', { ...VULN, prioridad: 'crítica' }],
  ['cvss fuera de rango', { ...VULN, cvss: 11 }],
  ['cvss como texto', { ...VULN, cvss: '7.5' }],
  ['item nulo', null],
];
for (const [nombre, item] of INVALIDOS) {
  test(`inválido: ${nombre} -> RegistroInvalidoError`, () => {
    assert.throws(() => aRegistroOracle(item), RegistroInvalidoError);
  });
}
