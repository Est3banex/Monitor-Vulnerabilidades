const test = require('node:test');
const assert = require('node:assert');
const {
  resolverAnalisis, interpretarRespuesta, EntradaInvalidaError, MOTIVOS,
} = require('../n8n/code/03_validar_analisis.js');

// Vulnerabilidad tal como sale de "M4 · Calcular CVSS y prioridad"
const VULN = {
  cveID: 'CVE-2026-00001', vendor: 'Fortinet', product: 'FortiOS', name: 'n',
  description: 'd', dateAdded: '2026-11-15', dueDate: '2026-12-06', ransomware: true,
  cvss: 9.8, severidad: 'CRITICAL', fuenteCvss: 'cvssMetricV31/Primary', motivoSinCvss: null, prioridad: 'alta',
};
const SOLICITUD_1 = { ...VULN, intento: 1, solicitudOllama: { model: 'phi4-mini' } };
const SOLICITUD_2 = { ...VULN, intento: 2, solicitudOllama: { model: 'phi4-mini' } };
const ollama = obj => ({ model: 'phi4-mini', done: true, response: typeof obj === 'string' ? obj : JSON.stringify(obj) });
const VALIDA = { resumen: 'Permite control remoto.', accion: 'Actualizar FortiOS hoy.' };

test('respuesta válida: agrega resumen y acción, conserva prioridad y CVSS, quita la solicitud', () => {
  const r = resolverAnalisis(SOLICITUD_1, ollama(VALIDA));
  assert.deepStrictEqual(r, { ...VULN, ...VALIDA, intento: 1, reintentar: false });
});

test('recorta espacios del resumen y la acción', () => {
  const r = interpretarRespuesta(ollama({ resumen: '  R. ', accion: ' Aplicar el parche. ' }));
  assert.deepStrictEqual(r, { ok: true, analisis: { resumen: 'R.', accion: 'Aplicar el parche.' } });
});

test('si el modelo devuelve una prioridad, se ignora: manda la de las reglas', () => {
  const r = resolverAnalisis({ ...SOLICITUD_1, prioridad: 'media' }, ollama({ ...VALIDA, prioridad: 'alta' }));
  assert.strictEqual(r.prioridad, 'media');
});

const CASOS_FALLO = [
  ['error de red / timeout (onError: continuar)', { error: 'timeout of 300000ms exceeded' }, MOTIVOS.SIN_RESPUESTA],
  ['respuesta vacía', {}, MOTIVOS.SIN_RESPUESTA],
  ['respuesta nula', null, MOTIVOS.SIN_RESPUESTA],
  ['texto que no es JSON', ollama('Claro, aquí tienes: {resumen'), MOTIVOS.JSON_INVALIDO],
  ['cadena vacía', ollama(''), MOTIVOS.JSON_INVALIDO],
  ['JSON que no es objeto (arreglo)', ollama([VALIDA]), MOTIVOS.JSON_INVALIDO],
  ['JSON null', ollama('null'), MOTIVOS.JSON_INVALIDO],
  ['falta resumen', ollama({ accion: 'a' }), MOTIVOS.CAMPO_FALTANTE],
  ['accion vacía', ollama({ ...VALIDA, accion: '   ' }), MOTIVOS.CAMPO_FALTANTE],
  ['resumen no es texto', ollama({ ...VALIDA, resumen: 5 }), MOTIVOS.CAMPO_FALTANTE],
  ['resumen excede 1000 caracteres', ollama({ ...VALIDA, resumen: 'x'.repeat(1001) }), MOTIVOS.CAMPO_MUY_LARGO],
  ['accion excede 500 caracteres', ollama({ ...VALIDA, accion: 'x'.repeat(501) }), MOTIVOS.CAMPO_MUY_LARGO],
  ['accion de una palabra (caso real: "revisar")', ollama({ ...VALIDA, accion: 'revisar' }), MOTIVOS.ACCION_INCOMPLETA],
  ['accion de dos palabras', ollama({ ...VALIDA, accion: 'Actualizar  hoy' }), MOTIVOS.ACCION_INCOMPLETA],
];

for (const [nombre, respuesta, motivo] of CASOS_FALLO) {
  test(`fallo: ${nombre} -> ${motivo}`, () => {
    const r = interpretarRespuesta(respuesta);
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.motivo, motivo);
    assert.strictEqual(typeof r.detalle, 'string');
  });
}

test('textos en el límite exacto son válidos', () => {
  const accion = `Aplicar el parche ${'y'.repeat(482)}`; // 500 caracteres exactos
  const r = interpretarRespuesta(ollama({ resumen: 'x'.repeat(1000), accion }));
  assert.strictEqual(accion.length, 500);
  assert.strictEqual(r.ok, true);
});

test('primer intento fallido: pide reintento con el motivo y conserva la prioridad', () => {
  const r = resolverAnalisis(SOLICITUD_1, ollama('no es json'));
  assert.strictEqual(r.reintentar, true);
  assert.strictEqual(r.intento, 1);
  assert.strictEqual(r.motivoFallo, MOTIVOS.JSON_INVALIDO);
  assert.strictEqual(r.prioridad, 'alta');
  assert.ok(!('resumen' in r) && !('solicitudOllama' in r));
});

test('segundo intento fallido: sin texto de la IA, pero la prioridad por reglas se mantiene', () => {
  const r = resolverAnalisis(SOLICITUD_2, { error: 'connect ECONNREFUSED' });
  assert.deepStrictEqual(r, {
    ...VULN, intento: 2, reintentar: false, resumen: null, accion: null,
    motivoFallo: MOTIVOS.SIN_RESPUESTA, detalleFallo: 'connect ECONNREFUSED',
  });
});

test('segundo intento válido: análisis normal', () => {
  const r = resolverAnalisis(SOLICITUD_2, ollama(VALIDA));
  assert.strictEqual(r.resumen, VALIDA.resumen);
  assert.strictEqual(r.intento, 2);
  assert.strictEqual(r.reintentar, false);
});

test('reintento conserva los datos aunque la solicitud traiga campos de un fallo anterior', () => {
  const r = resolverAnalisis({ ...SOLICITUD_2, motivoFallo: 'viejo', detalleFallo: 'viejo' }, ollama(VALIDA));
  assert.ok(!('motivoFallo' in r) && !('detalleFallo' in r));
});

test('solicitud sin cveID o intento lanza EntradaInvalidaError', () => {
  assert.throws(() => resolverAnalisis({ cveID: 'CVE-1' }, ollama(VALIDA)), EntradaInvalidaError);
  assert.throws(() => resolverAnalisis(undefined, ollama(VALIDA)), EntradaInvalidaError);
});
