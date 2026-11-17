const test = require('node:test');
const assert = require('node:assert');
const { descartarRegistrados } = require('../n8n/code/04_descartar_registrados.js');

const VULNS = [{ cveID: 'CVE-1' }, { cveID: 'CVE-2' }, { cveID: 'CVE-3' }];

test('descarta los CVE que ya están en Oracle', () => {
  assert.deepStrictEqual(descartarRegistrados(VULNS, [{ cveID: 'CVE-2' }]), [{ cveID: 'CVE-1' }, { cveID: 'CVE-3' }]);
});

test('tabla vacía: Oracle devuelve { success: true } y pasan todas', () => {
  assert.deepStrictEqual(descartarRegistrados(VULNS, [{ success: true }]), VULNS);
});

test('todas registradas: no queda nada (el flujo se detiene sin avisos repetidos)', () => {
  assert.deepStrictEqual(descartarRegistrados(VULNS, VULNS), []);
});

test('sin vulnerabilidades de entrada: lista vacía', () => {
  assert.deepStrictEqual(descartarRegistrados([], [{ cveID: 'CVE-1' }]), []);
});

test('ignora filas sin cveID válido', () => {
  assert.deepStrictEqual(descartarRegistrados(VULNS, [null, { cveID: 2 }, {}]), VULNS);
});
