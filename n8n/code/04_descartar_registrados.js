// Módulo 4 — Descartar las vulnerabilidades que ya están en Oracle (nodo Code, modo "Run Once for All Items").
// Va después del nodo Oracle "M4 · CVE ya registrados". Así NVD y la IA solo trabajan con lo nuevo.
//
// Entrada ($input): filas de Oracle { cveID } (o un único { success: true } si la tabla está vacía).
// Entrada ($(NODO_FILTRO)): las vulnerabilidades relevantes que salieron del filtro (M2).
// Salida:  las vulnerabilidades cuyo cveID no está registrado.

const NODO_FILTRO = 'M2 · Filtrar por fecha e inventario';

/**
 * @param {Array<Object>} vulnerabilidades  items del filtro
 * @param {Array<Object>} filas             filas de Oracle; las que no traen cveID (p. ej. { success: true }) se ignoran
 * @returns {Array<Object>}
 */
function descartarRegistrados(vulnerabilidades, filas) {
  const registrados = new Set(
    filas.filter(f => f && typeof f.cveID === 'string').map(f => f.cveID),
  );
  return vulnerabilidades.filter(v => !registrados.has(v.cveID));
}

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  const vulnerabilidades = $(NODO_FILTRO).all().map(item => item.json);
  const filas = $input.all().map(item => item.json);
  return descartarRegistrados(vulnerabilidades, filas).map(json => ({ json }));
}
module.exports = { descartarRegistrados, NODO_FILTRO };
