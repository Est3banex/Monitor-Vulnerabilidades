// Módulo 2 — Filtro del catálogo CISA KEV (nodo Code de n8n, modo "Run Once for All Items").
// Copia TODO este archivo dentro del nodo Code. El mismo archivo se prueba en local con:
//   npm test
//
// Entrada ($input):       filas de Oracle del nodo "M4 · Leer inventario" -> { vendor }
// Entrada ($(NODO_KEV)):  el JSON completo de CISA KEV -> { count, vulnerabilities: [...] }
// Salida:        0..N items { cveID, vendor, product, name, description, dateAdded, dueDate, ransomware }

const NODO_KEV = 'M1 · Descargar CISA KEV';

const CONFIG = {
  dias: 2, // ventana de dateAdded. Para probar usa 30.
};

class InventarioVacioError extends Error {
  constructor(mensaje) {
    super(mensaje);
    this.name = 'InventarioVacioError';
  }
}

/**
 * Convierte las filas de la tabla INVENTARIO en la lista de fabricantes.
 * Un inventario vacío se trata como error: casi siempre es una tabla sin datos o un fallo de conexión,
 * y filtrar contra nada dejaría el sistema "funcionando" sin avisar de ninguna vulnerabilidad.
 * @param {Array<Object>} filas  filas { vendor }; las que no traen vendor (p. ej. { success: true }) se ignoran
 * @returns {Array<string>}
 * @throws {InventarioVacioError}
 */
function extraerInventario(filas) {
  const vendors = filas
    .map(f => (f && typeof f.vendor === 'string' ? f.vendor.trim() : ''))
    .filter(v => v !== '');
  if (vendors.length === 0) {
    throw new InventarioVacioError('Leer inventario: la tabla INVENTARIO no tiene fabricantes activos');
  }
  return vendors;
}

/**
 * Devuelve 'YYYY-MM-DD' de hace `dias` días respecto a `ahora`.
 * KEV publica dateAdded como 'YYYY-MM-DD', así que se compara como texto (sin líos de zona horaria).
 */
function fechaDesde(dias, ahora = new Date()) {
  const d = new Date(ahora.getTime() - dias * 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 10);
}

function normalizar(texto) {
  return String(texto || '').trim().toLowerCase();
}

/**
 * Filtra el catálogo KEV por fecha e inventario y lo deja en un formato limpio.
 * @param {Array} vulnerabilidades  kev.vulnerabilities
 * @param {Object} opciones         { dias, inventario, ahora }
 */
function filtrarKev(vulnerabilidades, { dias, inventario, ahora } = {}) {
  if (!Array.isArray(vulnerabilidades)) {
    throw new Error('Entrada inválida: se esperaba el arreglo "vulnerabilities" de CISA KEV');
  }
  const desde = fechaDesde(dias, ahora);
  const vendors = new Set(inventario.map(normalizar));

  return vulnerabilidades
    .filter(v => typeof v.dateAdded === 'string' && v.dateAdded >= desde)
    .filter(v => vendors.has(normalizar(v.vendorProject)))
    .map(v => ({
      cveID: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      description: v.shortDescription,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
    }))
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
}

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  // Dentro de n8n
  const kev = $(NODO_KEV).first().json;
  const inventario = extraerInventario($input.all().map(item => item.json));
  const relevantes = filtrarKev(kev.vulnerabilities, { ...CONFIG, inventario });
  return relevantes.map(json => ({ json }));
}
// En Node (tests)
module.exports = { filtrarKev, fechaDesde, extraerInventario, InventarioVacioError, CONFIG };
