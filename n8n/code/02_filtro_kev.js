// Módulo 2 — Filtro del catálogo CISA KEV (nodo Code de n8n, modo "Run Once for All Items").
// Copia TODO este archivo dentro del nodo Code. El mismo archivo se prueba en local con:
//   npm test
//
// Entrada (n8n): el JSON completo de CISA KEV  -> { count, vulnerabilities: [...] }
// Salida:        0..N items { cveID, vendor, product, name, description, dateAdded, dueDate, ransomware }

// ---- Configuración (v1: fija; v4: el inventario se leerá de la tabla INVENTARIO de Oracle) ----
const CONFIG = {
  dias: 2, // ventana de dateAdded. Para probar usa 30.
  inventario: ['microsoft', 'fortinet', 'apache', 'cisco'],
};

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
  const kev = $input.first().json;
  const relevantes = filtrarKev(kev.vulnerabilities, CONFIG);
  return relevantes.map(json => ({ json }));
}
// En Node (tests)
module.exports = { filtrarKev, fechaDesde, CONFIG };
