// Módulo 4 — Preparar el registro para Oracle (nodo Code, modo "Run Once for All Items").
// Convierte la vulnerabilidad analizada en los valores que usa el MERGE de "M4 · Guardar en Oracle".
//
// Entrada: la vulnerabilidad después del Analista IA (válida o con resumen/accion null).
// Salida:  { registro: { cve_id, vendor, ..., accion } } con todos los valores como texto;
//          '' representa NULL (Oracle trata la cadena vacía como NULL).

// Tamaños (en bytes) de las columnas de sql/01_tablas.sql
const LIMITES = { vendor: 100, product: 150, nombre: 400, descripcion: 4000, severidad: 20, resumen_es: 1000, accion: 500 };
const PRIORIDADES = ['alta', 'media', 'baja', 'revisar'];
const FECHA = /^\d{4}-\d{2}-\d{2}$/;

class RegistroInvalidoError extends Error {
  constructor(mensaje) {
    super(mensaje);
    this.name = 'RegistroInvalidoError';
  }
}

const SUSPENSIVOS = '...';

function bytesUtf8(caracter) {
  const cp = caracter.codePointAt(0);
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  if (cp < 0x10000) return 3;
  return 4;
}

/**
 * Recorta al tamaño de la columna para que un texto largo no tumbe el guardado (ORA-12899).
 * Cuenta bytes UTF-8, no caracteres: VARCHAR2(n) en Oracle XE mide en bytes y "á" ocupa 2.
 */
function ajustar(valor, limiteBytes) {
  if (valor === null || valor === undefined) return '';
  const caracteres = Array.from(String(valor));
  const total = caracteres.reduce((suma, c) => suma + bytesUtf8(c), 0);
  if (total <= limiteBytes) return caracteres.join('');

  const disponible = limiteBytes - SUSPENSIVOS.length;
  let usados = 0;
  let corte = 0;
  while (corte < caracteres.length && usados + bytesUtf8(caracteres[corte]) <= disponible) {
    usados += bytesUtf8(caracteres[corte]);
    corte += 1;
  }
  return caracteres.slice(0, corte).join('') + SUSPENSIVOS;
}

/**
 * @param {Object} v  vulnerabilidad analizada
 * @returns {Object}  valores para los parámetros del MERGE
 * @throws {RegistroInvalidoError}  si faltan datos que la tabla exige con formato fijo
 */
function aRegistroOracle(v) {
  const cve = v && v.cveID;
  if (typeof cve !== 'string' || cve === '' || cve.length > 20) {
    throw new RegistroInvalidoError(`Preparar registro: cveID inválido (${JSON.stringify(cve)})`);
  }
  if (!FECHA.test(v.dateAdded) || !FECHA.test(v.dueDate)) {
    throw new RegistroInvalidoError(`Preparar registro ${cve}: dateAdded/dueDate deben ser YYYY-MM-DD`);
  }
  if (!PRIORIDADES.includes(v.prioridad)) {
    throw new RegistroInvalidoError(`Preparar registro ${cve}: prioridad inválida (${JSON.stringify(v.prioridad)})`);
  }
  if (v.cvss !== null && (typeof v.cvss !== 'number' || v.cvss < 0 || v.cvss > 10)) {
    throw new RegistroInvalidoError(`Preparar registro ${cve}: cvss fuera de rango (${JSON.stringify(v.cvss)})`);
  }

  return {
    cve_id: cve,
    vendor: ajustar(v.vendor, LIMITES.vendor),
    product: ajustar(v.product, LIMITES.product),
    nombre: ajustar(v.name, LIMITES.nombre),
    descripcion: ajustar(v.description, LIMITES.descripcion),
    fecha_kev: v.dateAdded,
    fecha_limite: v.dueDate,
    ransomware: v.ransomware === true ? 'S' : 'N',
    // Punto decimal fijo: el MERGE lo convierte con TO_NUMBER(..., NLS_NUMERIC_CHARACTERS = '.,')
    cvss: v.cvss === null ? '' : v.cvss.toFixed(1),
    severidad: ajustar(v.severidad, LIMITES.severidad),
    resumen_es: ajustar(v.resumen, LIMITES.resumen_es),
    prioridad: v.prioridad,
    accion: ajustar(v.accion, LIMITES.accion),
  };
}

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  return $input.all().map(item => ({ json: { ...item.json, registro: aRegistroOracle(item.json) } }));
}
module.exports = { aRegistroOracle, ajustar, RegistroInvalidoError, LIMITES };
