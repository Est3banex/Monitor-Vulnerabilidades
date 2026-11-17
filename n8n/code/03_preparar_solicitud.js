// Módulo 3 — Preparar la solicitud al Analista IA (nodo Code, modo "Run Once for All Items").
// Se usa en dos nodos: "M3 · Preparar solicitud" (intento 1) y "M3 · Preparar reintento" (intento 2).
// Copia TODO este archivo dentro del nodo Code. Se prueba en local con: npm test
//
// Entrada: items con CVSS y prioridad (M4 · Calcular CVSS y prioridad) o items del validador con reintentar = true.
// Salida:  el mismo item limpio + { intento, solicitudOllama } listo para el nodo HTTP de Ollama.

const CONFIG = {
  modelo: 'phi4-mini',
  // temperature 0: la misma vulnerabilidad debe producir la misma clasificación
  opciones: { temperature: 0 },
};

// Campos de control que agrega este módulo o el validador; no son datos de la vulnerabilidad.
const CAMPOS_CONTROL = ['intento', 'reintentar', 'motivoFallo', 'detalleFallo', 'solicitudOllama'];

class EntradaInvalidaError extends Error {
  constructor(mensaje) {
    super(mensaje);
    this.name = 'EntradaInvalidaError';
  }
}

/**
 * @typedef {Object} Vulnerabilidad
 * @property {string} cveID
 * @property {string} vendor
 * @property {string} product
 * @property {string} name
 * @property {string} description
 * @property {string} dueDate          'YYYY-MM-DD'
 * @property {boolean} ransomware
 * @property {number|null} cvss       de NVD; null si aún no tiene puntaje
 * @property {'alta'|'media'|'baja'|'revisar'} prioridad  decidida por reglas
 */

/** Separa los datos de la vulnerabilidad de los campos de control. */
function datosVulnerabilidad(item) {
  return Object.fromEntries(Object.entries(item).filter(([k]) => !CAMPOS_CONTROL.includes(k)));
}

/** Solo los datos que el modelo necesita: menos texto = respuesta más rápida en CPU. */
function datosParaPrompt(v) {
  const datos = {
    cve: v.cveID,
    fabricante: v.vendor,
    producto: v.product,
    nombre: v.name,
    descripcion: v.description,
    usada_en_ransomware: v.ransomware,
    fecha_limite_cisa: v.dueDate,
  };
  const conCvss = typeof v.cvss === 'number' ? { ...datos, cvss: v.cvss } : datos;
  return { ...conCvss, prioridad: v.prioridad };
}

// La prioridad ya viene decidida por reglas (04_cvss_prioridad.js); el modelo solo redacta.
// Se le entrega para que la urgencia de la acción sea coherente con ella.
function construirPrompt(v) {
  return [
    'Eres un analista de ciberseguridad que asesora al único encargado de sistemas de una clínica pequeña.',
    'Con los datos de la vulnerabilidad, responde SOLO un objeto JSON con exactamente estas claves:',
    '- "resumen": máximo 2 frases en español, explicando qué permite hacer a un atacante.',
    '- "accion": 1 frase completa en español, con un verbo y el nombre del producto, que diga qué hacer y cuándo.',
    // Con la lista de urgencias como palabras sueltas, phi4-mini respondía accion = "revisar" (probado 17-nov-2026)
    'La prioridad ya está decidida; no la cambies ni la menciones. Según la prioridad, el plazo de la acción es:',
    'alta -> hoy mismo; media -> durante esta semana; baja -> en el próximo ciclo de actualizaciones;',
    'revisar -> primero confirmar si el producto está instalado y expuesto a Internet.',
    'Ejemplo de accion (otro producto): "Aplicar durante esta semana el parche de seguridad de Apache Tomcat publicado por el fabricante."',
    'No inventes versiones, parches ni impactos que no estén en los datos.',
    `Datos: ${JSON.stringify(datosParaPrompt(v))}`,
  ].join('\n');
}

/**
 * @param {Object} item  item de entrada (vulnerabilidad, con o sin campos de control)
 * @returns {Object}     vulnerabilidad + { intento, solicitudOllama }
 * @throws {EntradaInvalidaError}
 */
function prepararSolicitud(item, config = CONFIG) {
  if (!item || typeof item.cveID !== 'string' || item.cveID === '') {
    throw new EntradaInvalidaError('Preparar solicitud: el item no tiene un cveID válido');
  }
  const intentoPrevio = Number.isInteger(item.intento) ? item.intento : 0;
  const vulnerabilidad = datosVulnerabilidad(item);

  return {
    ...vulnerabilidad,
    intento: intentoPrevio + 1,
    solicitudOllama: {
      model: config.modelo,
      stream: false,
      format: 'json',
      prompt: construirPrompt(vulnerabilidad),
      options: config.opciones,
    },
  };
}

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  return $input.all().map(item => ({ json: prepararSolicitud(item.json) }));
}
module.exports = { prepararSolicitud, construirPrompt, datosVulnerabilidad, EntradaInvalidaError, CONFIG, CAMPOS_CONTROL };
