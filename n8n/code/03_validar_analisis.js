// Módulo 3 — Validar la respuesta del Analista IA (nodo Code, modo "Run Once for All Items").
// Se usa en dos nodos: "M3 · Validar análisis" (intento 1) y "M3 · Validar reintento" (intento 2).
// Copia TODO este archivo dentro del nodo Code y ajusta NODO_SOLICITUD al nombre del nodo
// "Preparar ..." que va justo antes del HTTP de Ollama (scripts/construir_workflow.js lo hace solo).
//
// Entrada: la respuesta del nodo HTTP de Ollama ({ response: "<texto JSON>" } o { error: "..." }).
// Salida:  la vulnerabilidad (con su prioridad por reglas intacta) + una de estas tres formas:
//   - válida:     { resumen, accion, reintentar: false }
//   - reintentar: { reintentar: true, motivoFallo, detalleFallo }                   (si quedan intentos)
//   - sin texto:  { resumen: null, accion: null, reintentar: false, motivoFallo, detalleFallo }
// Que la IA falle no cambia la prioridad: una vulnerabilidad "alta" debe avisarse aunque no haya resumen.

const NODO_SOLICITUD = 'M3 · Preparar solicitud';
const MAX_INTENTOS = 2;
// Coinciden con las columnas resumen_es VARCHAR2(1000) y accion VARCHAR2(500) de Oracle (v4)
const LIMITES = { resumen: 1000, accion: 500 };

const MOTIVOS = {
  SIN_RESPUESTA: 'sin_respuesta',
  JSON_INVALIDO: 'json_invalido',
  CAMPO_FALTANTE: 'campo_faltante',
  CAMPO_MUY_LARGO: 'campo_muy_largo',
  ACCION_INCOMPLETA: 'accion_incompleta',
};

// Una acción de 1-2 palabras (p. ej. "revisar", visto con phi4-mini) no es ejecutable por el encargado.
const MIN_PALABRAS_ACCION = 3;

// Duplicado de 03_preparar_solicitud.js: cada nodo Code de n8n es independiente y no puede importar otro.
const CAMPOS_CONTROL = ['intento', 'reintentar', 'motivoFallo', 'detalleFallo', 'solicitudOllama'];

class EntradaInvalidaError extends Error {
  constructor(mensaje) {
    super(mensaje);
    this.name = 'EntradaInvalidaError';
  }
}

function datosVulnerabilidad(item) {
  return Object.fromEntries(Object.entries(item).filter(([k]) => !CAMPOS_CONTROL.includes(k)));
}

function fallo(motivo, detalle) {
  return { ok: false, motivo, detalle };
}

function textoLimpio(valor) {
  return typeof valor === 'string' ? valor.trim() : '';
}

/**
 * Interpreta la respuesta cruda de Ollama.
 * @param {Object} respuestaOllama  json del nodo HTTP: { response: string } o { error: string }
 * @returns {{ok: true, analisis: {resumen: string, accion: string}}
 *         | {ok: false, motivo: string, detalle: string}}
 */
function interpretarRespuesta(respuestaOllama) {
  if (!respuestaOllama || typeof respuestaOllama.response !== 'string') {
    const detalle = textoLimpio(respuestaOllama && respuestaOllama.error) || 'la respuesta no trae el campo "response"';
    return fallo(MOTIVOS.SIN_RESPUESTA, detalle);
  }

  let datos;
  try {
    datos = JSON.parse(respuestaOllama.response);
  } catch (error) {
    return fallo(MOTIVOS.JSON_INVALIDO, error.message);
  }
  if (datos === null || typeof datos !== 'object' || Array.isArray(datos)) {
    return fallo(MOTIVOS.JSON_INVALIDO, 'se esperaba un objeto JSON');
  }

  const resumen = textoLimpio(datos.resumen);
  const accion = textoLimpio(datos.accion);
  if (resumen === '' || accion === '') {
    return fallo(MOTIVOS.CAMPO_FALTANTE, 'faltan "resumen" o "accion"');
  }
  if (resumen.length > LIMITES.resumen || accion.length > LIMITES.accion) {
    return fallo(MOTIVOS.CAMPO_MUY_LARGO, `resumen ${resumen.length}/${LIMITES.resumen}, accion ${accion.length}/${LIMITES.accion}`);
  }
  const palabras = accion.split(/\s+/).length;
  if (palabras < MIN_PALABRAS_ACCION) {
    return fallo(MOTIVOS.ACCION_INCOMPLETA, `accion con ${palabras} palabra(s): ${JSON.stringify(accion)}`);
  }

  return { ok: true, analisis: { resumen, accion } };
}

/**
 * Decide el resultado final del item: análisis válido, reintento o sin texto de la IA.
 * @param {Object} solicitud        item que salió del nodo "Preparar ..." (vulnerabilidad + intento)
 * @param {Object} respuestaOllama  item que salió del nodo HTTP de Ollama
 * @throws {EntradaInvalidaError}
 */
function resolverAnalisis(solicitud, respuestaOllama, maxIntentos = MAX_INTENTOS) {
  if (!solicitud || typeof solicitud.cveID !== 'string' || !Number.isInteger(solicitud.intento)) {
    throw new EntradaInvalidaError('Validar análisis: la solicitud original no tiene cveID o intento');
  }
  const vulnerabilidad = datosVulnerabilidad(solicitud);
  const { intento } = solicitud;
  const resultado = interpretarRespuesta(respuestaOllama);

  if (resultado.ok) {
    return { ...vulnerabilidad, ...resultado.analisis, intento, reintentar: false };
  }
  const diagnostico = { motivoFallo: resultado.motivo, detalleFallo: resultado.detalle };
  if (intento < maxIntentos) {
    return { ...vulnerabilidad, intento, reintentar: true, ...diagnostico };
  }
  return { ...vulnerabilidad, intento, reintentar: false, resumen: null, accion: null, ...diagnostico };
}

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  // El nodo HTTP reemplaza el item por la respuesta; la vulnerabilidad se recupera del nodo que preparó la solicitud.
  return $input.all().map((item, i) => ({
    json: resolverAnalisis($(NODO_SOLICITUD).itemMatching(i).json, item.json),
  }));
}
module.exports = { resolverAnalisis, interpretarRespuesta, EntradaInvalidaError, MOTIVOS, MAX_INTENTOS, NODO_SOLICITUD };
