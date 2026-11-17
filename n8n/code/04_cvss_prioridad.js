// Módulo 4 — CVSS de NVD y prioridad por reglas (nodo Code, modo "Run Once for All Items").
// Va justo después del nodo HTTP que consulta NVD. Copia TODO este archivo dentro del nodo Code.
//
// Entrada: la respuesta de NVD por cada CVE ({ totalResults, vulnerabilities } o { error }).
// Salida:  la vulnerabilidad + { cvss, severidad, fuenteCvss, motivoSinCvss, prioridad }.
//
// La prioridad la deciden reglas fijas, no la IA: un modelo de 3-4B sobrestimaba la urgencia
// (ver prompts/analista.md). La IA solo redacta el resumen y la acción.

const NODO_ORIGEN = 'M4 · Descartar ya registrados';

// Orden de preferencia de versiones de CVSS presentes en NVD 2.0. Otras métricas (p. ej. ssvcV203) se ignoran.
const VERSIONES_CVSS = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2'];

const MOTIVOS_SIN_CVSS = {
  SIN_RESPUESTA: 'sin_respuesta',
  NO_ENCONTRADO: 'no_encontrado',
  SIN_METRICAS: 'sin_metricas',
};

const UMBRALES = { alta: 9, media: 7 };

/**
 * @typedef {'alta'|'media'|'baja'|'revisar'} Prioridad
 * @typedef {{ok: true, cvss: number, severidad: string|null, fuente: string}
 *         | {ok: false, motivo: string, detalle: string}} ResultadoCvss
 */

function puntajeValido(valor) {
  return typeof valor === 'number' && Number.isFinite(valor) && valor >= 0 && valor <= 10;
}

/** Primary (NIST) primero; si no hay, Secondary (el fabricante), que es lo habitual en CVE recientes. */
function mejorMetrica(metricas) {
  const validas = metricas.filter(m => m && m.cvssData && puntajeValido(m.cvssData.baseScore));
  return validas.find(m => m.type === 'Primary') || validas[0] || null;
}

/**
 * @param {Object} respuestaNvd  json del nodo HTTP de NVD
 * @returns {ResultadoCvss}
 */
/**
 * Describe una respuesta inesperada de NVD. Según la versión de n8n, el error del nodo HTTP llega
 * como texto ({ error: '...' }) o como objeto ({ error: { message, httpCode } }).
 */
function describirRespuesta(respuesta) {
  if (!respuesta || typeof respuesta !== 'object') return `respuesta vacía (${JSON.stringify(respuesta)})`;
  const { error } = respuesta;
  if (typeof error === 'string' && error !== '') return error;
  if (error && typeof error === 'object') {
    // code: errores de Node antes de enviar la solicitud (p. ej. ERR_INVALID_HTTP_TOKEN = nombre de header inválido)
    const partes = [error.httpCode, error.code, error.message, error.description].filter(p => p !== undefined && p !== '');
    if (partes.length > 0) return partes.join(' - ');
    // Formato desconocido: se muestra tal cual (recortado) para poder diagnosticarlo en n8n
    return `error sin mensaje conocido: ${JSON.stringify(error).slice(0, 300)}`;
  }
  if (error !== undefined) return `error sin mensaje: ${JSON.stringify(error)}`;
  return `la respuesta no trae "vulnerabilities"; claves recibidas: ${Object.keys(respuesta).slice(0, 8).join(', ') || 'ninguna'}`;
}

function extraerCvss(respuestaNvd) {
  if (!respuestaNvd || !Array.isArray(respuestaNvd.vulnerabilities)) {
    return { ok: false, motivo: MOTIVOS_SIN_CVSS.SIN_RESPUESTA, detalle: describirRespuesta(respuestaNvd) };
  }
  const cve = respuestaNvd.vulnerabilities[0] && respuestaNvd.vulnerabilities[0].cve;
  if (!cve) {
    return { ok: false, motivo: MOTIVOS_SIN_CVSS.NO_ENCONTRADO, detalle: 'NVD no tiene registro del CVE' };
  }

  const metricas = cve.metrics || {};
  for (const version of VERSIONES_CVSS) {
    const elegida = Array.isArray(metricas[version]) ? mejorMetrica(metricas[version]) : null;
    if (elegida) {
      const severidad = elegida.cvssData.baseSeverity || elegida.baseSeverity || null;
      return { ok: true, cvss: elegida.cvssData.baseScore, severidad, fuente: `${version}/${elegida.type || 's/d'}` };
    }
  }
  return { ok: false, motivo: MOTIVOS_SIN_CVSS.SIN_METRICAS, detalle: 'NVD aún no publica un puntaje CVSS' };
}

/**
 * Reglas: ransomware o CVSS >= 9 -> alta; 7 a 8.9 -> media; < 7 -> baja; sin CVSS -> revisar.
 * @param {{ransomware: boolean, cvss: number|null}} datos
 * @returns {Prioridad}
 */
function calcularPrioridad({ ransomware, cvss }) {
  if (ransomware === true) return 'alta';
  if (cvss === null) return 'revisar';
  if (cvss >= UMBRALES.alta) return 'alta';
  if (cvss >= UMBRALES.media) return 'media';
  return 'baja';
}

/**
 * @param {Object} vulnerabilidad  item del filtro (M2) ya sin los registrados
 * @param {Object} respuestaNvd
 */
function enriquecerConNvd(vulnerabilidad, respuestaNvd) {
  const resultado = extraerCvss(respuestaNvd);
  const cvss = resultado.ok ? resultado.cvss : null;
  return {
    ...vulnerabilidad,
    cvss,
    severidad: resultado.ok ? resultado.severidad : null,
    fuenteCvss: resultado.ok ? resultado.fuente : null,
    motivoSinCvss: resultado.ok ? null : `${resultado.motivo}: ${resultado.detalle}`,
    prioridad: calcularPrioridad({ ransomware: vulnerabilidad.ransomware, cvss }),
  };
}

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  // El nodo HTTP reemplaza el item por la respuesta de NVD; la vulnerabilidad se recupera del nodo anterior.
  return $input.all().map((item, i) => ({
    json: enriquecerConNvd($(NODO_ORIGEN).itemMatching(i).json, item.json),
  }));
}
module.exports = { extraerCvss, calcularPrioridad, enriquecerConNvd, MOTIVOS_SIN_CVSS, NODO_ORIGEN };
