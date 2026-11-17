// Módulo 5 — Formato del mensaje de Telegram (nodo Code, modo "Run Once for All Items").
// v4: la entrada son las filas pendientes de Oracle (nodo "M5 · Pendientes de notificar").
// Si la IA no produjo resumen o acción, el mensaje usa la descripción de CISA y una acción genérica.
// El nodo Telegram debe enviar el campo {{ $json.mensaje }} como texto plano (sin parse mode).

const ICONOS = { alta: '🔴', media: '🟠', baja: '🟢', revisar: '⚪' };

function formatearMensaje(v) {
  const prioridad = v.prioridad || 'revisar';
  const icono = ICONOS[prioridad] || ICONOS.revisar;
  const cvss = v.cvss != null ? `CVSS ${v.cvss}` : 'CVSS s/d';
  const ransomware = v.ransomware ? 'sí' : 'no';

  return [
    `${icono} PRIORIDAD ${prioridad.toUpperCase()} — ${v.cveID}`,
    `Producto: ${v.vendor} ${v.product}  |  ${cvss}  |  Ransomware: ${ransomware}`,
    `Qué pasa: ${v.resumen || v.description}`,
    `Qué hacer: ${v.accion || 'Revisar el boletín del fabricante y aplicar la actualización.'}`,
    `Fecha límite CISA: ${v.dueDate}`,
  ].join('\n');
}

/**
 * Convierte una fila de Oracle (alias de sql/02_consultas.sql) al formato que usa formatearMensaje.
 * @param {Object} fila  { cveID, vendor, product, description, dueDate, ransomware: 'S'|'N', cvss, resumen, prioridad, accion }
 * @returns {Object|null}  null si la fila no es una vulnerabilidad (p. ej. { success: true } cuando no hay pendientes)
 */
function filaOracleAVulnerabilidad(fila) {
  if (!fila || typeof fila.cveID !== 'string') return null;
  return { ...fila, ransomware: fila.ransomware === 'S' };
}

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  return $input.all()
    .map(item => filaOracleAVulnerabilidad(item.json))
    .filter(v => v !== null)
    .map(v => ({ json: { ...v, mensaje: formatearMensaje(v) } }));
}
module.exports = { formatearMensaje, filaOracleAVulnerabilidad };
