// Módulo 5 — Formato del mensaje de Telegram (nodo Code, modo "Run Once for All Items").
// v2: se usa SIN IA (resumen = descripción de CISA). En v3/v4 llegan resumen, prioridad, accion y cvss.
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

// ---- Punto de entrada ----
if (typeof $input !== 'undefined') {
  return $input.all().map(item => ({
    json: { ...item.json, mensaje: formatearMensaje(item.json) },
  }));
}
module.exports = { formatearMensaje };
