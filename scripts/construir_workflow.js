// Genera workflows/monitor_vulnerabilidades.json incrustando el código de n8n/code/*.js y las
// consultas de sql/n8n/*.sql, para que el workflow importable y lo probado nunca se desincronicen.
//   node scripts/construir_workflow.js
//
// Las credenciales (Oracle, NVD, Telegram) y el chat_id NO van aquí: se eligen en n8n tras importar.
const fs = require('node:fs');
const path = require('node:path');

const raiz = path.join(__dirname, '..');
const codigo = f => fs.readFileSync(path.join(raiz, 'n8n', 'code', f), 'utf8');
const sql = f => fs.readFileSync(path.join(raiz, 'sql', 'n8n', f), 'utf8').trim();

const OLLAMA_URL = 'http://192.168.56.1:11434/api/generate';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const N = {
  manual: 'Disparo manual',
  horario: 'Todos los días 7:00',
  kev: 'M1 · Descargar CISA KEV',
  inventario: 'M4 · Leer inventario',
  filtro: 'M2 · Filtrar por fecha e inventario',
  registrados: 'M4 · CVE ya registrados',
  descartar: 'M4 · Descartar ya registrados',
  nvd: 'M4 · Consultar NVD',
  prioridad: 'M4 · Calcular CVSS y prioridad',
  preparar: 'M3 · Preparar solicitud',
  ollama: 'M3 · Consultar Ollama',
  validar: 'M3 · Validar análisis',
  reintentar: '¿Reintentar?',
  prepararReintento: 'M3 · Preparar reintento',
  ollamaReintento: 'M3 · Consultar Ollama (reintento)',
  validarReintento: 'M3 · Validar reintento',
  registro: 'M4 · Preparar registro',
  guardar: 'M4 · Guardar en Oracle',
  pendientes: 'M5 · Pendientes de notificar',
  formato: 'M5 · Formatear mensaje',
  telegram: 'M5 · Enviar a Telegram',
  marcar: 'M5 · Marcar notificado',
};

// Cada archivo de n8n/code declara el nombre del nodo del que lee; si se renombra un nodo aquí,
// el build falla en lugar de generar un workflow que se rompe al ejecutarse.
function codigoConReferencia(archivo, constante, nodoEsperado, nodoReal = nodoEsperado) {
  const fuente = codigo(archivo);
  const declaracion = `const ${constante} = '${nodoEsperado}';`;
  if (!fuente.includes(declaracion)) {
    throw new Error(`construir_workflow: no se encontró "${declaracion}" en ${archivo}`);
  }
  return fuente.replace(declaracion, `const ${constante} = '${nodoReal}';`);
}

function nodoCodigo(id, name, position, jsCode) {
  return { id, name, type: 'n8n-nodes-base.code', typeVersion: 2, position, parameters: { jsCode } };
}

// Ollama en CPU tarda ~10-30 s por vulnerabilidad; 300 s deja margen para respuestas largas.
// onError continueRegularOutput: un timeout o conexión rechazada llega al validador como { error },
// que lo convierte en reintento o en "sin texto de la IA" en lugar de detener todo el flujo.
function nodoOllama(id, name, position) {
  return {
    id, name, type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position,
    onError: 'continueRegularOutput',
    parameters: {
      method: 'POST',
      url: OLLAMA_URL,
      sendBody: true,
      contentType: 'json',
      specifyBody: 'json',
      jsonBody: '={{ $json.solicitudOllama }}',
      options: { timeout: 300000 },
    },
  };
}

/**
 * Nodo Oracle Database (operación "Execute SQL").
 * @param {Object} opciones
 * @param {boolean} [opciones.unaVez]  executeOnce: la consulta no depende del item y debe correr una sola vez
 * @param {Array<[string, string]>} [opciones.parametros]  [nombre, expresión]; siempre como texto (bind variables)
 */
function nodoOracle(id, name, position, consulta, { unaVez = false, parametros = [] } = {}) {
  const nodo = {
    id, name, type: 'n8n-nodes-base.oracleDatabase', typeVersion: 1, position,
    parameters: {
      operation: 'execute',
      query: consulta,
      options: parametros.length === 0 ? {} : {
        params: {
          values: parametros.map(([nombre, valor]) => ({ name: nombre, datatype: 'string', valueString: valor })),
        },
      },
    },
  };
  return unaVez ? { ...nodo, executeOnce: true } : nodo;
}

const COLUMNAS_REGISTRO = [
  'cve_id', 'vendor', 'product', 'nombre', 'descripcion', 'fecha_kev', 'fecha_limite',
  'ransomware', 'cvss', 'severidad', 'resumen_es', 'prioridad', 'accion',
];

const workflow = {
  name: 'Monitor de vulnerabilidades',
  nodes: [
    { id: 'manual', name: N.manual, type: 'n8n-nodes-base.manualTrigger', typeVersion: 1,
      position: [0, 0], parameters: {} },
    { id: 'horario', name: N.horario, type: 'n8n-nodes-base.scheduleTrigger', typeVersion: 1.2,
      position: [0, 200],
      parameters: { rule: { interval: [{ field: 'cronExpression', expression: '0 7 * * *' }] } } },
    { id: 'kev', name: N.kev, type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2,
      position: [240, 100],
      parameters: {
        url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        options: { timeout: 60000 },
      } },
    nodoOracle('inventario', N.inventario, [480, 100], sql('leer_inventario.sql'), { unaVez: true }),
    nodoCodigo('filtro', N.filtro, [720, 100], codigoConReferencia('02_filtro_kev.js', 'NODO_KEV', N.kev)),
    nodoOracle('registrados', N.registrados, [960, 100], sql('cve_registrados.sql'), { unaVez: true }),
    nodoCodigo('descartar', N.descartar, [1200, 100],
      codigoConReferencia('04_descartar_registrados.js', 'NODO_FILTRO', N.filtro)),
    {
      id: 'nvd', name: N.nvd, type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position: [1440, 100],
      // 429 de NVD: hasta 3 intentos separados 6 s; si aun así falla, sigue con { error } y la prioridad queda "revisar"
      retryOnFail: true, maxTries: 3, waitBetweenTries: 6000,
      onError: 'continueRegularOutput',
      parameters: {
        url: NVD_URL,
        authentication: 'genericCredentialType',
        genericAuthType: 'httpHeaderAuth',
        sendQuery: true,
        queryParameters: { parameters: [{ name: 'cveId', value: '={{ $json.cveID }}' }] },
        // Con API key NVD permite 50 solicitudes / 30 s: una cada 700 ms queda por debajo del límite
        options: { timeout: 30000, batching: { batch: { batchSize: 1, batchInterval: 700 } } },
      },
    },
    nodoCodigo('prioridad', N.prioridad, [1680, 100],
      codigoConReferencia('04_cvss_prioridad.js', 'NODO_ORIGEN', N.descartar)),
    nodoCodigo('preparar', N.preparar, [1920, 100], codigo('03_preparar_solicitud.js')),
    nodoOllama('ollama', N.ollama, [2160, 100]),
    nodoCodigo('validar', N.validar, [2400, 100],
      codigoConReferencia('03_validar_analisis.js', 'NODO_SOLICITUD', N.preparar)),
    { id: 'reintentar', name: N.reintentar, type: 'n8n-nodes-base.if', typeVersion: 2.2,
      position: [2640, 100],
      parameters: {
        conditions: {
          options: { caseSensitive: true, leftValue: '', typeValidation: 'strict', version: 2 },
          conditions: [{
            id: 'reintentar-true',
            leftValue: '={{ $json.reintentar }}',
            rightValue: '',
            operator: { type: 'boolean', operation: 'true', singleValue: true },
          }],
          combinator: 'and',
        },
        options: {},
      } },
    nodoCodigo('preparar-reintento', N.prepararReintento, [2880, 0], codigo('03_preparar_solicitud.js')),
    nodoOllama('ollama-reintento', N.ollamaReintento, [3120, 0]),
    nodoCodigo('validar-reintento', N.validarReintento, [3360, 0],
      codigoConReferencia('03_validar_analisis.js', 'NODO_SOLICITUD', N.preparar, N.prepararReintento)),
    nodoCodigo('registro', N.registro, [3600, 200], codigo('04_preparar_registro.js')),
    nodoOracle('guardar', N.guardar, [3840, 200], sql('guardar_vulnerabilidad.sql'), {
      parametros: COLUMNAS_REGISTRO.map(c => [c, `={{ $json.registro.${c} }}`]),
    }),
    // Rama de aviso: va DEBAJO de la rama principal (y = 500) porque con executionOrder v1 n8n ejecuta
    // primero la rama de más arriba completa; así se notifica después de guardar lo nuevo.
    nodoOracle('pendientes', N.pendientes, [480, 500], sql('pendientes_notificar.sql'), { unaVez: true }),
    nodoCodigo('formato', N.formato, [720, 500], codigo('05_formato_telegram.js')),
    { id: 'telegram', name: N.telegram, type: 'n8n-nodes-base.telegram', typeVersion: 1.2,
      position: [960, 500],
      parameters: { chatId: '', text: '={{ $json.mensaje }}', additionalFields: { appendAttribution: false } } },
    // Se marca después de enviar: si Telegram falla, la alerta sigue pendiente y se reintenta en la próxima ejecución
    nodoOracle('marcar', N.marcar, [1200, 500], sql('marcar_notificado.sql'), {
      parametros: [['cve_id', `={{ $('${N.formato}').item.json.cveID }}`]],
    }),
  ],
  connections: {},
  settings: { executionOrder: 'v1', timezone: 'America/Bogota' },
  pinData: {},
};

const conectar = (origen, ...destinosPorSalida) => {
  workflow.connections[origen] = {
    main: destinosPorSalida.map(destino => [{ node: destino, type: 'main', index: 0 }]),
  };
};
conectar(N.manual, N.kev);
conectar(N.horario, N.kev);
// La rama de aviso sale del recolector y no del guardado: así corre en cada ejecución, aunque no haya
// vulnerabilidades nuevas, y reenvía las alertas cuyo envío a Telegram falló antes.
workflow.connections[N.kev] = {
  main: [[N.inventario, N.pendientes].map(destino => ({ node: destino, type: 'main', index: 0 }))],
};
conectar(N.inventario, N.filtro);
conectar(N.filtro, N.registrados);
conectar(N.registrados, N.descartar);
conectar(N.descartar, N.nvd);
conectar(N.nvd, N.prioridad);
conectar(N.prioridad, N.preparar);
conectar(N.preparar, N.ollama);
conectar(N.ollama, N.validar);
conectar(N.validar, N.reintentar);
// Salida 0 (true) -> reintento; salida 1 (false) -> análisis listo para guardar
conectar(N.reintentar, N.prepararReintento, N.registro);
conectar(N.prepararReintento, N.ollamaReintento);
conectar(N.ollamaReintento, N.validarReintento);
conectar(N.validarReintento, N.registro);
conectar(N.registro, N.guardar);
conectar(N.pendientes, N.formato);
conectar(N.formato, N.telegram);
conectar(N.telegram, N.marcar);

const destino = path.join(raiz, 'workflows', 'monitor_vulnerabilidades.json');
fs.writeFileSync(destino, JSON.stringify(workflow, null, 2) + '\n');
console.log('Workflow generado:', path.relative(raiz, destino));
