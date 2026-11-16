// Genera workflows/monitor_vulnerabilidades.json incrustando el código de n8n/code/*.js,
// para que el workflow importable y el código probado nunca se desincronicen.
//   node scripts/construir_workflow.js
const fs = require('node:fs');
const path = require('node:path');

const raiz = path.join(__dirname, '..');
const codigo = f => fs.readFileSync(path.join(raiz, 'n8n', 'code', f), 'utf8');

const workflow = {
  name: 'Monitor de vulnerabilidades',
  nodes: [
    { id: 'manual', name: 'Disparo manual', type: 'n8n-nodes-base.manualTrigger', typeVersion: 1,
      position: [0, 0], parameters: {} },
    { id: 'horario', name: 'Todos los días 7:00', type: 'n8n-nodes-base.scheduleTrigger', typeVersion: 1.2,
      position: [0, 200],
      parameters: { rule: { interval: [{ field: 'cronExpression', expression: '0 7 * * *' }] } } },
    { id: 'kev', name: 'M1 · Descargar CISA KEV', type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2,
      position: [240, 100],
      parameters: {
        url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        options: { timeout: 60000 },
      } },
    { id: 'filtro', name: 'M2 · Filtrar por fecha e inventario', type: 'n8n-nodes-base.code', typeVersion: 2,
      position: [480, 100], parameters: { jsCode: codigo('02_filtro_kev.js') } },
    { id: 'formato', name: 'M5 · Formatear mensaje', type: 'n8n-nodes-base.code', typeVersion: 2,
      position: [720, 100], parameters: { jsCode: codigo('05_formato_telegram.js') } },
    { id: 'telegram', name: 'M5 · Enviar a Telegram', type: 'n8n-nodes-base.telegram', typeVersion: 1.2,
      position: [960, 100],
      // chatId y la credencial se configuran en n8n después de importar (no van en el repo)
      parameters: { chatId: '', text: '={{ $json.mensaje }}', additionalFields: { appendAttribution: false } } },
  ],
  connections: {
    'Disparo manual': { main: [[{ node: 'M1 · Descargar CISA KEV', type: 'main', index: 0 }]] },
    'Todos los días 7:00': { main: [[{ node: 'M1 · Descargar CISA KEV', type: 'main', index: 0 }]] },
    'M1 · Descargar CISA KEV': { main: [[{ node: 'M2 · Filtrar por fecha e inventario', type: 'main', index: 0 }]] },
    'M2 · Filtrar por fecha e inventario': { main: [[{ node: 'M5 · Formatear mensaje', type: 'main', index: 0 }]] },
    'M5 · Formatear mensaje': { main: [[{ node: 'M5 · Enviar a Telegram', type: 'main', index: 0 }]] },
  },
  settings: { executionOrder: 'v1', timezone: 'America/Bogota' },
  pinData: {},
};

const destino = path.join(raiz, 'workflows', 'monitor_vulnerabilidades.json');
fs.writeFileSync(destino, JSON.stringify(workflow, null, 2) + '\n');
console.log('Workflow generado:', path.relative(raiz, destino));
