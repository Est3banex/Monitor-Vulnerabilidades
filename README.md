# Monitor de vulnerabilidades con IA

Cada mañana el sistema descarga las vulnerabilidades que se están **explotando activamente** (catálogo CISA KEV), se queda solo con las que afectan a un **inventario tecnológico**, consulta su gravedad (CVSS) en **NVD**, unas **reglas fijas** deciden la prioridad, un **LLM local** (Ollama) las explica en español con una acción concreta, se guardan en **Oracle** sin duplicados y las urgentes llegan por **Telegram**.

> De cientos de CVE diarios a una o dos alertas que alguien puede ejecutar antes del almuerzo.

## Caso de uso

Una clínica en Bogotá con 40 empleados y un único encargado de sistemas. Usan un firewall Fortinet, Windows Server y una web con Apache. El sistema le avisa solo de lo que lo afecta, ya explicado en español y con la acción a seguir.

## Arquitectura

```
[CISA KEV · NVD]
       │ HTTP GET (JSON)
       ▼
 1. Recolector ──► 2. Filtro ──────► 4. Memoria + NVD ──► 3. Analista IA ──► 4. Guardar ──► 5. Notificador ──► Telegram
 Schedule + HTTP   Code (JS)          descarta lo ya       Ollama (local)     Oracle         pendientes alta/revisar
                   inventario Oracle  guardado, CVSS,      resumen y acción   (MERGE)        y marca notificado
                                      prioridad por reglas
```

**Prioridad (reglas fijas):** ransomware o CVSS ≥ 9 → alta · CVSS 7–8.9 → media · CVSS < 7 → baja · sin CVSS → revisar.
Se notifican **alta** y **revisar**; media y baja quedan registradas en Oracle para consulta.

**Patrón:** pedir → filtrar → entender → guardar → avisar.

| Componente | Dónde corre |
|---|---|
| n8n | VM Alpine, contenedor Docker (`:5678`) |
| Oracle XE 21c | VM, contenedor `oracle-xe` en la red `red_oracle` |
| Ollama (`phi4-mini`, `llama3.2:3b`) | Laptop, nativo (`:11434`, solo red host-only) |
| CISA KEV, NVD, Telegram | Servicios externos |

## Estructura del repositorio

```
├── docker-compose.yml        # n8n unido a la red de Oracle
├── workflows/                # workflow de n8n importable (sin secretos)
├── n8n/code/                 # código JavaScript de los nodos Code (fuente de verdad)
├── tests/                    # pruebas del código JS con node:test
├── scripts/                  # utilidades (generar el workflow desde n8n/code)
├── sql/                      # usuario, tablas y consultas de análisis
│   └── n8n/                  # consultas que ejecutan los nodos Oracle (fuente de verdad)
├── prompts/                  # prompt del analista IA y registro de pruebas
├── notebooks/                # análisis del catálogo KEV con pandas
└── docs/                     # diagramas y capturas
```

## Puesta en marcha

### 1. n8n (en la VM)
```bash
docker network create red_oracle            # si no existe
docker network connect red_oracle oracle-xe
docker compose up -d
```

### 2. Importar el workflow
1. `node scripts/construir_workflow.js` (regenera el JSON a partir de `n8n/code/` y `sql/n8n/`).
2. En n8n: *Workflows → Import from file* → `workflows/monitor_vulnerabilidades.json`.
3. Elegir credenciales tras importar:
   - Los 5 nodos **Oracle** (M4 · Leer inventario, M4 · CVE ya registrados, M4 · Guardar en Oracle, M5 · Pendientes de notificar, M5 · Marcar notificado): credencial del usuario `monitor` (host `oracle-xe`, puerto `1521`, servicio `XEPDB1`).
   - **M4 · Consultar NVD**: credencial *Header Auth* con header `apiKey`.
   - **M5 · Enviar a Telegram**: credencial *Telegram API* y el `chat_id`.
4. Los nodos **M3 · Consultar Ollama** apuntan a `http://192.168.56.1:11434`; si la IP del laptop cambia, ajústala en `scripts/construir_workflow.js` y regenera.

### 3. Base de datos (una sola vez)
1. Como SYSTEM: `sql/00_usuario.sql` (crea el usuario `monitor`).
2. Como `monitor`: `sql/01_tablas.sql` (tablas e inventario inicial). El inventario se administra en la tabla `INVENTARIO`.

### 4. Pruebas del código JS (laptop)
```bash
npm test
```

### 5. Notebook de análisis (laptop)
```bash
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
jupyter lab notebooks/
```

## Secretos

Los tokens (Telegram, NVD, Gemini) viven **solo en Credentials de n8n**. `.env` está en `.gitignore`; usa `.env.example` como plantilla. Antes de subir un workflow exportado, revisa que no contenga tokens ni `chat_id`.

## Plan por versiones

| Versión | Qué agrega | Estado |
|---|---|---|
| v0 | Módulo 1: descarga de CISA KEV | ✅ |
| v1 | Módulo 2: filtro en JavaScript | ✅ (probado con el feed real) |
| v2 | Módulo 5: Telegram directo, sin IA | ✅ |
| v3 | Módulo 3: Ollama + validación del JSON | ✅ (probado en n8n) |
| v4 | Módulo 4: Oracle + NVD (CVSS) + inventario en tabla + prioridad por reglas | 🟡 probado en el laptop (NVD y Ollama reales); falta prueba en n8n |
| v5 | Webhook + agente con herramienta SQL | ⬜ |
| Extra | Respaldo con Gemini si Ollama falla | ⬜ |

## Manejo de errores

| Situación | Manejo |
|---|---|
| NVD responde 429 | 1 solicitud cada 700 ms con API key; hasta 3 intentos separados 6 s; si falla, CVSS vacío y prioridad `revisar` |
| NVD aún no tiene CVSS | Se usa el CVSS del fabricante (Secondary) si existe; si no, prioridad `revisar` (se notifica) |
| LLM devuelve JSON inválido o acción incompleta | Validación en nodo Code, 1 reintento; si falla, se guarda sin resumen y el mensaje usa la descripción de CISA (la prioridad por reglas no cambia) |
| Ollama apagado o tarda > 300 s | El nodo HTTP continúa con `{ error }`; mismo camino que el JSON inválido |
| CVE ya existe en Oracle | Se descarta antes de NVD y la IA; además `MERGE` evita el duplicado |
| Telegram falla | La alerta queda con `notificado = 'N'` y se reenvía en la próxima ejecución (la rama de aviso corre siempre, haya o no vulnerabilidades nuevas) |
| Tabla INVENTARIO vacía | El flujo se detiene con error en lugar de "funcionar" sin avisar nada |
| Texto más largo que la columna | Se recorta por bytes UTF-8 antes de guardar (evita ORA-12899) |
| CISA no responde | *Error Workflow* que avisa por Telegram |

**Limitaciones conocidas:**
- Si el laptop (Ollama) o la VM están apagados a las 7:00 a. m., el flujo no corre.
- Dos ejecuciones simultáneas (manual + programada) pueden chocar en el `MERGE` (ORA-00001); la siguiente ejecución lo corrige.
