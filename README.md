# Monitor de vulnerabilidades con IA

Cada mañana el sistema descarga las vulnerabilidades que se están **explotando activamente** (catálogo CISA KEV), se queda solo con las que afectan a un **inventario tecnológico**, un **LLM local** (Ollama) las explica en español con una prioridad y una acción, se guardan en **Oracle** y las críticas llegan por **Telegram**.

> De cientos de CVE diarios a una o dos alertas que alguien puede ejecutar antes del almuerzo.

## Caso de uso

Una clínica en Bogotá con 40 empleados y un único encargado de sistemas. Usan un firewall Fortinet, Windows Server y una web con Apache. El sistema le avisa solo de lo que lo afecta, ya explicado en español y con la acción a seguir.

## Arquitectura

```
[CISA KEV · NVD]
       │ HTTP GET (JSON)
       ▼
 1. Recolector ──► 2. Filtro ──► 3. Analista IA ──► 4. Memoria ──► 5. Notificador ──► Telegram
 Schedule + HTTP   Code (JS)     Ollama (local)     Oracle (MERGE)  IF + Telegram
```

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
├── sql/                      # usuario, tablas y consultas de Oracle
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
1. `node scripts/construir_workflow.js` (regenera el JSON a partir de `n8n/code/`).
2. En n8n: *Workflows → Import from file* → `workflows/monitor_vulnerabilidades.json`.
3. En el nodo **M5 · Enviar a Telegram**: elegir la credencial *Telegram API* y escribir el `chat_id`.

### 3. Pruebas del código JS (laptop)
```bash
npm test
```

### 4. Notebook de análisis (laptop)
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
| v2 | Módulo 5: Telegram directo, sin IA | 🟡 en curso |
| v3 | Módulo 3: Ollama + validación del JSON | ⬜ |
| v4 | Módulo 4: Oracle + NVD (CVSS) + inventario en tabla | ⬜ |
| v5 | Webhook + agente con herramienta SQL | ⬜ |
| Extra | Respaldo con Gemini si Ollama falla | ⬜ |

## Manejo de errores

| Situación | Manejo |
|---|---|
| NVD responde 429 | Esperar 6 s entre llamadas y usar la API key (header `apiKey`) |
| LLM devuelve JSON inválido | Validación en nodo Code, 1 reintento, si falla `prioridad = 'revisar'` |
| CVE ya existe en Oracle | `MERGE` evita el duplicado; no se re-notifica |
| CISA no responde | *Error Workflow* que avisa por Telegram |

**Limitación conocida:** si el laptop (Ollama) o la VM están apagados a las 7:00 a. m., el flujo no corre.
