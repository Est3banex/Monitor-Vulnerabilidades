# Prompt del Analista IA (Módulo 3)

Modelo principal: `phi4-mini` · comparación: `llama3.2:3b` · Ollama en `http://192.168.56.1:11434`.

> La fuente de verdad del prompt es `n8n/code/03_preparar_solicitud.js` (función `construirPrompt`).
> Este documento explica el diseño y registra las pruebas.

## Reparto de responsabilidades (desde v4)

| Qué | Quién lo decide | Por qué |
|---|---|---|
| **Prioridad** | Reglas fijas en `n8n/code/04_cvss_prioridad.js` | Predecible y explicable; el modelo de 3–4B sobrestimaba la urgencia (ver registro v3) |
| **Resumen y acción en español** | phi4-mini | Es lo que un LLM hace bien: explicar en lenguaje claro |

Reglas: ransomware o CVSS ≥ 9 → `alta`; CVSS 7–8.9 → `media`; CVSS < 7 → `baja`; sin CVSS en NVD → `revisar` (se notifica igual).

## Llamada

```http
POST /api/generate
Content-Type: application/json

{
  "model": "phi4-mini",
  "stream": false,
  "format": "json",
  "prompt": "<PROMPT>",
  "options": { "temperature": 0 }
}
```

- `format: "json"` obliga a Ollama a devolver JSON sintácticamente válido.
- `temperature: 0` hace que la misma vulnerabilidad reciba siempre el mismo texto.

## Prompt (v4)

```
Eres un analista de ciberseguridad que asesora al único encargado de sistemas de una clínica pequeña.
Con los datos de la vulnerabilidad, responde SOLO un objeto JSON con exactamente estas claves:
- "resumen": máximo 2 frases en español, explicando qué permite hacer a un atacante.
- "accion": 1 frase completa en español, con un verbo y el nombre del producto, que diga qué hacer y cuándo.
La prioridad ya está decidida; no la cambies ni la menciones. Según la prioridad, el plazo de la acción es:
alta -> hoy mismo; media -> durante esta semana; baja -> en el próximo ciclo de actualizaciones;
revisar -> primero confirmar si el producto está instalado y expuesto a Internet.
Ejemplo de accion (otro producto): "Aplicar durante esta semana el parche de seguridad de Apache Tomcat publicado por el fabricante."
No inventes versiones, parches ni impactos que no estén en los datos.
Datos: {"cve", "fabricante", "producto", "nombre", "descripcion", "usada_en_ransomware",
        "fecha_limite_cisa", "cvss" (si existe), "prioridad"}
```

## Validación (`n8n/code/03_validar_analisis.js`)

| Motivo de fallo | Cuándo ocurre |
|---|---|
| `sin_respuesta` | Ollama apagado, conexión rechazada o timeout (300 s) |
| `json_invalido` | El texto no es JSON o no es un objeto |
| `campo_faltante` | Falta `resumen` o `accion`, o vienen vacíos |
| `campo_muy_largo` | `resumen` > 1000 o `accion` > 500 caracteres |
| `accion_incompleta` | `accion` con menos de 3 palabras (caso real: `"revisar"`) |

Ante un fallo se hace 1 reintento. Si vuelve a fallar, `resumen` y `accion` quedan vacíos (el mensaje usa la descripción de CISA y una acción genérica) **y la prioridad por reglas se conserva**: una vulnerabilidad alta se avisa aunque la IA falle.

## Registro de pruebas

### v3 — la IA decidía la prioridad (sin CVSS)

| Fecha | Modelo | Prompt | CVE | ¿JSON válido? | Tiempo | Prioridad | Notas |
|---|---|---|---|---|---|---|---|
| 2026-11-17 | phi4-mini | inicial | CVE-2026-124194 (Outlook, spoofing) | Sí | 30,1 s | alta | 1ª llamada incluye carga del modelo |
| 2026-11-17 | phi4-mini | inicial | CVE-2026-20320 (BroadWorks, fuga de info) | Sí | 14,2 s | alta | |
| 2026-11-17 | phi4-mini | inicial | CVE-2026-76418 (ASA/FTD, DoS) | Sí | 15,0 s | alta | Marcó todo como alta |
| 2026-11-17 | phi4-mini | v3 (regla sin CVSS) | CVE-2026-124194 | Sí | 15,7 s | media | Correcto |
| 2026-11-17 | phi4-mini | v3 (regla sin CVSS) | CVE-2026-20320 | Sí | 13,8 s | alta | Debería ser media |
| 2026-11-17 | phi4-mini | v3 (regla sin CVSS) | CVE-2026-76418 | Sí | 14,9 s | alta | Debería ser media; se cuela "Poses" (inglés) |
| 2026-11-17 | llama3.2:3b | v3 (regla sin CVSS) | las 3 anteriores | Sí | 13–31 s | alta ×3 | Inventa impactos ("tomar el control") y dice que no hay parche: descartado |

En n8n (VM) también salieron las tres como alta. **Decisión:** la prioridad pasa a reglas fijas con el CVSS de NVD.

### v4 — prioridad por reglas, la IA solo redacta

| Fecha | CVE | CVSS (NVD) | Prioridad | Prompt | Acción generada | Notas |
|---|---|---|---|---|---|---|
| 2026-11-17 | CVE-2026-124194 | 6.5 (Secondary, Microsoft) | baja | v4 inicial | `revisar` | Copió una palabra de la lista de plazos → se agrega `accion_incompleta` |
| 2026-11-17 | CVE-2026-20320 | 7.5 (Secondary, Cisco) | media | v4 inicial | `revisar` | Igual |
| 2026-11-17 | CVE-2026-124194 | 6.5 | baja | v4 con ejemplo | "Verificar durante esta semana si Microsoft Office Outlook está instalado y expuesto a Internet." | Correcta (plazo algo más urgente que "baja") |
| 2026-11-17 | CVE-2026-20320 | 7.5 | media | v4 con ejemplo | "Durante esta semana, verificar si el producto Cisco BroadWorks está instalado y expuesto a Internet, y aplicar el parche…" | Correcta. ~10–14 s por llamada |

Observación de NVD: las tres vulnerabilidades del período solo tenían CVSS del fabricante (`Secondary`), no de NIST (`Primary`). Por eso el extractor acepta `Secondary` cuando no hay `Primary`.
