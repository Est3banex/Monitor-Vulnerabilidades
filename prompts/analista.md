# Prompt del Analista IA (Módulo 3)

Modelo principal: `phi4-mini` · comparación: `llama3.2:3b` · Ollama en `http://192.168.56.1:11434`.

## Llamada

```http
POST /api/generate
Content-Type: application/json

{
  "model": "phi4-mini",
  "stream": false,
  "format": "json",
  "prompt": "<PROMPT>"
}
```

## Prompt (v3)

```
Eres un analista de ciberseguridad. Con estos datos de una vulnerabilidad, responde SOLO un JSON
con las claves:
- resumen: máximo 2 frases, en español, sin tecnicismos innecesarios.
- prioridad: "alta", "media" o "baja".
- accion: 1 frase con lo que debe hacer el encargado de sistemas.

Criterios de prioridad: "alta" si CVSS >= 9 o si se usa en campañas de ransomware;
"media" si CVSS entre 7 y 8.9; "baja" en otro caso.

Datos: {{ JSON.stringify($json) }}
```

## Salida esperada

```json
{
  "resumen": "Vulnerabilidad en FortiOS que permite ejecutar código de forma remota sin autenticación.",
  "prioridad": "alta",
  "accion": "Actualizar FortiOS a la versión corregida y revisar los registros de acceso VPN."
}
```

## Validación

Un nodo *Code* verifica que la respuesta sea JSON válido y que `prioridad` ∈ {alta, media, baja}.
1 reintento; si vuelve a fallar → `prioridad = "revisar"`.

## Registro de pruebas

| Fecha | Modelo | CVE | ¿JSON válido? | Tiempo | Notas |
|---|---|---|---|---|---|
| | | | | | |
