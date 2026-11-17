-- Consultas de análisis para el README y la entrevista (ejecutar como MONITOR en XEPDB1).
-- Las consultas que ejecuta el workflow de n8n están en sql/n8n/ (una por nodo).

-- Vulnerabilidades críticas pendientes por proveedor
SELECT vendor, COUNT(*) AS total
FROM vulnerabilidades
WHERE prioridad = 'alta' AND fecha_limite >= SYSDATE
GROUP BY vendor
ORDER BY total DESC;

-- Lo que llegó en los últimos 7 días que afecta al inventario
SELECT v.cve_id, v.vendor, v.cvss, v.prioridad
FROM vulnerabilidades v
JOIN inventario i ON LOWER(v.vendor) = LOWER(i.vendor)
WHERE v.creado_en >= SYSTIMESTAMP - INTERVAL '7' DAY;

-- Distribución de prioridades y cuántas siguen sin notificar
SELECT prioridad, COUNT(*) AS total,
       SUM(CASE WHEN notificado = 'N' THEN 1 ELSE 0 END) AS sin_notificar
FROM vulnerabilidades
GROUP BY prioridad;
