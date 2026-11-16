-- Insertar sin duplicar (Módulo 4). Parámetros enlazados desde n8n.
MERGE INTO vulnerabilidades v
USING (SELECT :cve_id AS cve_id FROM dual) s
ON (v.cve_id = s.cve_id)
WHEN NOT MATCHED THEN
  INSERT (cve_id, vendor, product, nombre, descripcion, fecha_kev, fecha_limite,
          ransomware, cvss, severidad, resumen_es, prioridad, accion)
  VALUES (:cve_id, :vendor, :product, :nombre, :descripcion,
          TO_DATE(:fecha_kev, 'YYYY-MM-DD'), TO_DATE(:fecha_limite, 'YYYY-MM-DD'),
          :ransomware, :cvss, :severidad, :resumen_es, :prioridad, :accion);

-- Pendientes de notificar (Módulo 5)
SELECT * FROM vulnerabilidades
WHERE prioridad = 'alta' AND notificado = 'N';

-- Marcar como notificada
UPDATE vulnerabilidades SET notificado = 'S' WHERE cve_id = :cve_id;

-- Inventario activo (v4: reemplaza la lista fija del nodo Code)
SELECT LOWER(vendor) AS vendor, LOWER(product) AS product
FROM inventario
WHERE activo = 'S';

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
