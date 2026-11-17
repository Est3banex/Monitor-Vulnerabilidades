MERGE INTO vulnerabilidades v
USING (SELECT :cve_id AS cve_id FROM dual) s
ON (v.cve_id = s.cve_id)
WHEN NOT MATCHED THEN
  INSERT (cve_id, vendor, product, nombre, descripcion, fecha_kev, fecha_limite,
          ransomware, cvss, severidad, resumen_es, prioridad, accion)
  VALUES (:cve_id, :vendor, :product, :nombre, :descripcion,
          TO_DATE(:fecha_kev, 'YYYY-MM-DD'), TO_DATE(:fecha_limite, 'YYYY-MM-DD'),
          :ransomware, TO_NUMBER(:cvss, '99D9', 'NLS_NUMERIC_CHARACTERS = ''.,'''),
          :severidad, :resumen_es, :prioridad, :accion)
