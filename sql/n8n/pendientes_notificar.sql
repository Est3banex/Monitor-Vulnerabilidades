SELECT cve_id                              AS "cveID",
       vendor                              AS "vendor",
       product                             AS "product",
       descripcion                         AS "description",
       TO_CHAR(fecha_limite, 'YYYY-MM-DD') AS "dueDate",
       ransomware                          AS "ransomware",
       cvss                                AS "cvss",
       resumen_es                          AS "resumen",
       prioridad                           AS "prioridad",
       accion                              AS "accion"
FROM vulnerabilidades
WHERE prioridad IN ('alta', 'revisar')
  AND notificado = 'N'
ORDER BY fecha_kev DESC, cve_id
