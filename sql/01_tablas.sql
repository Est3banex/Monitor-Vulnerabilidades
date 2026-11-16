-- Ejecutar conectado como el usuario MONITOR en XEPDB1.

-- Inventario tecnológico de la "empresa" (v4)
CREATE TABLE inventario (
  id          NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  vendor      VARCHAR2(100) NOT NULL,
  product     VARCHAR2(150),
  activo      CHAR(1) DEFAULT 'S' CHECK (activo IN ('S','N'))
);

-- Vulnerabilidades analizadas
CREATE TABLE vulnerabilidades (
  cve_id        VARCHAR2(20) PRIMARY KEY,
  vendor        VARCHAR2(100),
  product       VARCHAR2(150),
  nombre        VARCHAR2(400),
  descripcion   VARCHAR2(4000),
  fecha_kev     DATE,
  fecha_limite  DATE,
  ransomware    CHAR(1) CHECK (ransomware IN ('S','N')),
  cvss          NUMBER(3,1),
  severidad     VARCHAR2(20),
  resumen_es    VARCHAR2(1000),
  prioridad     VARCHAR2(10) CHECK (prioridad IN ('alta','media','baja','revisar')),
  accion        VARCHAR2(500),
  notificado    CHAR(1) DEFAULT 'N' CHECK (notificado IN ('S','N')),
  creado_en     TIMESTAMP DEFAULT SYSTIMESTAMP
);

-- Inventario inicial del caso de uso (clínica en Bogotá)
INSERT INTO inventario (vendor, product) VALUES ('Fortinet',  'FortiOS');
INSERT INTO inventario (vendor, product) VALUES ('Microsoft', 'Windows');
INSERT INTO inventario (vendor, product) VALUES ('Apache',    'HTTP Server');
INSERT INTO inventario (vendor, product) VALUES ('Cisco',     NULL);
COMMIT;
