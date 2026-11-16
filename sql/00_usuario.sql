-- Usuario propio del proyecto (no usar SYSTEM). Ejecutar como SYSTEM en la PDB XEPDB1:
--   docker exec -it oracle-xe sqlplus system/<PASSWORD>@//localhost:1521/XEPDB1 @/ruta/00_usuario.sql
-- Cambia la contraseña antes de ejecutarlo y NO la subas al repo.

CREATE USER monitor IDENTIFIED BY "CAMBIAR_CONTRASENA"
  DEFAULT TABLESPACE users
  QUOTA 200M ON users;

GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE SEQUENCE TO monitor;
