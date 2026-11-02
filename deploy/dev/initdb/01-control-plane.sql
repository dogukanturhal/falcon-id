-- falcon_id is created by POSTGRES_DB. The service also wants a second
-- database for control-plane data (CONTROL_PLANE_DATABASE_URL).
CREATE DATABASE falcon_id_control OWNER falcon;
