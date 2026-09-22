-- Creates the org host's database next to the directory's when the compose
-- Postgres container first starts. The host owns its own database (plan §1
-- decision G); the schema is created by the host itself.
CREATE DATABASE dimo_org_host OWNER dimo;
