@echo off
REM ─────────────────────────────────────────────────────────
REM  Backend Dev Runner — sets env vars and starts Spring Boot
REM  for LOCAL development only.
REM  Production credentials are managed by your hosting provider.
REM ─────────────────────────────────────────────────────────

REM Point to JDK 21 (update this path if your JDK 21 is installed elsewhere)
set JAVA_HOME=C:\Program Files\Java\jdk-21
set PATH=%JAVA_HOME%\bin;%PATH%

REM ── Database (Neon PostgreSQL) ─────────────────────────────
set DB_URL=jdbc:postgresql://ep-dark-meadow-a1p7zgz9-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require
set DB_USERNAME=neondb_owner
set DB_PASSWORD=npg_dBFJbQcD6k5n
set DB_SSL_MODE=require
set DB_POOL_SIZE=5

REM ── JWT ───────────────────────────────────────────────────
set JWT_SECRET=BpXUdMsKL8ravvJ2D57HkXx6u87zgcxHDQUKnS0uHrMG0iQF00I+cLEamUj3kLLe5gr8mAGBrcBfF2MuvtMqvQ==

REM ── CORS — allow local Next.js frontend ──────────────────
set CORS_ALLOWED_ORIGINS=http://localhost:3000

REM ── JPA ───────────────────────────────────────────────────
set DDL_AUTO=update
set SHOW_SQL=true

REM ── Logging ───────────────────────────────────────────────
set LOG_LEVEL_SECURITY=DEBUG
set LOG_LEVEL_APP=DEBUG
set LOG_LEVEL_SQL=DEBUG

REM ── Port ──────────────────────────────────────────────────
set PORT=8080

echo.
echo  Java version:
java -version
echo.
echo  Starting backend on http://localhost:8080 ...
echo  CORS allowed: %CORS_ALLOWED_ORIGINS%
echo.

call mvnw.cmd spring-boot:run
