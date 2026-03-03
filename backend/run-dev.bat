@echo off
REM ─────────────────────────────────────────────────────────
REM  Backend Dev Runner — sets JAVA_HOME to JDK 21 then starts
REM  the Spring Boot app using the dev profile (H2 in-memory DB)
REM ─────────────────────────────────────────────────────────

REM Point to JDK 21 (update this path if your JDK 21 is installed elsewhere)
set JAVA_HOME=C:\Program Files\Java\jdk-21
set PATH=%JAVA_HOME%\bin;%PATH%

REM Load .env file variables (skip blank lines and comments)
for /f "usebackq tokens=1,* delims==" %%A in (`findstr /v "^#" .env`) do (
    if not "%%A"=="" (
        set "%%A=%%B"
    )
)

echo.
echo  Java version:
java -version
echo.
echo  Starting backend (dev profile, H2 in-memory DB)...
echo  H2 Console: http://localhost:8080/h2-console
echo  API base:   http://localhost:8080
echo.

call mvnw.cmd spring-boot:run
