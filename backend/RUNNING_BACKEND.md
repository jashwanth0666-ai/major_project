# Running the Backend

The backend is a Spring Boot application using Maven and Java 21.

## Prerequisites

- Java 21 installed and available on `PATH`
- PowerShell, Command Prompt, or a Unix-like shell
- The ML API running at `http://127.0.0.1:8000` when ML predictions are needed

Check Java from the `backend` directory:

```powershell
java -version
```

## Start the backend

From the repository root:

```powershell
cd backend
.\mvnw.cmd spring-boot:run
```

The backend starts at:

```text
http://localhost:8080
```

To stop it, press `Ctrl+C`.

## Build the backend

```powershell
cd backend
.\mvnw.cmd clean package
```

The packaged JAR is created in `backend/target/`.

Run the packaged application with:

```powershell
java -jar target/backend-0.0.1-SNAPSHOT.jar
```

## Run tests

Run all tests:

```powershell
cd backend
.\mvnw.cmd test
```

Build without running tests:

```powershell
.\mvnw.cmd clean package -DskipTests
```

## Useful Maven commands

```powershell
# Compile the source
.\mvnw.cmd compile

# Clean generated build files
.\mvnw.cmd clean

# Show Spring Boot application information
.\mvnw.cmd spring-boot:help
```

## Run the ML API

From the repository root, create or activate the Python environment used by the API, then run:

```powershell
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload
```

The backend's ML URL is configured in `backend/src/main/resources/application.properties`:

```properties
ai-watchdog.ml.base-url=http://127.0.0.1:8000
```

If the ML API uses another URL, update that property before starting the backend.
