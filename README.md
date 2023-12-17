# Auth Service

## Overview

Auth Service is a crucial microservice in the BerryTracer project, designed for handling authentication and authorization for IoT devices and users. It utilizes gRPC for secure and efficient inter-service communication.

## Features

- Secure authentication for users and devices.
- Authorization management.
- Reliable gRPC communication for inter-service interactions.
- MongoDB integration for persistent data storage.

## Prerequisites

- Go (version 1.15 or later is recommended).
- An active MongoDB instance.
- Other dependent services (like `device-service`) should be running and accessible (configured via environment variables).

## Installation

Clone the Auth Service repository:

```bash
git clone https://github.com/BerryTracer/auth-service.git
cd auth-service
```

Set up the environment variables in a `.env` file:

```env
MONGODB_URI=mongodb://root:password@localhost:27017/berrytracer
DEVICE_SERVICE_URL=localhost:50051
```

## Running the Service

To run the Auth Service locally:

```bash
go run main.go
```

## Docker Compose
To start MongoDB using Docker Compose:

```bash
docker-compose -f docker-compose.dev.db.yml up -d
```

Ensure the MongoDB URI in the .env file matches the configuration in the Docker Compose file.

## Project Structure

- `/grpc`: gRPC service definitions and protocol buffers.
- `/model`: Data models related to authentication and authorization.
- `/repository`: Database operations and data access layer.
- `/service`: Business logic and service handlers for authentication.
- `main.go`: The main entry point for the Auth Service.

## Development
Build the project:

```bash
go build -o auth-service
```

Run tests:
```bash
go test ./...
```
