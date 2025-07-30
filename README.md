# **Go OAuth 2.0 Authentication Microservice**

A robust, scalable, and secure Authentication Microservice built in Go. It implements the OAuth 2.0 framework and follows Clean Architecture principles to provide a centralized identity and access management solution for our platform.

### **Table of Contents**

1. [Project](https://www.google.com/search?q=%23project-documentation) Documentation  
2. [Core Concepts](https://www.google.com/search?q=%23core-concepts)  
3. [Getting Started](https://www.google.com/search?q=%23getting-started)  
   * [Prerequisites](https://www.google.com/search?q=%23prerequisites)  
   * [Installation](https://www.google.com/search?q=%23installation)  
   * [Running the Service](https://www.google.com/search?q=%23running-the-service)  
4. [Running Tests](https://www.google.com/search?q=%23running-tests)  
5. [API Endpoints](https://www.google.com/search?q=%23api-endpoints)

### **Project Documentation**

This project is defined by a series of detailed documents to ensure consistency and clarity for all developers. Please review them before contributing.

* [**Product Requirements (PRD.md)**](https://www.google.com/search?q=./PRD.md): The vision, goals, and requirements for the service.  
* [**Features (FEATURES.md)**](https://www.google.com/search?q=./FEATURES.md): A detailed list of supported features and OAuth 2.0 flows.  
* [**Architecture (ARCHITECTURE.md)**](https://www.google.com/search?q=./ARCHITECTURE.md): An in-depth look at the Clean/Hexagonal Architecture design.  
* [**Technology Stack (TECH\_STACK.md)**](https://www.google.com/search?q=./TECH_STACK.md): The libraries, databases, and tools used in this project.  
* [**Project Structure (PROJECT\_STRUCTURE.md)**](https://www.google.com/search?q=./PROJECT_STRUCTURE.md): The official directory layout for the codebase.  
* [**Development Guidelines (GUIDELINES.md)**](https://www.google.com/search?q=./GUIDELINES.md): Rules for coding style, testing, and contributions.

### **Core Concepts**

* **Clean Architecture:** The codebase is separated into distinct layers (Domain, Application, Infrastructure) to isolate business logic from external concerns like databases and web frameworks.  
* **OAuth 2.0:** We use the industry-standard protocol for authorization. Key supported flows include Authorization Code (PKCE), Client Credentials, and Refresh Token.  
* **Stateless Services:** API resource servers can validate JWT access tokens offline using a public key, reducing load on the auth service.

### **Getting Started**

#### **Prerequisites**

* Go 1.24+  
* Docker and Docker Compose  
* golang-migrate/migrate CLI

#### **Installation**

1. **Clone the repository:**  
   git clone \<repository-url\>  
   cd auth-service

2. **Install dependencies:**  
   go mod tidy

3. Set up environment variables:  
   Copy the .env.example file to .env and populate it with your configuration, especially the database connection string.  
   cp .env.example .env

4. Start the database:  
   A docker-compose.yml file is provided to easily run a PostgreSQL instance.  
   docker-compose up \-d

5. **Run database migrations:**  
   migrate \-path migrations \-database "postgres://user:password@localhost:5432/authdb?sslmode=disable" up

#### **Running the Service**

go run cmd/server/main.go

The server will start on the port specified in your .env file (default: 8080).

### **Running Tests**

To run all unit tests and check coverage:

go test ./... \-cover

### **API Endpoints**

The primary OAuth 2.0 endpoints are:

* POST /oauth/token: For exchanging credentials or refresh tokens for an access token.  
* GET /oauth/authorize: Initiates the authorization code flow.  
* GET /.well-known/jwks.json: Exposes the public key for JWT validation.

For detailed API specifications, please refer to an API documentation tool like Swagger or Postman, which will be added later.