\# Project Structure

This document describes the directory structure of the project, which is designed to enforce our Clean Architecture principles.

.  
├── api/  
│ └── openapi.yaml \# OpenAPI 3.0 specification  
├── cmd/  
│ └── server/  
│ └── main.go \# Application entry point, DI wiring  
├── configs/  
│ └── config.yml \# Default configuration file  
├── internal/  
│ ├── application/  
│ │ ├── usecase/ \# Application use cases (interactors)  
│ │ │ ├── auth\_usecase.go  
│ │ │ └── ...  
│ │ └── repository/ \# Repository interfaces (contracts)  
│ │ ├── user\_repo.go  
│ │ └── ...  
│ ├── domain/  
│ │ ├── entity/ \# Core domain entities  
│ │ │ ├── user.go  
│ │ │ └── ...  
│ │ └── vo/ \# Domain value objects  
│ │ ├── email.go  
│ │ └── ...  
│ └── infrastructure/  
│ ├── api/  
│ │ ├── handler/ \# HTTP handlers (controllers)  
│ │ │ └── auth\_handler.go  
│ │ ├── middleware/ \# HTTP middleware  
│ │ │ └── auth\_middleware.go  
│ │ └── router.go \# API route definitions  
│ ├── repository/  
│ │ ├── postgres/ \# PostgreSQL implementation of repositories  
│ │ │ └── user\_postgres\_repo.go  
│ │ └── redis/ \# Redis implementation of repositories  
│ │ └── token\_redis\_repo.go  
│ └── services/ \# Clients for external services (e.g. email)  
├── pkg/  
│ ├── common/ \# Truly generic helper code, safe for sharing  
│ │ ├── hasher/  
│ │ └── ...  
│ └── utils/  
│ └── ...  
├── scripts/ \# Helper scripts (e.g., for migrations)  
├── .env.example \# Example environment variables  
├── .gitignore  
├── docker-compose.yml  
├── Dockerfile  
├── go.mod  
├── go.sum  
└── README.md  
\#\# Key Directory Explanations

\- \*\*\`cmd/server/main.go\`\*\*: The only place where all the application dependencies are instantiated and injected (Dependency Injection). It wires together the handlers, use cases, and repository implementations.  
\- \*\*\`internal/\`\*\*: This is the core application code. The \`internal\` directory ensures that these packages cannot be imported by other projects, enforcing their role as internal components of this microservice.  
  \- \*\*\`domain/\`\*\*: Contains pure, dependency-free business logic.  
  \- \*\*\`application/\`\*\*: Defines what the application can do, orchestrating the domain logic. It depends only on \`domain\`.  
  \- \*\*\`infrastructure/\`\*\*: Contains all the implementation details: how the application talks to the database, how it's exposed via an API, etc. It depends on \`application\` and \`domain\`.  
\- \*\*\`pkg/\`\*\*: This directory is for code that is safe to be shared with other applications. \*\*Use with caution.\*\* Most code should live in \`internal\`. Only place truly generic, project-agnostic code here (e.g., a generic password hashing library).  
\- \*\*\`api/\`\*\*: Contains the API contract (OpenAPI/Swagger spec). This defines the public-facing interface of our service.

This structure strictly enforces the dependency rule: \*\*Infrastructure \-\> Application \-\> Domain\*\*.

\---  
\*This document is maintained by the Product Owner. Last updated: 2025-07-30\*  
