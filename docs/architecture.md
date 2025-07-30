# **System Architecture**

## **OAuth 2.0 Authentication Microservice**

Version: 1.0
This document details the software architecture for the Authentication Microservice, which is based on the principles of **Clean Architecture** (also known as Hexagonal or Ports & Adapters Architecture). This design ensures a strong separation of concerns, making the system testable, maintainable, and independent of external frameworks and technologies.

### **1\. Core Principles**

* **Independent of Frameworks:** The core business logic does not depend on any specific web framework (e.g., Gin, Echo).  
* **Testable:** The business logic can be tested in isolation, without requiring a database, UI, or any other external element.  
* **Independent of UI:** The core logic doesn't care if the client is a web app, a CLI, or another service.  
* **Independent of Database:** The business rules are not tied to a specific database technology. We can swap PostgreSQL for another database with minimal changes to the core logic.  
* **The Dependency Rule:** All dependencies flow inwards. Outer layers (e.g., frameworks, databases) depend on inner layers (business rules), but inner layers know nothing about the outer layers.

### **2\. Architectural Layers**

The architecture is composed of the following concentric layers, from outermost to innermost:

*Diagram: The layers of the Clean Architecture. Dependencies point inwards.*

#### **Layer 1: Domain (The Core)**

This is the heart of the application. It contains the enterprise-wide business rules and is written in pure Go, with no external dependencies.

* **Entities:** These are the core business objects (e.g., User, AuthClient). They contain the most general business rules and are the least likely to change when external factors change.  
* **Use Cases (Interactors):** This layer implements the application-specific business rules. It orchestrates the flow of data between entities and the outer layers. For example, a RegisterUserUseCase would contain the logic for creating a new user, ensuring the email is unique, and hashing the password. Use cases do not directly know about the database; they operate on interfaces.

#### **Layer 2: Application (Interfaces & Ports)**

This layer defines the **interfaces** (or "Ports" in Hexagonal Architecture) that are implemented by the outer layers and used by the inner layers (Use Cases).

* **Repositories:** Defines interfaces for data persistence, such as UserRepository with methods like Save(user User) or FindByEmail(email string). The Use Cases depend on these interfaces, not on concrete database implementations.  
* **Services:** Defines interfaces for external services, like a HashingService or a TokenService.

#### **Layer 3: Infrastructure (Adapters)**

This is the outermost layer where all the implementation details and external dependencies reside. These are the "Adapters" that plug into the ports defined in the Application layer.

* **Frameworks (Delivery Mechanisms):** This includes the web server (e.g., using the net/http package or a framework like Gin), which handles HTTP requests, parses them, and calls the appropriate Use Case. This is the primary "driving adapter."  
* **Database (Persistence):** This contains the concrete implementation of the repository interfaces. For example, a PostgresUserRepository that uses the database/sql package to interact with a PostgreSQL database. This is a "driven adapter."  
* **External Services:** Concrete implementations of other services, like a BcryptHashingService that implements the HashingService interface.

### **3\. Data and Control Flow**

Let's trace a "User Registration" request to see how the layers interact:

1. **HTTP Request Arrives:** An HTTP POST request to /register hits the web server in the **Infrastructure** layer.  
2. **Handler/Controller:** The HTTP handler parses the request body into a data transfer object (DTO). It is only responsible for transport-level concerns.  
3. **Call Use Case:** The handler invokes the RegisterUserUseCase in the **Domain** layer, passing the DTO.  
4. Execute Business Logic: The RegisterUserUseCase:  
   a. Calls the UserRepository interface to check if a user with that email already exists.  
   b. Calls the HashingService interface to hash the user's password.  
   c. Creates a new User entity.  
   d. Calls the UserRepository interface again to save the new user.  
5. **Repository Implementation:** The call to the UserRepository interface is fulfilled by the PostgresUserRepository in the **Infrastructure** layer, which executes the necessary SQL queries.  
6. **Return Response:** The Use Case returns a result (or an error) to the handler.  
7. **HTTP Response:** The handler formats the result into an HTTP response (e.g., 201 Created) and sends it back to the client.

This strict, unidirectional flow of dependencies ensures that our core business logic remains pure, protected, and easy to change or test.