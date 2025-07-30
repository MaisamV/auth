# **Development Guidelines**

## **OAuth 2.0 Authentication Microservice**

Version: 1.0
To ensure consistency, quality, and smooth collaboration between all developers (human and AI), this document outlines the development guidelines and standards for this project.

### **1\. Code Style & Formatting**

* **GoFMT:** All Go code **must** be formatted with gofmt before committing. Most IDEs can be configured to do this automatically on save.  
* **Go Imports:** Use goimports to automatically format imports and keep them organized.  
* **Linting:** Use golangci-lint with the provided configuration file (.golangci.yml) to enforce a higher standard of code quality. All code must pass the linter before a pull request can be merged.

### **2\. SOLID Principles**

All code should adhere to the SOLID principles:

* **S \- Single Responsibility Principle:** A struct or function should have only one reason to change. Keep them small and focused.  
* **O \- Open/Closed Principle:** Code should be open for extension but closed for modification. Use interfaces to allow new implementations without changing existing code.  
* **L \- Liskov Substitution Principle:** Subtypes must be substitutable for their base types. When implementing an interface, ensure the implementation honors the interface's contract.  
* **I \- Interface Segregation Principle:** Don't force clients to depend on interfaces they don't use. Keep interfaces small and focused on a specific behavior.  
* **D \- Dependency Inversion Principle:** High-level modules should not depend on low-level modules; both should depend on abstractions. This is the core of our Clean Architecture. Use cases depend on repository interfaces, not on PostgreSQL.

### **3\. Error Handling**

* **No Panics:** Do not use panic for recoverable errors. Panics should only be used for unrecoverable, programmer-level errors during initialization (e.g., failure to connect to the database on startup).  
* **Error Wrapping:** When an error is passed up the call stack, wrap it with context using fmt.Errorf("context: %w", err). This preserves the original error and provides a clear trace.  
* **Custom Errors:** Define custom error variables or types (e.g., ErrUserNotFound) in the appropriate layer (usually alongside the interface) to allow for programmatic checking of specific error conditions.

### **4\. Testing**

* **Unit Tests:** Every use case and business-critical function must have corresponding unit tests.  
* **Test Coverage:** Aim for a minimum of 80% test coverage for the domain layer. Use go test \-cover to check coverage.  
* **Table-Driven Tests:** Use table-driven tests where appropriate to test multiple scenarios concisely.  
* **Mocking:** Use mocks for all external dependencies (repositories, services) when unit testing use cases.

### **5\. Git & Version Control**

* **Branching:** Use the **GitFlow** model (or a simplified version).  
  * main: Represents the production-ready code.  
  * develop: The main development branch where features are integrated.  
  * feature/ branches: All new work must be done on a feature branch created from develop.  
* **Commit Messages:** Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. This helps in automating changelogs and makes history more readable.  
  * Example: feat: add authorization code flow with pkce  
  * Example: fix: correct password hashing salt generation  
  * Example: docs: update README with setup instructions

### **6\. Pull Requests (PRs)**

* **Small & Focused:** PRs should be small and represent a single logical change. Avoid "mega PRs."  
* **Clear Description:** The PR description should clearly explain the "what" and "why" of the change. Link to the relevant issue or user story.  
* **CI Checks:** All CI checks (build, lint, test) must pass before a PR can be merged.  
* **Code Review:** At least one other developer must review and approve the PR. Address all comments before merging.