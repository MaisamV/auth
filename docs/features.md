# **Features & Supported Flows**

## **OAuth 2.0 Authentication Microservice**

Version: 1.0 
This document specifies the concrete features and the OAuth 2.0 grant types that the Authentication Microservice must implement to meet the requirements outlined in the PRD.

### **1\. Core Features**

* **User Registration:**  
  * Endpoint for creating a new user with an email and password.  
  * Passwords must be securely hashed using a modern, strong algorithm (e.g., Argon2id or bcrypt).  
* **Token Issuance:**  
  * Generate JWTs (JSON Web Tokens) as Access Tokens.  
  * Generate opaque, random strings for Refresh Tokens, which are stored in the database.  
* **Token Validation:**  
  * Provide a public key endpoint (/.well-known/jwks.json) for other microservices to fetch keys and validate JWT signatures locally.  
  * This allows other services to verify tokens without calling the auth service, improving performance and resilience.  
* **Token Refresh:**  
  * Endpoint to exchange a valid (non-expired, non-revoked) Refresh Token for a new Access Token.  
* **Token Revocation:**  
  * Endpoint to revoke a Refresh Token. Revoking a refresh token should immediately invalidate it.  
  * This is critical for logging users out and handling security events.

### **2\. Supported OAuth 2.0 Grant Types**

The service must implement the following grant types to support our different client applications.

#### **2.1. Authorization Code Flow with PKCE**

* **Purpose:** The primary and most secure flow for our first-party, public clients like the **web dashboard (SPA)**. It is designed for applications that cannot securely store a client secret.  
* **Actors:** End-User (Instagram Page Owner), Web Browser (Client), Auth Service.  
* **Flow:**  
  1. The web app initiates the login, creating a code\_verifier and a code\_challenge.  
  2. It redirects the user to the auth service's /authorize endpoint with the code\_challenge.  
  3. The user logs in with their credentials.  
  4. The auth service redirects back to the web app with a short-lived authorization\_code.  
  5. The web app sends the authorization\_code and the original code\_verifier to the /token endpoint.  
  6. The auth service verifies the code\_verifier against the code\_challenge and, if valid, returns an **Access Token** and a **Refresh Token**.

#### **2.2. Refresh Token Grant**

* **Purpose:** To allow all clients (web dashboard, mobile apps) to obtain a new access token after the old one has expired, without requiring the user to log in again.  
* **Actors:** Client Application, Auth Service.  
* **Flow:**  
  1. The client's Access Token expires.  
  2. The client sends its **Refresh Token** to the /token endpoint with grant\_type=refresh\_token.  
  3. The auth service validates the refresh token (checks if it exists, is not expired, and not revoked).  
  4. If valid, it returns a new Access Token (and optionally, a new Refresh Token for rotation).

#### **2.3. Client Credentials Grant**

* **Purpose:** For non-interactive, machine-to-machine (M2M) communication. This will be used by our own backend services to securely communicate with each other.  
* **Actors:** Backend Microservice (Client), Auth Service.  
* **Flow:**  
  1. A backend service (e.g., billing-service) needs to call another service (e.g., user-service).  
  2. It sends its client\_id and client\_secret to the /token endpoint with grant\_type=client\_credentials.  
  3. The auth service validates the credentials and returns an Access Token.  
  4. The billing-service uses this token to make authenticated requests.

#### **2.4. Resource Owner Password Credentials (ROPC) Grant**

* **Purpose:** For trusted, first-party applications only, such as a future native mobile app. It allows the app to collect the user's username and password directly.  
* **WARNING:** This flow should be used with extreme caution and **never** exposed to third-party clients. It is included for trusted clients where a redirect-based flow is not feasible.  
* **Actors:** End-User, Mobile App (Client), Auth Service.  
* **Flow:**  
  1. The user enters their email and password into the mobile app.  
  2. The mobile app sends the credentials, its client\_id, and client\_secret to the /token endpoint with grant\_type=password.  
  3. The auth service validates the credentials and returns an Access Token and a Refresh Token.