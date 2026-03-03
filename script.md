# 🚀 GENERATE FULL PROJECT
# Smart Micro-Loan Risk Scoring System
# Tech Stack:
# - Frontend: Next.js 14 (TypeScript + Tailwind)
# - Backend: Spring Boot 3 (Java 17)
# - Database: PostgreSQL
# - Auth: JWT (Spring Security)

You are a senior full-stack engineer.

Generate a FULLY WORKING production-ready project with clean architecture.

====================================================
PROJECT NAME
====================================================

Smart Micro-Loan Risk Scoring System

====================================================
PROJECT GOAL
====================================================

Build a system that:

- Allows users to register/login
- Users can record transactions (income/expense)
- Users can apply for micro-loans
- System automatically calculates risk score
- Admin can approve/reject loans
- Uses JWT authentication
- Uses PostgreSQL relational database
- Has clean folder structure
- Includes error handling
- Includes validation
- Includes DTO pattern
- Includes role-based access control

====================================================
BACKEND REQUIREMENTS (SPRING BOOT)
====================================================

Use:
- Spring Boot 3
- Spring Security
- Spring Data JPA
- PostgreSQL
- Lombok
- JJWT (for JWT)
- Maven
- Java 17

----------------------------------------------------
BACKEND STRUCTURE
----------------------------------------------------

com.wingbank.loanrisk
├── config
│   ├── SecurityConfig.java
│   ├── JwtAuthenticationFilter.java
│   ├── JwtService.java
│
├── controller
│   ├── AuthController.java
│   ├── UserController.java
│   ├── TransactionController.java
│   ├── LoanController.java
│   ├── AdminController.java
│
├── service
│   ├── AuthService.java
│   ├── UserService.java
│   ├── TransactionService.java
│   ├── LoanService.java
│   ├── RiskScoringService.java
│
├── repository
│   ├── UserRepository.java
│   ├── TransactionRepository.java
│   ├── LoanRepository.java
│   ├── LoanDecisionRepository.java
│
├── model
│   ├── User.java
│   ├── Transaction.java
│   ├── Loan.java
│   ├── LoanDecision.java
│   ├── enums (Role, LoanStatus, TransactionType, RiskLevel)
│
├── dto
│   ├── LoginRequest.java
│   ├── RegisterRequest.java
│   ├── LoanRequestDTO.java
│   ├── LoanResponseDTO.java
│
├── exception
│   ├── GlobalExceptionHandler.java
│
└── LoanRiskApplication.java

----------------------------------------------------
DATABASE SCHEMA
----------------------------------------------------

Use PostgreSQL with UUID primary keys.

Tables:

users
transactions
loans
loan_decisions

Include:
- Proper foreign keys
- Cascade delete
- Index on email
- Enum constraints

----------------------------------------------------
RISK SCORING LOGIC (IMPORTANT)
----------------------------------------------------

Implement RiskScoringService.java

Score formula:

incomeWeight = 0.3
expenseWeight = 0.2
transactionWeight = 0.2
savingsWeight = 0.3

Calculate:

incomeScore:
- >= 1000 → 100
- 500–999 → 70
- < 500 → 40

expenseScore:
- expense/income < 50% → 100
- < 80% → 70
- else → 30

transactionScore:
- > 30 transactions → 100
- > 10 → 70
- else → 40

savingsScore:
- savings > 300 → 100
- > 100 → 70
- else → 40

Final:

riskScore =
(incomeScore × 0.3) +
(expenseScore × 0.2) +
(transactionScore × 0.2) +
(savingsScore × 0.3)

Risk Level:
>= 80 → LOW
50–79 → MEDIUM
< 50 → HIGH

Auto-calculate during loan submission.

----------------------------------------------------
SECURITY REQUIREMENTS
----------------------------------------------------

Implement full JWT flow:

- Register endpoint
- Login endpoint
- Generate JWT
- Validate JWT in filter
- Stateless session
- BCrypt password encoder
- Role-based endpoint protection

USER endpoints:
- Apply loan
- View own loans
- Add transactions

ADMIN endpoints:
- View all loans
- Approve loan
- Reject loan

----------------------------------------------------
FRONTEND REQUIREMENTS (NEXT JS)
----------------------------------------------------

Use:
- Next.js 14 (App Router)
- TypeScript
- Tailwind CSS
- Axios
- Context API for auth

----------------------------------------------------
FRONTEND STRUCTURE
----------------------------------------------------

src/
├── app/
│   ├── login/
│   ├── register/
│   ├── dashboard/
│   ├── transactions/
│   ├── loan/apply/
│   ├── loan/status/
│   ├── admin/dashboard/
│   ├── admin/applicants/
│
├── components/
│   ├── Navbar.tsx
│   ├── Sidebar.tsx
│   ├── LoanCard.tsx
│   ├── RiskBadge.tsx
│
├── context/
│   ├── AuthContext.tsx
│
├── services/
│   ├── api.ts

----------------------------------------------------
FRONTEND FEATURES
----------------------------------------------------

Login & Register:
- Store JWT in localStorage
- Auto redirect by role

User Dashboard:
- Show total transactions
- Show risk score
- Show loan status

Loan Apply Page:
- Input amount
- Input income/expense
- Submit to backend

Admin Dashboard:
- Show pending loans
- Approve / Reject buttons

----------------------------------------------------
API CONNECTION
----------------------------------------------------

Axios instance:

Authorization: Bearer <token>

Handle:
- 401 auto logout
- Error toast

----------------------------------------------------
VALIDATION
----------------------------------------------------

Backend:
- Use @Valid
- Use DTO validation annotations

Frontend:
- Form validation before submit

----------------------------------------------------
ERROR HANDLING
----------------------------------------------------

GlobalExceptionHandler:
- BadRequest
- Unauthorized
- NotFound
- Generic Exception

Return structured JSON error.

----------------------------------------------------
DELIVERABLE FORMAT
----------------------------------------------------

Generate:

1. Full backend code
2. Full frontend code
3. application.yml
4. pom.xml
5. database-schema.sql
6. README.md with setup instructions
7. Example API requests
8. Example .env for frontend

====================================================
IMPORTANT
====================================================

- Code must compile
- No pseudo-code
- No incomplete functions
- Clean architecture
- Production-ready structure
- Clear comments

====================================================
END OF GENERATION SCRIPT
====================================================