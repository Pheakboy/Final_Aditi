# 🎓 FINAL YEAR PROJECT GENERATION SCRIPT
# Project Title:
SMART MICRO-LOAN RISK SCORING SYSTEM
(For Wing Bank Scholarship Final Project)

====================================================
1️⃣ PROJECT OVERVIEW
====================================================

This system is a web-based Smart Micro-Loan Risk Scoring System.

Technology Stack:
- Backend: Java 21 + Spring Boot 3
- Security: Spring Security + JWT
- Database: PostgreSQL
- Frontend: Next.js 14 (TypeScript + Tailwind CSS)

The system contains TWO main roles:

1. USER
2. ADMIN

The goal of the system:
- Allow users to apply for micro-loans
- Automatically calculate loan risk score
- Allow admin to approve/reject loans
- Provide full audit trail and analytics
- Simulate real banking decision system

====================================================
2️⃣ SYSTEM ROLES (VERY IMPORTANT)
====================================================

=========================================
ROLE 1: USER
=========================================

A USER is a normal customer of Wing Bank.

User Capabilities:

1. Register account
2. Login
3. Add financial transactions (income/expense)
4. View transaction history
5. Apply for micro-loan
6. View calculated risk score
7. View loan status (Pending, Approved, Rejected)
8. View personal financial summary dashboard
9. Update profile
10. View loan history

-----------------------------------------
USER BUSINESS LOGIC
-----------------------------------------

The user cannot:
- Approve loans
- View other users’ data
- Change risk score manually

Risk score is automatically calculated by system only.

=========================================
ROLE 2: ADMIN
=========================================

An ADMIN is a Wing Bank officer.

Admin Capabilities:

1. Login
2. View all users
3. View all loan applications
4. Filter loans by:
   - Risk level
   - Status
   - Date
5. View detailed applicant profile
6. Approve loan
7. Reject loan
8. View system analytics dashboard
9. View risk distribution chart
10. View audit logs

Admin cannot:
- Modify risk score manually
- Modify transaction records

====================================================
3️⃣ CORE SYSTEM MODULES
====================================================

MODULE 1: AUTHENTICATION MODULE
MODULE 2: USER MANAGEMENT MODULE
MODULE 3: TRANSACTION MANAGEMENT MODULE
MODULE 4: LOAN MANAGEMENT MODULE
MODULE 5: RISK SCORING ENGINE
MODULE 6: ADMIN CONTROL PANEL
MODULE 7: ANALYTICS MODULE
MODULE 8: AUDIT LOGGING MODULE

====================================================
4️⃣ DETAILED FUNCTION EXPLANATION
====================================================

----------------------------------------------------
AUTHENTICATION FUNCTIONS
----------------------------------------------------

1. registerUser()
   - Input: name, email, password
   - Validate email uniqueness
   - Encrypt password (BCrypt)
   - Assign default role: USER
   - Save to database
   - Return success message

2. loginUser()
   - Validate email/password
   - Generate JWT token
   - Return token + role

3. validateToken()
   - Extract JWT
   - Verify signature
   - Check expiration
   - Load user details

----------------------------------------------------
USER FUNCTIONS
----------------------------------------------------

1. addTransaction()
   - Input: amount, type (INCOME/EXPENSE), description
   - Validate amount > 0
   - Save to database
   - Update user financial summary

2. getUserTransactions()
   - Return list sorted by date descending

3. applyLoan()
   - Input: loanAmount, loanPurpose
   - Fetch user transaction history
   - Call RiskScoringService
   - Calculate risk score
   - Assign risk level
   - Save loan with status PENDING

4. getUserLoans()
   - Return all loans of that user

5. getUserDashboardSummary()
   - Total income
   - Total expenses
   - Savings balance
   - Average monthly income
   - Current risk score

----------------------------------------------------
RISK SCORING ENGINE (CORE LOGIC)
----------------------------------------------------

Function: calculateRiskScore(userId)

Steps:

1. Fetch all transactions
2. Calculate:
   - Total income
   - Total expenses
   - Savings
   - Transaction frequency
3. Compute score using weighted formula

Weight Distribution:
- Income stability: 30%
- Expense ratio: 20%
- Transaction activity: 20%
- Savings amount: 30%

Final Score Range: 0 – 100

Risk Level:
- >= 80 → LOW
- 50–79 → MEDIUM
- < 50 → HIGH

System automatically stores:
- riskScore
- riskLevel

----------------------------------------------------
LOAN MANAGEMENT FUNCTIONS
----------------------------------------------------

1. approveLoan(loanId)
   - Only ADMIN
   - Change status → APPROVED
   - Save decision record

2. rejectLoan(loanId)
   - Only ADMIN
   - Change status → REJECTED
   - Save rejection reason

3. getAllLoans()
   - Paginated
   - Filterable
   - Sortable

----------------------------------------------------
ANALYTICS FUNCTIONS
----------------------------------------------------

1. getRiskDistribution()
   - Count LOW/MEDIUM/HIGH loans

2. getLoanApprovalRate()
   - Approved vs Rejected percentage

3. getMonthlyLoanStatistics()

4. getTopHighRiskUsers()

----------------------------------------------------
AUDIT LOGGING FUNCTIONS
----------------------------------------------------

Every important action logs:
- User login
- Loan application
- Loan approval
- Loan rejection

Stored in audit_logs table.

====================================================
5️⃣ DATABASE STRUCTURE (POSTGRESQL)
====================================================

Tables:

users
- id (UUID)
- name
- email (unique)
- password
- role (USER, ADMIN)
- created_at

transactions
- id
- user_id (FK)
- amount
- type (INCOME/EXPENSE)
- description
- created_at

loans
- id
- user_id (FK)
- amount
- risk_score
- risk_level
- status (PENDING, APPROVED, REJECTED)
- created_at

loan_decisions
- id
- loan_id (FK)
- admin_id (FK)
- decision
- reason
- decision_date

audit_logs
- id
- action
- performed_by
- timestamp

====================================================
6️⃣ SECURITY CONFIGURATION
====================================================

- Stateless session
- JWT Authentication filter
- Role-based authorization
- BCrypt password encoding
- Method-level security
- Exception handling for unauthorized access

====================================================
7️⃣ FRONTEND STRUCTURE (NEXT JS)
====================================================

Pages:

Public:
- /login
- /register

User:
- /dashboard
- /transactions
- /loan/apply
- /loan/history

Admin:
- /admin/dashboard
- /admin/loans
- /admin/users
- /admin/analytics

====================================================
8️⃣ NON-FUNCTIONAL REQUIREMENTS
====================================================

- Clean Architecture
- DTO pattern
- Service layer separation
- Global Exception Handler
- Input validation
- Pagination support
- Logging
- Error handling
- Production-ready structure

====================================================
9️⃣ PROJECT COMPLEXITY LEVEL
====================================================

This project is NOT small because:

- Multi-role system
- Authentication & JWT
- Financial calculations
- Risk scoring algorithm
- Admin decision workflow
- Analytics module
- Audit logging
- Database relationships
- Secure REST API
- Frontend dashboard

This is suitable for:
- Final Year Project
- Banking/Fintech Simulation
- Software Engineering Defense

====================================================
END OF MASTER PROJECT SPECIFICATION
====================================================