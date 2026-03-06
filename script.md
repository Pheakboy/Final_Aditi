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
- View other users' data
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




====================================================
🆕 EXTENDED FEATURES
====================================================

====================================================
2️⃣ SYSTEM ROLES — EXTENDED CAPABILITIES
====================================================

=========================================
ROLE 1: USER — ADDITIONAL
=========================================

11. View detailed loan history (status, risk score, rejection reason)
12. View transaction history with filter by type and date
13. Export own transaction history as CSV
14. Receive notification when loan status changes
15. View notification inbox

=========================================
ROLE 2: ADMIN — ADDITIONAL
=========================================

11. CRUD: Create user account manually
12. CRUD: Update any user profile
13. CRUD: Deactivate user account
14. CRUD: Reactivate user account
15. View full loan history of any user
16. View full transaction history of any user
17. Export user list to CSV
18. Export loan list to CSV
19. Export analytics report to CSV
20. Send notification to a specific user
21. Send broadcast notification to all users
22. Bulk approve multiple loans at once
23. Bulk reject multiple loans at once
24. View monthly statistics and trends

====================================================
3️⃣ CORE SYSTEM MODULES — ADDITIONAL
====================================================

MODULE 9:  NOTIFICATION MODULE
MODULE 10: EXPORT MODULE

====================================================
4️⃣ DETAILED FUNCTION EXPLANATION — ADDITIONAL
====================================================

----------------------------------------------------
USER FUNCTIONS (ADDITIONAL)
----------------------------------------------------

6. getLoanHistory()
   - Return all loans with full detail per loan:
     amount, purpose, risk score, risk level,
     status, applied date, decision date, rejection reason
   - Sorted by date descending

7. getTransactionHistory()
   - Return paginated transaction list
   - Filter by: type (INCOME / EXPENSE / ALL)
   - Filter by: date range (from / to)
   - Sorted by date descending

8. exportTransactionsCSV()
   - Export own transaction history as downloadable CSV
   - Columns: Date, Type, Amount, Description

9. getUserNotifications()
   - Return own notifications (paginated)
   - Unread notifications shown first
   - Include total unread count

10. markNotificationAsRead()
    - Input: notificationId
    - Set isRead = true for that notification

11. markAllNotificationsAsRead()
    - Set isRead = true for all own notifications

12. getUnreadNotificationCount()
    - Return integer count
    - Used to show badge number on notification icon

----------------------------------------------------
LOAN MANAGEMENT FUNCTIONS (ADDITIONAL)
----------------------------------------------------

4. getLoanById()
   - Return full loan detail:
     risk score, risk level, score breakdown,
     status, decision date, rejection reason, admin name
   - USER: own loans only
   - ADMIN: any loan

5. bulkApproveLoan()
   - ADMIN only
   - Input: list of loanIds
   - Approve all PENDING loans in the list
   - Send notification to each affected user
   - Log to audit: action = BULK_LOAN_APPROVED

6. bulkRejectLoan()
   - ADMIN only
   - Input: list of loanIds, shared reason
   - Reject all PENDING loans in the list
   - Send notification to each affected user
   - Log to audit: action = BULK_LOAN_REJECTED

7. adminGetUserLoanHistory()
   - ADMIN only
   - Input: userId
   - Return full loan history of any specific user
   - Includes: risk scores, decisions, rejection reasons

8. exportLoansCSV()
   - ADMIN only
   - Export loan list with current filters applied
   - Columns: ID, User Name, Email, Amount, Purpose,
              Risk Score, Risk Level, Status,
              Applied Date, Decision Date, Admin Name, Reason

----------------------------------------------------
ADMIN CRUD FUNCTIONS (ADDITIONAL)
----------------------------------------------------

1. adminCreateUser()
   - Input: name, email, role
   - Auto-generate temporary password
   - Save to database
   - Log to audit: action = ADMIN_CREATED_USER

2. adminUpdateUser()
   - Input: userId, name, email, isActive
   - Save changes
   - Log to audit: action = ADMIN_UPDATED_USER

3. adminDeactivateUser()
   - Set isActive = false (data preserved, not deleted)
   - User can no longer login
   - Log to audit: action = ADMIN_DEACTIVATED_USER

4. adminReactivateUser()
   - Set isActive = true
   - Log to audit: action = ADMIN_REACTIVATED_USER

5. adminListUsers()
   - Paginated list of all users
   - Filter by: status (active / inactive)
   - Search by: name or email

6. adminGetUserDetail()
   - Return full profile of any user:
     name, email, role, status, registered date,
     total income, total expense, savings,
     loan count by status, latest risk score

7. adminGetUserTransactions()
   - Input: userId
   - Return full transaction history of any user
   - Paginated, filter by type and date range

8. exportUserListCSV()
   - Columns: ID, Name, Email, Role, Status,
              Registered Date, Total Loans

----------------------------------------------------
NOTIFICATION FUNCTIONS (ADDITIONAL)
----------------------------------------------------

1. sendNotificationToUser()
   - Internal — called automatically by other services
   - Input: userId, title, message, type
   - Types: LOAN_APPROVED, LOAN_REJECTED, BROADCAST, GENERAL

2. sendBroadcastToAllUsers()
   - ADMIN only
   - Input: title, message
   - Save one notification for every active user
   - Log to audit: action = BROADCAST_SENT

3. sendMessageToSpecificUser()
   - ADMIN only
   - Input: userId, title, message
   - Log to audit: action = NOTIFICATION_SENT

----------------------------------------------------
ANALYTICS FUNCTIONS (ADDITIONAL)
----------------------------------------------------

5. getSystemKPISummary()
   - Return: totalUsers, totalLoans, pendingLoans,
     approvalRate (%), averageRiskScore,
     totalApprovedAmount, newUsersThisMonth

6. getMonthlyLoanStatistics() (enhanced)
   - Per month: application count, total amount,
     approved count, rejected count

7. getUserGrowthStats()
   - New user registrations per month (last 6 months)

8. exportAnalyticsReportCSV()
   - ADMIN only
   - Includes: monthly stats, risk distribution, approval rates
   - Return as downloadable CSV

----------------------------------------------------
AUDIT LOGGING (ADDITIONAL)
----------------------------------------------------

Additional events now logged:
- BULK_LOAN_APPROVED
- BULK_LOAN_REJECTED
- ADMIN_CREATED_USER
- ADMIN_UPDATED_USER
- ADMIN_DEACTIVATED_USER
- ADMIN_REACTIVATED_USER
- BROADCAST_SENT
- NOTIFICATION_SENT
- DATA_EXPORTED

Additional columns added to audit_logs table:
- target_id   (UUID of the affected record)
- target_type (e.g. "LOAN", "USER")
- details     (JSON string with extra context)
- ip_address

====================================================
5️⃣ DATABASE STRUCTURE — ADDITIONAL TABLES
====================================================

notifications
- id (UUID)
- user_id (FK → users.id)
- title
- message
- type (LOAN_APPROVED / LOAN_REJECTED / BROADCAST / GENERAL)
- is_read (DEFAULT false)
- created_at

Additional columns on existing tables:
- users        → is_active (DEFAULT true), updated_at
- transactions → is_deleted (DEFAULT false), updated_at
- loans        → purpose, score_breakdown (TEXT/JSON)
- audit_logs   → target_id, target_type, details (TEXT), ip_address

====================================================
7️⃣ FRONTEND STRUCTURE — ADDITIONAL PAGES
====================================================

User (additional pages):
- /loan/history      (detailed: risk score, decision, rejection reason)
- /notifications     (inbox, unread badge, mark read)

Admin (additional pages):
- /admin/loans/[id]       (full detail, approve/reject)
- /admin/users/[id]       (profile, loan history, transaction history)
- /admin/notifications    (send to user, send broadcast)
- /admin/audit-logs       (read-only log table, filter by action/date)

====================================================
8️⃣ REST API ENDPOINTS — ADDITIONAL
====================================================

USER:
GET    /api/users/me/loans/{id}
GET    /api/users/me/transactions/export
GET    /api/users/me/notifications
PUT    /api/users/me/notifications/{id}/read
PUT    /api/users/me/notifications/read-all
GET    /api/users/me/notifications/unread-count

ADMIN:
POST   /api/admin/users
GET    /api/admin/users/{id}
PUT    /api/admin/users/{id}
PUT    /api/admin/users/{id}/deactivate
PUT    /api/admin/users/{id}/reactivate
GET    /api/admin/users/export
GET    /api/admin/users/{id}/loans
GET    /api/admin/users/{id}/transactions
GET    /api/admin/loans/{id}
POST   /api/admin/loans/bulk-approve
POST   /api/admin/loans/bulk-reject
GET    /api/admin/loans/export
GET    /api/admin/analytics/summary
GET    /api/admin/analytics/user-growth
GET    /api/admin/analytics/export
GET    /api/admin/audit-logs
POST   /api/admin/notifications/broadcast
POST   /api/admin/notifications/user/{id}

====================================================
END OF EXTENDED FEATURES
====================================================