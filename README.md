# Smart Micro-Loan Risk Scoring System

A full-stack web application for micro-loan management with automated risk scoring.

## Tech Stack

| Layer    | Technology                                        |
| -------- | ------------------------------------------------- |
| Frontend | Next.js 14 (App Router), TypeScript, Tailwind CSS |
| Backend  | Spring Boot 4.0.3, Java 21, Spring Security       |
| Database | PostgreSQL                                        |
| Auth     | JWT (JJWT 0.11.5) + Refresh Tokens                |
| ORM      | Spring Data JPA / Hibernate                       |

## Features

- **User Authentication** — Register, Login, JWT access + refresh tokens
- **Transaction Management** — Record income and expense transactions
- **Loan Applications** — Apply for micro-loans with financial details
- **Automated Risk Scoring** — Weighted algorithm calculates risk score (0–100)
- **Admin Panel** — Approve or reject loan applications with notes
- **Role-Based Access** — USER and ADMIN roles with protected endpoints

## Risk Scoring Algorithm

```
Score = (incomeScore × 0.3) + (expenseScore × 0.2) + (transactionScore × 0.2) + (savingsScore × 0.3)

incomeScore:   ≥$1000 → 100 | $500–999 → 70 | <$500 → 40
expenseScore:  <50% of income → 100 | <80% → 70 | else → 30
transactionScore: >30 transactions → 100 | >10 → 70 | else → 40
savingsScore:  savings >$300 → 100 | >$100 → 70 | else → 40

Risk Level: ≥80 → LOW | 50–79 → MEDIUM | <50 → HIGH
```

## Project Structure

```
additi-final-project/
├── backend/                    # Spring Boot application
│   └── src/main/java/groupproject/backend/
│       ├── config/             # Security, JWT filter
│       ├── controller/         # REST controllers
│       ├── dto/                # Data Transfer Objects
│       ├── exception/          # Global exception handler
│       ├── model/              # JPA entities + enums
│       ├── repository/         # Spring Data repositories
│       ├── request/            # Request bodies
│       ├── response/           # Response wrappers
│       ├── service/            # Business logic interfaces + impls
│       └── util/               # Utilities
├── frontend/                   # Next.js application
│   ├── app/                    # App Router pages
│   │   ├── login/
│   │   ├── register/
│   │   ├── dashboard/
│   │   ├── transactions/
│   │   ├── loan/apply/
│   │   ├── loan/status/
│   │   ├── admin/dashboard/
│   │   └── admin/applicants/
│   ├── components/             # Reusable UI components
│   ├── context/                # React Context (AuthContext)
│   ├── services/               # Axios API service
│   └── types/                  # TypeScript interfaces
└── database-schema.sql         # PostgreSQL schema reference
```

## Prerequisites

- Java 21+
- Node.js 18+
- PostgreSQL 14+
- Maven 3.8+

## Setup Instructions

### 1. Database Setup

Create a PostgreSQL database:

```sql
CREATE DATABASE loanrisk_db;
```

Optionally run the schema file:

```bash
psql -U postgres -d loanrisk_db -f database-schema.sql
```

### 2. Backend Setup

Navigate to the backend directory:

```bash
cd backend
```

Create environment variables (or set them in your system):

```bash
# Required environment variables
DB_URL=jdbc:postgresql://localhost:5432/loanrisk_db
DB_USERNAME=postgres
DB_PASSWORD=your_password
JWT_SECRET=your-very-long-secret-key-at-least-256-bits-long
```

Run the application:

```bash
./mvnw spring-boot:run
```

The backend starts on **http://localhost:8080**

Spring Boot will auto-create tables via `spring.jpa.hibernate.ddl-auto=update`.

**Create an admin user** — after registering a user, run this SQL:

```sql
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.email = 'your-admin@email.com' AND r.name = 'ADMIN';
```

### 3. Frontend Setup

Navigate to the frontend directory:

```bash
cd frontend
```

Create `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

Install dependencies and run:

```bash
npm install
npm run dev
```

The frontend starts on **http://localhost:3000**

## API Endpoints

### Auth

| Method | Endpoint             | Auth   | Description          |
| ------ | -------------------- | ------ | -------------------- |
| POST   | `/api/auth/register` | Public | Register new user    |
| POST   | `/api/auth/login`    | Public | Login, returns JWT   |
| GET    | `/api/auth/me`       | Bearer | Get current user     |
| PUT    | `/api/auth/profile`  | Bearer | Update profile       |
| POST   | `/api/auth/logout`   | Bearer | Logout               |
| POST   | `/api/auth/refresh`  | Cookie | Refresh access token |

### Transactions

| Method | Endpoint            | Auth   | Description         |
| ------ | ------------------- | ------ | ------------------- |
| POST   | `/api/transactions` | Bearer | Add transaction     |
| GET    | `/api/transactions` | Bearer | Get my transactions |

### Loans

| Method | Endpoint           | Auth   | Description    |
| ------ | ------------------ | ------ | -------------- |
| POST   | `/api/loans/apply` | Bearer | Apply for loan |
| GET    | `/api/loans/my`    | Bearer | Get my loans   |

### Admin

| Method | Endpoint                       | Auth  | Description         |
| ------ | ------------------------------ | ----- | ------------------- |
| GET    | `/api/admin/loans`             | ADMIN | Get all loans       |
| GET    | `/api/admin/loans/pending`     | ADMIN | Get pending loans   |
| POST   | `/api/admin/loans/{id}/decide` | ADMIN | Approve/reject loan |

## Example API Requests

### Register

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "password123",
    "confirmPassword": "password123"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Add Transaction

```bash
curl -X POST http://localhost:8080/api/transactions \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "INCOME",
    "amount": 2500.00,
    "description": "Monthly salary"
  }'
```

### Apply for Loan

```bash
curl -X POST http://localhost:8080/api/loans/apply \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "loanAmount": 5000.00,
    "monthlyIncome": 3000.00,
    "monthlyExpense": 1200.00,
    "purpose": "Business expansion"
  }'
```

### Admin: Approve Loan

```bash
curl -X POST http://localhost:8080/api/admin/loans/<loan-id>/decide \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "APPROVED",
    "note": "Good financial profile."
  }'
```

## Environment Variables Reference

### Backend (`application.properties`)

| Variable      | Description                      | Example                                        |
| ------------- | -------------------------------- | ---------------------------------------------- |
| `DB_URL`      | PostgreSQL JDBC URL              | `jdbc:postgresql://localhost:5432/loanrisk_db` |
| `DB_USERNAME` | Database username                | `postgres`                                     |
| `DB_PASSWORD` | Database password                | `secret`                                       |
| `JWT_SECRET`  | JWT signing secret (min 256-bit) | `your-256-bit-secret`                          |

### Frontend (`.env.local`)

| Variable              | Description          | Default                 |
| --------------------- | -------------------- | ----------------------- |
| `NEXT_PUBLIC_API_URL` | Backend API base URL | `http://localhost:8080` |

## License

MIT
