# LoanRisk — Smart Micro-Loan Risk Scoring System

A full-stack web application for micro-loan management with automated risk scoring, a real-time admin dashboard, JWT authentication, and live notification badges.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Risk Scoring Algorithm](#risk-scoring-algorithm)
- [Prerequisites](#prerequisites)
- [Local Setup](#local-setup)
- [API Reference](#api-reference)
- [Deployment](#deployment)

---

## Features

### User Features

- **Authentication** — Register, login, JWT access tokens + refresh tokens via HTTP-only cookies
- **Dashboard** — Overview of loan status, recent transactions, and quick actions
- **Transaction Management** — Record income and expense transactions with filters and CSV export
- **Loan Applications** — Apply for micro-loans; track status (Pending / Approved / Active / Rejected)
- **Notifications** — Real-time badge count with 30-second polling
- **Loan History** — Filter past loans by status; view full detail pages

### Admin Features

- **Admin Dashboard** — Stat cards, loan status doughnut chart, approval trend line chart
- **Applicants Panel** — Table and card views with status / risk / date filters and pagination
- **Loan Detail Review** — Full applicant financials, risk score bar, and one-click approve / reject with notes
- **User Management** — List, search, and manage all registered users
- **Analytics** — Aggregate loan metrics and risk distribution charts
- **Audit Logs** — Immutable record of all admin actions
- **Role-Based Access** — `USER` and `ADMIN` roles enforced on every endpoint

### Technical Highlights

- Automated risk score (0–100) calculated server-side on every loan application
- Skeleton loading states on all pages for production-grade UX
- Token refresh interceptor — silently renews expired access tokens
- Toast notification system for all user actions
- Fully responsive layout (mobile to desktop)

---

## Tech Stack

| Layer      | Technology                                                     |
| ---------- | -------------------------------------------------------------- |
| Frontend   | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS v4 |
| Backend    | Spring Boot 3.4.3, Java 21, Spring Security                    |
| Database   | PostgreSQL 14+                                                 |
| Auth       | JWT (JJWT) + HTTP-only refresh-token cookie                    |
| ORM        | Spring Data JPA / Hibernate                                    |
| Deployment | Vercel (frontend) · Render + Docker (backend)                  |

---

## Project Structure

```
additi-final-project/
├── backend/                          # Spring Boot application
│   ├── Dockerfile
│   ├── render.yaml                   # Render deployment config
│   └── src/main/java/groupproject/
│       ├── config/                   # Security config, JWT filter, CORS
│       ├── controller/               # REST controllers
│       ├── dto/                      # Data Transfer Objects
│       ├── exception/                # Global exception handler
│       ├── model/                    # JPA entities (User, Loan, Transaction...)
│       ├── repository/               # Spring Data repositories
│       ├── request/                  # Request body classes
│       ├── response/                 # ApiResponse wrapper
│       ├── service/                  # Business logic
│       └── util/                     # JWT utils, risk scoring
└── frontend/                         # Next.js application
    ├── app/                          # App Router pages
    │   ├── (landing)/                # Public marketing pages
    │   ├── dashboard/                # User dashboard
    │   ├── transactions/             # Transaction management
    │   ├── loan/apply|status|history # Loan flows
    │   ├── notifications/
    │   └── admin/                    # Admin-only pages
    │       ├── dashboard/
    │       ├── applicants/
    │       ├── loans/[id]/           # Loan detail + decision
    │       ├── users/
    │       ├── analytics/
    │       └── audit-logs/
    ├── components/                   # Reusable UI components
    ├── context/                      # AuthContext (JWT state)
    ├── services/api.ts               # Axios instance + interceptors
    └── types/index.ts                # TypeScript interfaces
```

---

## Risk Scoring Algorithm

The backend calculates a risk score (0–100) on every loan application:

```
Score = (incomeScore × 0.3) + (expenseScore × 0.2) + (transactionScore × 0.2) + (savingsScore × 0.3)

incomeScore:       monthly income >= $1,000 → 100  |  $500–999 → 70  |  < $500 → 40
expenseScore:      expenses < 50% of income → 100  |  < 80% → 70      |  >= 80% → 30
transactionScore:  > 30 transactions → 100          |  > 10 → 70        |  <= 10 → 40
savingsScore:      net savings > $300 → 100         |  > $100 → 70     |  <= $100 → 40

Risk Level:  score >= 80 → LOW  |  50–79 → MEDIUM  |  < 50 → HIGH
```

---

## Prerequisites

| Tool       | Minimum Version |
| ---------- | --------------- |
| Java       | 21              |
| Maven      | 3.8             |
| Node.js    | 18              |
| PostgreSQL | 14              |

---

## Local Setup

### 1. Database

Create the database:

```sql
CREATE DATABASE loanrisk_db;
```

Spring Boot will auto-create all tables on first run (`ddl-auto=update`).

To grant admin access to a registered user:

```sql
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.email = 'admin@example.com' AND r.name = 'ADMIN';
```

---

### 2. Backend

```bash
cd backend
```

Set required environment variables:

```bash
DB_URL=jdbc:postgresql://localhost:5432/loanrisk_db
DB_USERNAME=postgres
DB_PASSWORD=your_password
JWT_SECRET=your-very-long-secret-key-at-least-256-bits
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

Run:

```bash
# macOS / Linux
./mvnw spring-boot:run

# Windows
mvnw.cmd spring-boot:run
```

The API starts on **http://localhost:8080**

---

### 3. Frontend

```bash
cd frontend
```

Create `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

Install and run:

```bash
npm install
npm run dev
```

The app starts on **http://localhost:3000**

---

## API Reference

### Authentication

| Method | Endpoint             | Auth   | Description                 |
| ------ | -------------------- | ------ | --------------------------- |
| POST   | `/api/auth/register` | Public | Register new user           |
| POST   | `/api/auth/login`    | Public | Login, returns JWT + cookie |
| GET    | `/api/auth/me`       | Bearer | Get current user            |
| PUT    | `/api/auth/profile`  | Bearer | Update profile              |
| POST   | `/api/auth/logout`   | Bearer | Logout (clears cookie)      |
| POST   | `/api/auth/refresh`  | Cookie | Refresh access token        |

### Transactions

| Method | Endpoint                 | Auth   | Description          |
| ------ | ------------------------ | ------ | -------------------- |
| POST   | `/api/transactions`      | Bearer | Record a transaction |
| GET    | `/api/transactions`      | Bearer | Get my transactions  |
| DELETE | `/api/transactions/{id}` | Bearer | Delete a transaction |

### Loans

| Method | Endpoint           | Auth   | Description         |
| ------ | ------------------ | ------ | ------------------- |
| POST   | `/api/loans/apply` | Bearer | Apply for a loan    |
| GET    | `/api/loans/my`    | Bearer | Get my loan history |
| GET    | `/api/loans/{id}`  | Bearer | Get loan detail     |

### Admin

| Method | Endpoint                          | Auth   | Description                     |
| ------ | --------------------------------- | ------ | ------------------------------- |
| GET    | `/api/admin/loans`                | ADMIN  | All loans (paginated, filtered) |
| GET    | `/api/admin/loans/{id}`           | ADMIN  | Loan detail                     |
| POST   | `/api/admin/loans/{id}/decide`    | ADMIN  | Approve or reject loan          |
| GET    | `/api/admin/users`                | ADMIN  | All users                       |
| GET    | `/api/admin/analytics`            | ADMIN  | Aggregate analytics             |
| GET    | `/api/admin/audit-logs`           | ADMIN  | Audit log entries               |
| GET    | `/api/notifications/unread-count` | Bearer | Unread notification count       |

---

## Deployment

### Backend → Render

The backend is containerised with Docker and deployed on [Render](https://render.com).

1. Push the repository to GitHub.
2. On Render, create a new **Web Service** and select the repository.
3. Set **Root Directory** to `backend` — Render uses `Dockerfile` automatically.
4. Set the following **environment variables** in the Render dashboard (mark sensitive ones as Secret):

   | Variable                 | Description                      |
   | ------------------------ | -------------------------------- |
   | `DB_URL`                 | PostgreSQL JDBC connection URL   |
   | `DB_USERNAME`            | Database username                |
   | `DB_PASSWORD`            | Database password                |
   | `JWT_SECRET`             | Random string, at least 256 bits |
   | `CORS_ALLOWED_ORIGINS`   | Your Vercel frontend URL         |
   | `SPRING_PROFILES_ACTIVE` | `prod`                           |

5. Use Render's managed **PostgreSQL** add-on and copy its internal URL into `DB_URL`.

---

### Frontend → Vercel

1. Import the repository on [Vercel](https://vercel.com).
2. Set **Root Directory** to `frontend`.
3. Add the environment variable:

   | Variable              | Value                   |
   | --------------------- | ----------------------- |
   | `NEXT_PUBLIC_API_URL` | Your Render backend URL |

4. Deploy — Vercel redeploys automatically on every push to `main`.

> **CORS note:** After getting your Vercel URL, update `CORS_ALLOWED_ORIGINS` on Render and redeploy the backend.
