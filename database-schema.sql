-- ============================================================
-- Smart Micro-Loan Risk Scoring System
-- Database Schema for PostgreSQL
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- ENUMS
-- ============================================================

CREATE TYPE transaction_type AS ENUM ('INCOME', 'EXPENSE');
CREATE TYPE loan_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- ============================================================
-- TABLES
-- ============================================================

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    photo TEXT,
    phone_number VARCHAR(20),
    address TEXT,
    bio TEXT
);

-- Index on email for fast lookup
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- User-Roles join table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token TEXT NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(10) NOT NULL CHECK (type IN ('INCOME', 'EXPENSE')),
    amount NUMERIC(15, 2) NOT NULL CHECK (amount > 0),
    description TEXT,
    transaction_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index on user_id for fast user transaction lookup
CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);

-- Loans table
CREATE TABLE IF NOT EXISTS loans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    loan_amount NUMERIC(15, 2) NOT NULL CHECK (loan_amount > 0),
    monthly_income NUMERIC(15, 2) NOT NULL CHECK (monthly_income >= 0),
    monthly_expense NUMERIC(15, 2) NOT NULL CHECK (monthly_expense >= 0),
    risk_score DOUBLE PRECISION,
    risk_level VARCHAR(10) CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    status VARCHAR(10) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    purpose TEXT,
    admin_note TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index on user_id and status for fast queries
CREATE INDEX IF NOT EXISTS idx_loans_user_id ON loans(user_id);
CREATE INDEX IF NOT EXISTS idx_loans_status ON loans(status);

-- Loan decisions table
CREATE TABLE IF NOT EXISTS loan_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    loan_id UUID NOT NULL UNIQUE REFERENCES loans(id) ON DELETE CASCADE,
    admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
    decision VARCHAR(10) NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
    note TEXT,
    decided_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SEED DATA
-- ============================================================

-- Insert default roles
INSERT INTO roles (name) VALUES ('USER') ON CONFLICT (name) DO NOTHING;
INSERT INTO roles (name) VALUES ('ADMIN') ON CONFLICT (name) DO NOTHING;

-- ============================================================
-- NOTES
-- ============================================================
-- Spring Boot with spring.jpa.hibernate.ddl-auto=update will
-- auto-create/update tables. This script is for manual setup
-- or reference.
--
-- To create an admin user, register normally then run:
-- INSERT INTO user_roles (user_id, role_id)
--   SELECT u.id, r.id FROM users u, roles r
--   WHERE u.email = 'admin@example.com' AND r.name = 'ADMIN';
