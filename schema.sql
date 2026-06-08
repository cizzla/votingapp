-- =========================================================================
-- MERU UNIVERSITY DIGITAL ELECTORAL MANAGEMENT PLATFORM
-- Unified Database Initialization Script (Target Environment: Neon Serverless PostgreSQL)
-- =========================================================================

-- Step 1: Initialize System Extensions for Distributed Cryptographic Keys
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Step 2: Drop Tables Systematically if they exist to allow clean reinstatements
DROP TABLE IF EXISTS ballots CASCADE;
DROP TABLE IF EXISTS candidates CASCADE;
DROP TABLE IF EXISTS elections CASCADE;
DROP TABLE IF EXISTS students CASCADE;
DROP TABLE IF EXISTS faculties CASCADE;

-- Step 3: Base Institutional Context Table
CREATE TABLE faculties (
    faculty_code VARCHAR(16) PRIMARY KEY,
    faculty_name VARCHAR(128) NOT NULL
);

-- Step 4: Master Domain: Student Identification Base Domain
CREATE TABLE students (
    student_id VARCHAR(32) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    faculty_code VARCHAR(16) NOT NULL REFERENCES faculties(faculty_code) ON DELETE RESTRICT,
    is_active_enrollment BOOLEAN NOT NULL DEFAULT TRUE,
    biometric_signature_hash VARCHAR(64) NOT NULL UNIQUE,
    has_voted_active_session BOOLEAN NOT NULL DEFAULT FALSE
);

-- Step 5: Master Domain: Electoral Configuration Parameters
CREATE TABLE elections (
    election_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(128) NOT NULL,
    start_timestamp TIMESTAMPTZ NOT NULL,
    end_timestamp TIMESTAMPTZ NOT NULL,
    electoral_status VARCHAR(32) NOT NULL DEFAULT 'DRAFT',
    CONSTRAINT chk_timeline CHECK (end_timestamp > start_timestamp)
);

-- Step 6: Master Domain: Candidate Profiles 
CREATE TABLE candidates (
    candidate_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    election_id UUID NOT NULL REFERENCES elections(election_id) ON DELETE CASCADE,
    student_id VARCHAR(32) NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
    manifesto TEXT NOT NULL,
    vetting_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    candidate_hash VARCHAR(64) NOT NULL UNIQUE
);

-- Step 7: Transaction Domain: Anonymized Cryptographic Votes Log (Completely decoupled from identity)
CREATE TABLE ballots (
    ballot_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    election_id UUID NOT NULL REFERENCES elections(election_id) ON DELETE RESTRICT,
    candidate_identifier_hash VARCHAR(64) NOT NULL,
    ledger_sequence_number SERIAL NOT NULL,
    previous_block_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================================================================
-- PRODUCTION SEEDING: POPULATING LIVE PARAMETERS FOR TESTING
-- =========================================================================

-- 1. Insert Core Institutional Faculties
INSERT INTO faculties (faculty_code, faculty_name) VALUES 
('SCIT', 'School of Computing and Information Technology'),
('ENG', 'School of Engineering and Architecture'),
('BUSS', 'School of Business and Economics');

-- 2. Insert Base Testing Students (Default Password for both: Password123)
-- STU101 acts as a test candidate, STU102 acts as a regular voting student
INSERT INTO students (student_id, password_hash, faculty_code, biometric_signature_hash, has_voted_active_session) VALUES
('STU101', '$2a$10$X7m8Z7p3VvR99WmW9I3LbuBvM14C7tGfe0fSmq0IecK7L3mB8z31.', 'SCIT', '8f431b818a78e17845bc2498762145fa4bde', FALSE),
('STU102', '$2a$10$X7m8Z7p3VvR99WmW9I3LbuBvM14C7tGfe0fSmq0IecK7L3mB8z31.', 'ENG', '9a431b818a78e17845bc2498762145fa4bde', FALSE);

-- 3. Insert an Active, Live Election Window (Current Window 2026)
INSERT INTO elections (election_id, title, start_timestamp, end_timestamp, electoral_status) VALUES
('e1c72051-2db0-4c40-b6cb-78adcb0bc86c', 'MUSA General Presidential Election 2026', NOW() - INTERVAL '1 day', NOW() + INTERVAL '7 days', 'ACTIVE');

-- 4. Insert an Approved Candidate Linked to the Active Election
INSERT INTO candidates (candidate_id, election_id, student_id, manifesto, vetting_status, candidate_hash) VALUES
('c9a83421-1bfa-4927-99cf-832145fa4bde', 'e1c72051-2db0-4c40-b6cb-78adcb0bc86c', 'STU101', 'Driving radical transparency and automated digital resource distribution frameworks across all campus faculties.', 'APPROVED', '8f431b818a78e17845bc2498762145fa4bde7c10b7b120f26317bde90abcd123');

-- =========================================================================
-- VERIFICATION CHECK
-- =========================================================================
SELECT 'Schema initialized successfully!' AS build_status;
