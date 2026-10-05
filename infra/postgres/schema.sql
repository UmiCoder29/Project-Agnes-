-- BLACK WALL v0.1 DATABASE SCHEMA
-- PostgreSQL Persistence Layer for Security State, Telemetry, and Experiments

CREATE TABLE IF NOT EXISTS agents (
    agent_id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    runtime_type VARCHAR(64) DEFAULT 'generic',
    registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id UUID PRIMARY KEY,
    agent_id VARCHAR(128) NOT NULL REFERENCES agents(agent_id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMPTZ,
    total_actions BIGINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tools (
    tool_id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    provider VARCHAR(128),
    parameters_schema JSONB,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mcp_servers (
    server_id VARCHAR(128) PRIMARY KEY,
    server_name VARCHAR(255) NOT NULL,
    command TEXT,
    transport VARCHAR(32) NOT NULL DEFAULT 'stdio',
    registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS capabilities (
    capability_id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    resource_scope VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id VARCHAR(255) PRIMARY KEY,
    resource_type VARCHAR(64) NOT NULL,
    uri TEXT NOT NULL,
    classification VARCHAR(64) DEFAULT 'INTERNAL',
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS policies (
    policy_id VARCHAR(128) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    current_version INT NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_versions (
    version_id UUID PRIMARY KEY,
    policy_id VARCHAR(128) NOT NULL REFERENCES policies(policy_id),
    version_number INT NOT NULL,
    policy_definition JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (policy_id, version_number)
);

CREATE TABLE IF NOT EXISTS actions (
    action_id UUID PRIMARY KEY,
    correlation_id UUID NOT NULL,
    test_id VARCHAR(64),
    agent_id VARCHAR(128) NOT NULL,
    session_id UUID,
    action_type VARCHAR(64) NOT NULL,
    target_resource TEXT NOT NULL,
    payload JSONB NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id UUID PRIMARY KEY,
    correlation_id UUID NOT NULL,
    action_id UUID REFERENCES actions(action_id),
    policy_id VARCHAR(128),
    rule_id VARCHAR(128),
    decision VARCHAR(16) NOT NULL, -- ALLOW / DENY
    reason TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enforcement_events (
    enforcement_id UUID PRIMARY KEY,
    correlation_id UUID NOT NULL,
    decision_id UUID REFERENCES policy_decisions(decision_id),
    enforcement_action VARCHAR(64) NOT NULL,
    observed_result VARCHAR(64) NOT NULL,
    error_message TEXT,
    enforced_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id UUID PRIMARY KEY,
    correlation_id UUID NOT NULL,
    test_id VARCHAR(64),
    agent_id VARCHAR(128) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    target_resource TEXT NOT NULL,
    policy_id VARCHAR(128) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    reason TEXT NOT NULL,
    enforcement_action VARCHAR(64) NOT NULL,
    observed_result VARCHAR(64) NOT NULL,
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credentials_metadata (
    credential_id VARCHAR(128) PRIMARY KEY,
    agent_id VARCHAR(128) REFERENCES agents(agent_id),
    scope VARCHAR(255) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS experiments (
    experiment_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    hypothesis TEXT NOT NULL,
    setup_description TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'PLANNED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS test_cases (
    test_case_id VARCHAR(64) PRIMARY KEY,
    experiment_id VARCHAR(64) REFERENCES experiments(experiment_id),
    description TEXT NOT NULL,
    expected_decision VARCHAR(16) NOT NULL,
    expected_result VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS test_runs (
    run_id UUID PRIMARY KEY,
    test_case_id VARCHAR(64) REFERENCES test_cases(test_case_id),
    correlation_id UUID NOT NULL,
    actual_decision VARCHAR(16) NOT NULL,
    actual_result VARCHAR(64) NOT NULL,
    passed BOOLEAN NOT NULL,
    evidence JSONB,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    hypothesis_status VARCHAR(32) NOT NULL, -- SUPPORTED / REFUTED / INCONCLUSIVE
    details TEXT NOT NULL,
    evidence JSONB,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS benchmarks (
    benchmark_id VARCHAR(64) PRIMARY KEY,
    system_name VARCHAR(128) NOT NULL, -- BLACK WALL, OPENSHELL, DEFENSECLAW, CHECK POINT
    test_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL, -- SUPPORTED, BLOCKED, DETECTED, NOT_DETECTED, UNKNOWN, NOT_APPLICABLE
    metrics JSONB,
    notes TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed initial test agents
INSERT INTO agents (agent_id, name, description)
VALUES ('agent-001', 'Primary Test Mock Agent', 'Deterministic test agent for Black Wall experiments')
ON CONFLICT (agent_id) DO NOTHING;
