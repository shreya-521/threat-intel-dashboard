-- ============================================================
-- DARK WEB & THREAT INTELLIGENCE TRACKER
-- SQL Schema - Database: threat_intel_db
-- ============================================================

CREATE DATABASE IF NOT EXISTS threat_intel_db;
USE threat_intel_db;

-- ------------------------------------------------------------
-- 1. THREAT ACTORS TABLE
--    Profiles of known hacker groups / APT groups
-- ------------------------------------------------------------
CREATE TABLE threat_actors (
    actor_id        INT AUTO_INCREMENT PRIMARY KEY,
    actor_name      VARCHAR(100) NOT NULL,          -- e.g. 'APT28', 'Lazarus Group'
    alias           VARCHAR(200),                   -- Other known names
    origin_country  VARCHAR(100),                   -- Suspected country of origin
    motivation      ENUM('Financial','Espionage','Hacktivism','Ransomware','Unknown'),
    sophistication  ENUM('Low','Medium','High','Nation-State'),
    first_seen      DATE,
    last_active     DATE,
    active_status   BOOLEAN DEFAULT TRUE,
    description     TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------------------------
-- 2. INDICATORS OF COMPROMISE (IOC) TABLE
--    Malicious IPs, domains, hashes, URLs
-- ------------------------------------------------------------
CREATE TABLE ioc_records (
    ioc_id          INT AUTO_INCREMENT PRIMARY KEY,
    ioc_type        ENUM('IP','Domain','URL','File_Hash','Email','CVE') NOT NULL,
    ioc_value       VARCHAR(500) NOT NULL,
    threat_type     ENUM('Malware','Phishing','Ransomware','C2','Botnet','Exploit','Data_Leak','Other'),
    severity        ENUM('Critical','High','Medium','Low') DEFAULT 'Medium',
    confidence      INT CHECK (confidence BETWEEN 0 AND 100),
    actor_id        INT,
    source          VARCHAR(200),
    first_seen      DATETIME,
    last_seen       DATETIME,
    is_active       BOOLEAN DEFAULT TRUE,
    tags            VARCHAR(500),
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES threat_actors(actor_id)
);

-- ------------------------------------------------------------
-- 3. LEAKED CREDENTIALS TABLE
--    Data breach / credential dump records
-- ------------------------------------------------------------
CREATE TABLE leaked_credentials (
    leak_id         INT AUTO_INCREMENT PRIMARY KEY,
    breach_name     VARCHAR(200) NOT NULL,
    breach_date     DATE,
    discovered_date DATE,
    affected_sector VARCHAR(100),
    records_exposed BIGINT,
    data_types      VARCHAR(300),
    source_url      VARCHAR(500),
    severity        ENUM('Critical','High','Medium','Low'),
    actor_id        INT,
    country_affected VARCHAR(200),
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES threat_actors(actor_id)
);

-- ------------------------------------------------------------
-- 4. CAMPAIGNS TABLE
--    Active/past attack campaigns
-- ------------------------------------------------------------
CREATE TABLE attack_campaigns (
    campaign_id     INT AUTO_INCREMENT PRIMARY KEY,
    campaign_name   VARCHAR(200) NOT NULL,
    actor_id        INT,
    start_date      DATE,
    end_date        DATE,
    status          ENUM('Active','Completed','Dormant','Unknown') DEFAULT 'Unknown',
    attack_type     ENUM('Phishing','Ransomware','Supply-Chain','Zero-Day','DDoS','APT','Social-Engineering','Other'),
    targeted_sector VARCHAR(200),
    targeted_region VARCHAR(200),
    tools_used      VARCHAR(500),
    description     TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES threat_actors(actor_id)
);

-- ------------------------------------------------------------
-- 5. SECTOR IMPACT TABLE
--    For mapping attacks to industry sectors
-- ------------------------------------------------------------
CREATE TABLE sector_impact (
    impact_id       INT AUTO_INCREMENT PRIMARY KEY,
    sector_name     VARCHAR(100) NOT NULL,
    ioc_id          INT,
    campaign_id     INT,
    incident_date   DATE,
    country         VARCHAR(100),
    impact_level    ENUM('Critical','High','Medium','Low'),
    estimated_loss  DECIMAL(15,2),
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES ioc_records(ioc_id),
    FOREIGN KEY (campaign_id) REFERENCES attack_campaigns(campaign_id)
);

-- ------------------------------------------------------------
-- 6. DARK WEB MENTIONS TABLE
--    Tracks mentions on dark web forums (from public threat intel feeds)
-- ------------------------------------------------------------
CREATE TABLE darkweb_mentions (
    mention_id      INT AUTO_INCREMENT PRIMARY KEY,
    target_entity   VARCHAR(200),
    mention_type    ENUM('Credential_Sale','Data_Sale','Threat','Recruitment','Tool_Sale','Other'),
    forum_source    VARCHAR(200),
    mention_date    DATE,
    severity        ENUM('Critical','High','Medium','Low'),
    sector          VARCHAR(100),
    country         VARCHAR(100),
    actor_id        INT,
    verified        BOOLEAN DEFAULT FALSE,
    description     TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES threat_actors(actor_id)
);

-- ------------------------------------------------------------
-- INDEXES for Query Performance
-- ------------------------------------------------------------
CREATE INDEX idx_ioc_type       ON ioc_records(ioc_type);
CREATE INDEX idx_ioc_severity   ON ioc_records(severity);
CREATE INDEX idx_ioc_threat_type ON ioc_records(threat_type);
CREATE INDEX idx_ioc_first_seen ON ioc_records(first_seen);
CREATE INDEX idx_actor_country  ON threat_actors(origin_country);
CREATE INDEX idx_leak_sector    ON leaked_credentials(affected_sector);
CREATE INDEX idx_campaign_status ON attack_campaigns(status);
CREATE INDEX idx_darkweb_date   ON darkweb_mentions(mention_date);
