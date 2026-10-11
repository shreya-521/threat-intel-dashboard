-- ============================================================
-- SAMPLE DATA - Threat Intelligence Tracker
-- Based on PUBLICLY KNOWN information from security reports
-- ALL DATA IS FOR EDUCATIONAL PURPOSES ONLY
-- Sources: MITRE ATT&CK, CISA Advisories, Public CVE databases
-- ============================================================

USE threat_intel_db;

-- ------------------------------------------------------------
-- THREAT ACTORS (Based on public MITRE ATT&CK entries)
-- ------------------------------------------------------------
INSERT INTO threat_actors (actor_name, alias, origin_country, motivation, sophistication, first_seen, last_active, description) VALUES
('APT28',          'Fancy Bear, Sofacy, STRONTIUM',        'Russia',       'Espionage',    'Nation-State', '2004-01-01', '2024-09-01', 'Russian GRU-linked group targeting governments and military'),
('Lazarus Group',  'HIDDEN COBRA, Guardians of Peace',     'North Korea',  'Financial',    'Nation-State', '2009-01-01', '2024-10-01', 'North Korean state-sponsored group targeting banks and crypto'),
('REvil',          'Sodinokibi',                           'Russia',       'Ransomware',   'High',         '2019-04-01', '2022-01-01', 'Prolific ransomware-as-a-service group'),
('APT41',          'Double Dragon, Winnti Group',          'China',        'Espionage',    'Nation-State', '2012-01-01', '2024-08-01', 'Chinese group conducting both espionage and cybercrime'),
('Anonymous',      'AnonSec',                              'Unknown',      'Hacktivism',   'Medium',       '2003-01-01', '2024-09-15', 'Decentralized hacktivist collective'),
('DarkSide',       'BlackMatter',                          'Russia',       'Ransomware',   'High',         '2020-08-01', '2021-11-01', 'Responsible for Colonial Pipeline attack'),
('Cozy Bear',      'APT29, The Dukes',                     'Russia',       'Espionage',    'Nation-State', '2008-01-01', '2024-07-01', 'Russian SVR-linked group, involved in SolarWinds breach'),
('Scattered Spider','UNC3944, Muddled Libra',              'Unknown',      'Financial',    'High',         '2022-05-01', '2024-10-01', 'Social engineering specialists targeting cloud environments');

-- ------------------------------------------------------------
-- IOC RECORDS
-- ------------------------------------------------------------
INSERT INTO ioc_records (ioc_type, ioc_value, threat_type, severity, confidence, actor_id, source, first_seen, last_seen, tags) VALUES
('IP',        '185.234.219.xx',        'C2',         'Critical', 95, 1, 'AlienVault OTX',  '2024-01-15 08:00:00', '2024-09-10 12:00:00', 'APT28,C2,Russia'),
('IP',        '91.108.4.xxx',          'Malware',    'High',     87, 2, 'VirusTotal',       '2024-02-20 10:00:00', '2024-08-15 09:00:00', 'Lazarus,Dropper'),
('Domain',    'secure-update-cdn.net', 'Phishing',   'High',     90, 1, 'PhishTank',        '2024-03-01 00:00:00', '2024-07-22 00:00:00', 'APT28,Phishing,Credential'),
('File_Hash', 'd41d8cd98f00b204e9800998ecf8427e', 'Ransomware', 'Critical', 99, 3, 'MalwareBazaar', '2024-01-05 00:00:00', '2024-06-30 00:00:00', 'REvil,Ransomware'),
('Domain',    'win-update-microsoft.xyz', 'Malware', 'Critical', 92, 4, 'CISA Advisory',   '2024-04-10 00:00:00', '2024-09-05 00:00:00', 'APT41,Spearphishing'),
('URL',       'http://login-paypal-verify.ru/auth', 'Phishing', 'High', 88, NULL, 'PhishTank', '2024-05-01 00:00:00', '2024-08-20 00:00:00', 'Phishing,Financial'),
('CVE',       'CVE-2024-3400',         'Exploit',    'Critical', 100, NULL, 'NVD',          '2024-04-12 00:00:00', '2024-09-30 00:00:00', 'Zero-Day,PAN-OS,Exploit'),
('Email',     'noreply-security@microsoft-alerts.org', 'Phishing', 'Medium', 75, NULL, 'OpenPhish', '2024-06-01 00:00:00', '2024-08-01 00:00:00', 'Phishing,BEC'),
('IP',        '103.75.190.xxx',        'Botnet',     'Medium',   70, 5, 'Shodan',           '2024-03-15 00:00:00', '2024-07-10 00:00:00', 'Botnet,Anonymous'),
('File_Hash', 'a87ff679a2f3e71d9181a67b7542122c', 'Malware', 'High', 93, 6, 'MalwareBazaar', '2024-05-18 00:00:00', '2024-09-01 00:00:00', 'DarkSide,Wiper');

-- ------------------------------------------------------------
-- LEAKED CREDENTIALS (Based on publicly known breaches)
-- ------------------------------------------------------------
INSERT INTO leaked_credentials (breach_name, breach_date, discovered_date, affected_sector, records_exposed, data_types, severity, actor_id, country_affected) VALUES
('LinkedIn Data Breach 2021',    '2021-04-06', '2021-04-08', 'Technology',   700000000,  'Name, Email, Phone, LinkedIn URL',      'High',     NULL, 'Global'),
('RockYou2024 Password Leak',    '2024-07-04', '2024-07-06', 'Multiple',    9948575739,  'Passwords',                              'Critical', NULL, 'Global'),
('LastPass Breach 2022',         '2022-08-25', '2022-12-22', 'Technology',   33000000,   'Encrypted Passwords, URLs, Usernames',  'Critical', NULL, 'Global'),
('MOVEit Transfer Breach 2023',  '2023-05-27', '2023-06-01', 'Government',   60000000,   'SSN, DOB, Name, Address',               'Critical', 3,    'USA, UK, Germany'),
('MGM Resorts Breach 2023',      '2023-09-11', '2023-09-13', 'Hospitality',  30000000,   'Name, DOB, Drivers License, Passport',  'Critical', 8,    'USA'),
('AT&T Data Breach 2024',        '2024-03-17', '2024-03-30', 'Telecom',      73000000,   'SSN, Passcode, Name, Email, DOB',       'Critical', NULL, 'USA'),
('Ticketmaster Breach 2024',     '2024-04-14', '2024-05-28', 'Entertainment',560000000,  'Name, Email, Payment Card',             'Critical', NULL, 'USA, Canada, Australia'),
('Change Healthcare 2024',       '2024-02-21', '2024-03-13', 'Healthcare',   100000000,  'Medical Records, SSN, DOB',             'Critical', 2,    'USA'),
('Trello API Exposure 2024',     '2024-01-15', '2024-01-22', 'Technology',   15000000,   'Email, Name, Username',                 'Medium',   NULL, 'Global'),
('Infosys McCamish Breach 2024', '2023-11-02', '2024-02-01', 'Finance',      6000000,    'SSN, Bank Account, Name, DOB',          'High',     NULL, 'USA');

-- ------------------------------------------------------------
-- ATTACK CAMPAIGNS
-- ------------------------------------------------------------
INSERT INTO attack_campaigns (campaign_name, actor_id, start_date, end_date, status, attack_type, targeted_sector, targeted_region, tools_used, description) VALUES
('Operation Cloud Hopper',   4, '2014-01-01', '2017-12-31', 'Completed', 'APT',                'Technology, MSP',           'USA, UK, Australia, Japan', 'PlugX, RedLeaves, QuasarRAT',        'APT10 compromise of MSPs to reach downstream customers'),
('SolarWinds SUNBURST',      7, '2019-10-01', '2021-01-01', 'Completed', 'Supply-Chain',       'Government, Technology',    'USA, Europe',               'SUNBURST, TEARDROP, SUNSPOT',        'Supply chain attack via SolarWinds Orion platform update'),
('Colonial Pipeline Attack', 6, '2021-05-07', '2021-05-13', 'Completed', 'Ransomware',         'Energy, Infrastructure',    'USA',                       'DarkSide Ransomware',                'Ransomware attack shutting down major US fuel pipeline'),
('Operation Dream Job',      2, '2023-01-01', NULL,          'Active',    'Social-Engineering', 'Aerospace, Defense',        'USA, Europe, India',        'BLINDINGCAN, COPPERHEDGE',           'Fake job offers targeting aerospace engineers via LinkedIn'),
('Scattered Spider Telecom', 8, '2023-06-01', '2024-06-01', 'Completed', 'Phishing',           'Telecom, Hospitality',      'USA',                       'Okta phishing, Sim Swapping',        'Social engineering attacks against major US telecoms'),
('APT28 NATO Spearphish',   1, '2024-01-01', NULL,          'Active',    'Phishing',           'Government, Military, NGO', 'Europe, USA',               'HEADLACE, MASEPIE',                  'Spearphishing campaigns targeting NATO-aligned organizations'),
('Operation Crimson Palace', 4, '2023-03-01', '2024-06-01', 'Completed', 'APT',                'Government',                'Southeast Asia',            'NUPAKAGE, PROPSIDE',                 'Long-term espionage campaign in Southeast Asian government'),
('Cl0p MOVEit Campaign',  NULL,'2023-05-27', '2023-12-31', 'Completed', 'Zero-Day',           'Government, Finance, Health','USA, Europe, Canada',       'MOVEit Exploit (CVE-2023-34362)',    'Mass exploitation of MOVEit Transfer zero-day vulnerability');

-- ------------------------------------------------------------
-- SECTOR IMPACT
-- ------------------------------------------------------------
INSERT INTO sector_impact (sector_name, ioc_id, campaign_id, incident_date, country, impact_level, estimated_loss) VALUES
('Energy',       3, 3, '2021-05-07', 'USA',       'Critical', 4400000.00),
('Government',   5, 2, '2020-12-13', 'USA',       'Critical', 18000000.00),
('Healthcare',   4, NULL,'2024-02-21','USA',       'Critical', 22000000.00),
('Technology',   1, 1, '2024-03-15', 'UK',        'High',     5000000.00),
('Finance',      6, NULL,'2024-01-10','India',     'High',     1200000.00),
('Telecom',      9, 5, '2023-09-11', 'USA',       'Critical', 100000000.00),
('Aerospace',    2, 4, '2023-06-20', 'Germany',   'High',     8000000.00),
('Entertainment',7, NULL,'2024-05-28','Australia', 'High',     500000.00),
('Education',    8, NULL,'2024-04-01','USA',       'Medium',   300000.00),
('Manufacturing',10,3, '2024-03-10', 'Canada',    'High',     2500000.00);

-- ------------------------------------------------------------
-- DARK WEB MENTIONS
-- ------------------------------------------------------------
INSERT INTO darkweb_mentions (target_entity, mention_type, forum_source, mention_date, severity, sector, country, actor_id, verified, description) VALUES
('Major US Hospital Chain',   'Data_Sale',       'BreachForums',   '2024-08-15', 'Critical', 'Healthcare',    'USA',     2,    TRUE,  '2.5M patient records offered for $150k in crypto'),
('European Bank Credentials', 'Credential_Sale', 'XSS Forum',      '2024-07-22', 'High',     'Finance',       'Germany', NULL, TRUE,  '50k banking credentials including 2FA bypass methods'),
('Government VPN Access',     'Data_Sale',       'Exploit.in',     '2024-09-01', 'Critical', 'Government',    'India',   1,    FALSE, 'Claimed access to government VPN sold for $25k'),
('Fortune 500 RDP Access',    'Data_Sale',       'RaidForums',     '2024-06-10', 'Critical', 'Technology',    'USA',     NULL, TRUE,  'Initial access broker selling RDP access to tech firm'),
('APT Recruitment Post',      'Recruitment',     'Dark Forum XYZ', '2024-08-01', 'Medium',   'Unknown',       'Unknown', NULL, FALSE, 'Threat actor recruiting pentesters for ransomware ops'),
('US Telecom Source Code',    'Data_Sale',       'BreachForums',   '2024-05-15', 'High',     'Telecom',       'USA',     8,    TRUE,  'Scattered Spider claims telecom source code for sale'),
('Ransomware Builder v4.0',   'Tool_Sale',       'Exploit.in',     '2024-07-01', 'Critical', 'Multiple',      'Unknown', NULL, FALSE, 'New ransomware-as-a-service kit advertised for $500/month'),
('UK Energy Firm Access',     'Threat',          'Telegram Channel','2024-09-10','Critical', 'Energy',        'UK',      6,    FALSE, 'Threat to release stolen data if ransom not paid'),
('Student Database Dump',     'Data_Sale',       'BreachForums',   '2024-08-30', 'Medium',   'Education',     'Australia',NULL,TRUE,  '300k student records including grades and contact info'),
('Banking Trojan Source',     'Tool_Sale',       'XSS Forum',      '2024-06-25', 'High',     'Finance',       'Unknown', 2,    FALSE, 'Lazarus-linked banking trojan source code for sale');
