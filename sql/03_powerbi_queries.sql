-- ============================================================
-- ANALYTICAL QUERIES FOR POWER BI
-- Dark Web & Threat Intelligence Tracker
-- ============================================================

USE threat_intel_db;

-- ============================================================
-- QUERY 1: IOC Severity Breakdown (Donut / Bar Chart)
-- ============================================================
SELECT 
    severity,
    COUNT(*) AS total_iocs,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS percentage
FROM ioc_records
WHERE is_active = TRUE
GROUP BY severity
ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low');

-- ============================================================
-- QUERY 2: Monthly IOC Detection Trend (Line Chart)
-- ============================================================
SELECT 
    DATE_FORMAT(first_seen, '%Y-%m') AS month_year,
    ioc_type,
    COUNT(*) AS ioc_count,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_count
FROM ioc_records
GROUP BY DATE_FORMAT(first_seen, '%Y-%m'), ioc_type
ORDER BY month_year;

-- ============================================================
-- QUERY 3: Top Threat Actors by Activity (Bar Chart)
-- ============================================================
SELECT 
    ta.actor_name,
    ta.origin_country,
    ta.motivation,
    ta.sophistication,
    COUNT(DISTINCT ir.ioc_id)       AS total_iocs,
    COUNT(DISTINCT ac.campaign_id)  AS total_campaigns,
    COUNT(DISTINCT lc.leak_id)      AS linked_breaches,
    COUNT(DISTINCT dm.mention_id)   AS darkweb_mentions
FROM threat_actors ta
LEFT JOIN ioc_records ir        ON ta.actor_id = ir.actor_id
LEFT JOIN attack_campaigns ac   ON ta.actor_id = ac.actor_id
LEFT JOIN leaked_credentials lc ON ta.actor_id = lc.actor_id
LEFT JOIN darkweb_mentions dm   ON ta.actor_id = dm.actor_id
GROUP BY ta.actor_id, ta.actor_name, ta.origin_country, ta.motivation, ta.sophistication
ORDER BY total_iocs DESC;

-- ============================================================
-- QUERY 4: Sector Impact Heatmap (Matrix Visual)
-- ============================================================
SELECT 
    si.sector_name,
    si.country,
    si.impact_level,
    SUM(si.estimated_loss)  AS total_estimated_loss_usd,
    COUNT(si.impact_id)     AS total_incidents,
    MAX(si.incident_date)   AS latest_incident
FROM sector_impact si
GROUP BY si.sector_name, si.country, si.impact_level
ORDER BY total_estimated_loss_usd DESC;

-- ============================================================
-- QUERY 5: Campaign Status Overview (KPI Cards + Pie)
-- ============================================================
SELECT 
    ac.status,
    ac.attack_type,
    COUNT(*) AS campaign_count,
    MIN(ac.start_date) AS earliest_campaign,
    MAX(ac.start_date) AS latest_campaign
FROM attack_campaigns ac
GROUP BY ac.status, ac.attack_type
ORDER BY campaign_count DESC;

-- ============================================================
-- QUERY 6: Dark Web Activity Timeline (Area / Line Chart)
-- ============================================================
SELECT 
    DATE_FORMAT(mention_date, '%Y-%m') AS month,
    mention_type,
    sector,
    COUNT(*) AS mention_count,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_mentions,
    SUM(CASE WHEN verified = TRUE THEN 1 ELSE 0 END) AS verified_count
FROM darkweb_mentions
GROUP BY DATE_FORMAT(mention_date, '%Y-%m'), mention_type, sector
ORDER BY month DESC;

-- ============================================================
-- QUERY 7: Biggest Data Breaches Ranking (Ranked Table)
-- ============================================================
SELECT 
    lc.breach_name,
    lc.breach_date,
    lc.affected_sector,
    lc.records_exposed,
    lc.data_types,
    lc.severity,
    lc.country_affected,
    ta.actor_name AS responsible_actor,
    DATEDIFF(lc.discovered_date, lc.breach_date) AS days_to_discover,
    DENSE_RANK() OVER (ORDER BY lc.records_exposed DESC) AS breach_rank
FROM leaked_credentials lc
LEFT JOIN threat_actors ta ON lc.actor_id = ta.actor_id
ORDER BY lc.records_exposed DESC;

-- ============================================================
-- QUERY 8: Geographic Threat Distribution (Map Visual)
-- ============================================================
SELECT 
    ta.origin_country AS country,
    COUNT(DISTINCT ta.actor_id)     AS threat_actors_count,
    COUNT(DISTINCT ir.ioc_id)       AS iocs_linked,
    SUM(si.estimated_loss)          AS total_damage_usd,
    GROUP_CONCAT(DISTINCT ta.motivation ORDER BY ta.motivation SEPARATOR ', ') AS motivations
FROM threat_actors ta
LEFT JOIN ioc_records ir      ON ta.actor_id = ir.actor_id
LEFT JOIN attack_campaigns ac ON ta.actor_id = ac.actor_id
LEFT JOIN sector_impact si    ON ac.campaign_id = si.campaign_id
GROUP BY ta.origin_country
ORDER BY iocs_linked DESC;

-- ============================================================
-- QUERY 9: Active Critical Threats Summary (Alert Table)
-- ============================================================
SELECT 
    ir.ioc_type,
    ir.ioc_value,
    ir.threat_type,
    ir.severity,
    ir.confidence AS confidence_pct,
    ir.source,
    ta.actor_name,
    ta.origin_country,
    DATEDIFF(NOW(), ir.last_seen) AS days_since_last_seen,
    ir.tags
FROM ioc_records ir
LEFT JOIN threat_actors ta ON ir.actor_id = ta.actor_id
WHERE ir.severity IN ('Critical', 'High')
  AND ir.is_active = TRUE
ORDER BY ir.confidence DESC, days_since_last_seen ASC;

-- ============================================================
-- QUERY 10: Full Threat Actor Profile (Drillthrough View)
-- ============================================================
SELECT 
    ta.actor_name,
    ta.alias,
    ta.origin_country,
    ta.motivation,
    ta.sophistication,
    ta.first_seen,
    ta.last_active,
    ta.active_status,
    COUNT(DISTINCT ir.ioc_id)       AS ioc_count,
    COUNT(DISTINCT ac.campaign_id)  AS campaign_count,
    COUNT(DISTINCT lc.leak_id)      AS breach_count,
    COUNT(DISTINCT dm.mention_id)   AS darkweb_mention_count,
    SUM(si.estimated_loss)          AS total_attributed_damage_usd,
    GROUP_CONCAT(DISTINCT ac.attack_type  SEPARATOR ', ') AS attack_types_used,
    GROUP_CONCAT(DISTINCT ac.targeted_sector SEPARATOR ' | ') AS sectors_targeted,
    GROUP_CONCAT(DISTINCT ac.targeted_region SEPARATOR ' | ') AS regions_targeted
FROM threat_actors ta
LEFT JOIN ioc_records ir        ON ta.actor_id = ir.actor_id
LEFT JOIN attack_campaigns ac   ON ta.actor_id = ac.actor_id
LEFT JOIN leaked_credentials lc ON ta.actor_id = lc.actor_id
LEFT JOIN darkweb_mentions dm   ON ta.actor_id = dm.actor_id
LEFT JOIN sector_impact si      ON ac.campaign_id = si.campaign_id
GROUP BY ta.actor_id, ta.actor_name, ta.alias, ta.origin_country, 
         ta.motivation, ta.sophistication, ta.first_seen, ta.last_active, ta.active_status
ORDER BY ioc_count DESC;
