## Power BI DAX Measures Reference

Copy these DAX measures into Power BI Desktop after loading your data.

### KPI Card Measures

```dax
-- Total Active IOCs
Active IOCs = 
CALCULATE(
    COUNT(ioc_records[ioc_id]), 
    ioc_records[is_active] = TRUE
)

-- Critical IOC Percentage
Critical IOC % = 
DIVIDE(
    CALCULATE(COUNT(ioc_records[ioc_id]), ioc_records[severity] = "Critical"),
    COUNT(ioc_records[ioc_id]),
    0
) * 100

-- Total Records Breached (Billions)
Records Breached (B) = 
DIVIDE(SUM(leaked_credentials[records_exposed]), 1000000000)

-- Average Confidence Score
Avg Confidence Score = 
AVERAGE(ioc_records[confidence])

-- Active Campaigns Count
Active Campaigns = 
CALCULATE(
    COUNT(attack_campaigns[campaign_id]), 
    attack_campaigns[status] = "Active"
)

-- Total Estimated Damage (Millions USD)
Total Damage $M = 
DIVIDE(SUM(sector_impact[estimated_loss]), 1000000)

-- Dark Web Critical Verified Alerts
DW Critical Alerts = 
CALCULATE(
    COUNT(darkweb_mentions[mention_id]),
    darkweb_mentions[severity] = "Critical",
    darkweb_mentions[verified] = TRUE
)

-- Nation-State Actor Count
Nation-State Actors = 
CALCULATE(
    COUNT(threat_actors[actor_id]),
    threat_actors[sophistication] = "Nation-State"
)
```

### Trend Measures

```dax
-- IOC Month-over-Month Change
IOC MoM Change % = 
VAR CurrentMonth = COUNT(ioc_records[ioc_id])
VAR PrevMonth = CALCULATE(
    COUNT(ioc_records[ioc_id]),
    DATEADD(ioc_records[first_seen], -1, MONTH)
)
RETURN DIVIDE(CurrentMonth - PrevMonth, PrevMonth, 0) * 100

-- Breach Discovery Lag (avg days)
Avg Discovery Lag = 
AVERAGEX(
    leaked_credentials,
    DATEDIFF(leaked_credentials[breach_date], leaked_credentials[discovered_date], DAY)
)

-- Verified Dark Web Mention Rate
Verified Mention Rate = 
DIVIDE(
    CALCULATE(COUNT(darkweb_mentions[mention_id]), darkweb_mentions[verified] = TRUE),
    COUNT(darkweb_mentions[mention_id]),
    0
) * 100
```

## Power BI Connection Setup (MySQL)

1. Download **MySQL ODBC 8.0 Connector** from mysql.com/downloads
2. Open Power BI Desktop → **Get Data** → **MySQL database**
3. Server: `localhost`, Database: `threat_intel_db`
4. Use **Import** mode for static data, **DirectQuery** for live updates
5. Load each query from `03_powerbi_queries.sql` as a named query

## Recommended Dashboard Theme

Apply the **Midnight** or **Executive** built-in theme, or download a custom dark theme from:
- https://community.powerbi.com/t5/Themes-Gallery/bd-p/ThemesGallery

Use these hex colors for a cybersecurity aesthetic:
- Background: `#0d1117`
- Accent 1 (Critical): `#ff4444`
- Accent 2 (High): `#ff8c00`
- Accent 3 (Medium): `#ffd700`
- Positive/Safe: `#00d4aa`
- Text: `#e6edf3`
