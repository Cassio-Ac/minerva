# Changelog - Intelligence Platform (Minerva)

## [Unreleased] - 2025-01-17

### Fixed
- **Timeline not showing Malpedia Library articles** (#1)
  - Fixed Pydantic ValidationError: Made `summary` field optional in `RSSArticle` schema
  - Fixed frontend parameter mismatch: Changed `sources` to `feed_names` in API request
  - Increased article limit for "All period" timeline: 50 → 10,000 articles
  - Increased backend max limit validation: 500 → 10,000 articles
  - Now correctly displays all 17,595 Malpedia Library BibTeX entries in timeline

### Technical Details

#### Root Cause
The `RSSArticle` Pydantic model required a mandatory `summary` field, but Malpedia Library articles (from BibTeX parser) don't have summaries. This caused a ValidationError when the API tried to serialize these articles.

#### Files Changed
1. `backend/app/schemas/rss.py:150` - Made `summary: Optional[str] = None`
2. `backend/app/schemas/rss.py:187` - Increased `limit` max from 500 to 10,000
3. `frontend/src/pages/InfoPage.tsx:96` - Dynamic limit based on date range
4. `frontend/src/pages/InfoPage.tsx:103` - Fixed parameter name: `sources` → `feed_names`

#### Validation
```bash
# Total Malpedia articles in Elasticsearch
curl -s "http://localhost:9200/rss-articles/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"feed_name":"Malpedia Library"}}}' \
  | jq '.count'
# Result: 17595

# API successfully returns articles with null summary
curl -s -X POST http://localhost:8001/api/v1/rss/articles/search \
  -H "Content-Type: application/json" \
  -d '{"feed_names": ["Malpedia Library"], "limit": 10000}' \
  | jq '.total'
# Result: 10000 (capped by limit, actual total is 17595)
```

---

## [Initial Release] - 2025-01-16

### Added
- Fork from Dashboard AI v2
- Port configuration for simultaneous execution
  - Frontend: 5174 (vs Dashboard AI v2: 5173)
  - Backend: 8001 (vs Dashboard AI v2: 8000)
  - PostgreSQL: 5433 (vs Dashboard AI v2: 5432)
  - Redis: 6380 (vs Dashboard AI v2: 6379)
