# 🎯 CTI Features - Executive Summary & Decisions Needed

**Data**: 2025-11-19
**Status**: Awaiting Go/No-Go Decision

---

## 📊 What We Have (Current State)

### Elasticsearch Indices - Malpedia Data

✅ **malpedia_actors** (864 actors, 6.3MB)
- Actor names, aliases, descriptions
- Related malware families
- References to threat reports

✅ **malpedia_families** (3,578 families, 13.3MB)
- Malware family names, OS targets
- YARA rules (full content)
- Descriptions and references
- Status and update dates

### What's Missing

❌ **MITRE ATT&CK Techniques** - Not in indices
❌ **Bidirectional Actor↔Family Links** - Only Actor→Family works
❌ **MISP IOCs** - No integration yet

---

## 🎯 Proposed Features

### Feature 1: Cyber Actors & Malware Dashboard with ATT&CK

**What It Does**:
- Interactive page showing actors and malware families
- MITRE ATT&CK matrix visualization
- Click actor/family → Matrix highlights their techniques
- Technique details panel with references

**User Flow**:
```
1. User selects "Sandworm" actor
   → Matrix highlights 45 techniques used by Sandworm's malware
2. User selects "IsaacWiper" family
   → Matrix highlights only IsaacWiper's techniques
3. User clicks highlighted technique
   → Side panel shows: Description, tactics, malware using it
```

---

### Feature 2: MISP Threat Intelligence Integration

**What It Does**:
- Connect to MISP (Malware Information Sharing Platform)
- Import IOCs (IP addresses, domains, hashes, etc.)
- Match IOCs with malware families
- Timeline of recent threat activity

**User Flow**:
```
1. User views "Emotet" family
   → See recent IOCs: IPs, domains, file hashes
2. User views timeline
   → See when new Emotet activity was detected
3. User exports IOCs for blocking
```

---

## ⚠️ Key Decisions Needed

### Decision 1: Implementation Priority

**Options**:
- **A) ATT&CK Only** (Feature 1) - ~2-3 weeks
  - Pros: High value, clear scope, no external dependencies
  - Cons: Missing IOC enrichment

- **B) ATT&CK + MISP** (Features 1+2) - ~4-6 weeks
  - Pros: Complete CTI solution
  - Cons: More complex, needs MISP access

- **C) Postpone Both**
  - Focus on other priorities first

**Recommendation**: **Option A (ATT&CK Only)** - Start with high-value feature, add MISP later if needed.

---

### Decision 2: MITRE ATT&CK Data Source

**Options**:

**A) Malpedia API** (Recommended)
- ✅ Curated by malware analysts
- ✅ Aligned with existing data
- ❌ Requires API key
- ❌ Rate limits

**B) MITRE ATT&CK Official STIX Data**
- ✅ Free, no rate limits
- ✅ Comprehensive
- ❌ Manual mapping needed
- ❌ Not all families covered

**C) Hybrid Approach**
- ✅ Best coverage
- ❌ More complex

**Recommendation**: **Option A (Malpedia API)** - Easier integration, better coverage.

**Action Required**: Obtain Malpedia API key

---

### Decision 3: ATT&CK Visualization Approach

**Options**:

**A) Embed Official ATT&CK Navigator** (iFrame)
- ✅ Full functionality, zero maintenance
- ❌ Limited customization
- ❌ External dependency

**B) Custom Matrix Visualization**
- ✅ Fully customized for our use case
- ✅ Better UX for show/hide interactions
- ❌ Development effort (~1 week)

**C) Navigator Layer Export**
- Generate JSON layers
- POST to Navigator
- ✅ Moderate effort
- ❌ Extra click for user

**Recommendation**: **Option B (Custom Matrix)** - Better UX, worth the investment.

---

### Decision 4: MISP Integration (If Proceeding with Feature 2)

**Options**:

**A) Public MISP Feeds**
- ✅ Free, no credentials
- ❌ Limited data
- ❌ Generic IOCs

**B) Private MISP Instance**
- ✅ Organization-specific IOCs
- ✅ Better quality
- ❌ Requires MISP setup
- ❌ API key management

**C) Hybrid**
- Public feeds + Private instance
- ✅ Best of both worlds
- ❌ More complexity

**Recommendation**: **Start with Option A (Public Feeds)** - Prove value first, upgrade later.

---

## 🔧 Technical Challenges & Solutions

### Challenge 1: Bidirectional Actor-Family Links

**Problem**: Can find families for an actor, but NOT actors for a family
- `malpedia_actors.familias_relacionadas` = ["win.emotet", ...]  ✅
- `malpedia_families.actors` = [] (empty)  ❌

**Solution**: Compute on backend
```python
# When querying family
family = get_family("win.emotet")
family['actors'] = [a for a in actors if family.name in a.familias_relacionadas]
```

**Effort**: Low (~1 day)

---

### Challenge 2: ATT&CK Technique Mapping

**Problem**: Need to get techniques for 3,578 families

**Solution Options**:
1. **Batch enrichment** - Run pipeline to fetch all techniques (~1 week one-time)
2. **Lazy loading** - Fetch techniques on-demand (~2 days setup)
3. **Hybrid** - Pre-load top 100 families, lazy-load rest

**Recommendation**: Option 1 (Batch) - Better UX, one-time cost

---

### Challenge 3: Matrix Performance

**Problem**: 14 tactics × 200 techniques = 2,800 cells

**Solutions**:
- Virtualization (only render visible cells)
- Collapse unused tactics
- Cache technique data

**Effort**: Moderate (~3 days)

---

## 📅 Proposed Implementation Plan

### Phase 1: MITRE ATT&CK Dashboard (If Approved)

**Week 1: Backend**
- ✅ Research complete
- ⬜ Set up Malpedia API integration
- ⬜ Modify enrichment pipeline
- ⬜ Update Elasticsearch mappings
- ⬜ Run batch enrichment (3,578 families)

**Week 2: API & Data**
- ⬜ Create `/api/v1/cti/actors` endpoint
- ⬜ Create `/api/v1/cti/families` endpoint
- ⬜ Create `/api/v1/cti/techniques` endpoint
- ⬜ Add search/filter capabilities

**Week 3: Frontend**
- ⬜ Create CTI monitoring page
- ⬜ Build actor/family selection lists
- ⬜ Implement matrix visualization (custom)
- ⬜ Add technique details panel
- ⬜ Implement show/hide interactions

**Deliverables**:
- Working CTI dashboard
- ATT&CK matrix with actor/family filtering
- Documentation

---

### Phase 2: MISP Integration (Optional)

**Week 4: MISP Backend**
- ⬜ Set up PyMISP connection
- ⬜ Create Celery task for feed ingestion
- ⬜ Design `misp_iocs` index
- ⬜ Build IOC matching logic

**Week 5-6: MISP Frontend**
- ⬜ Add IOC timeline
- ⬜ Show IOCs in family details
- ⬜ Build correlation views
- ⬜ Add MISP search

**Deliverables**:
- MISP feed integration
- IOC enrichment for families
- Timeline visualization

---

## 💰 Resource Requirements

### API Keys Needed
- **Malpedia API Key** (for ATT&CK data)
  - Request: https://malpedia.caad.fkie.fraunhofer.de/api/
  - Cost: Free (academic/research use)
  - Lead time: ~1 week

- **MISP Access** (if doing Phase 2)
  - Option 1: Public feeds (free)
  - Option 2: Private instance (setup required)

### Python Packages
```bash
pip install mitreattack-python  # ATT&CK library
pip install pymisp              # MISP library (Phase 2)
pip install stix2               # STIX format support
```

### Storage
- Elasticsearch: ~20MB additional (ATT&CK data)
- MISP IOCs: ~100MB-1GB (depends on feed volume)

---

## ✅ Recommendations

### Immediate Next Steps

1. **Decision Required**: Go/No-Go on Feature 1 (ATT&CK Dashboard)
   - If YES → Request Malpedia API key
   - If NO → Document for future consideration

2. **If Approved**:
   - Week 1: Backend enrichment
   - Week 2: API development
   - Week 3: Frontend visualization

3. **Phase 2 Decision**: Defer MISP until after Phase 1 complete
   - Validate ATT&CK dashboard value first
   - Then decide on MISP integration

---

## 📊 Expected Value

### Benefits

**For Analysts**:
- Visual understanding of threat actor capabilities
- Quick technique lookup for malware families
- Export ATT&CK layers for reporting
- IOC enrichment (with MISP)

**For Organization**:
- Better threat intelligence
- Improved detection coverage
- Standardized CTI framework (ATT&CK)
- Threat information sharing (with MISP)

### Success Metrics

- Analysts use dashboard for threat research
- ATT&CK techniques inform detection rules
- IOCs integrated into security tools (with MISP)
- Reduced time to understand threat actor TTPs

---

## 🚀 Ready to Proceed?

**Questions to Answer**:
1. ✅ Do we proceed with Feature 1 (ATT&CK Dashboard)?
2. ✅ Custom matrix or embed Navigator?
3. ✅ Can we get Malpedia API key?
4. ⏸️ Defer Feature 2 (MISP) to Phase 2?

**Once decided**, we can begin implementation immediately.

---

**Documented with ❤️ for ADINT**
