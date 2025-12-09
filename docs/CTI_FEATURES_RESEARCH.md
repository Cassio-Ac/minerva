# 🔍 CTI Features Research: Malpedia + MITRE ATT&CK + MISP

**Data**: 2025-11-19
**Status**: Research Phase - Study Before Implementation

---

## 📋 Executive Summary

This document contains research findings for two proposed Cyber Threat Intelligence (CTI) features:

1. **Cyber Actors & Malware Monitoring Dashboard**
   - Read from existing Malpedia indices (`malpedia_actors`, `malpedia_families`)
   - Associate with MITRE ATT&CK framework
   - Interactive TTP visualization (show/hide techniques based on selection)

2. **MISP (Malware Information Sharing Platform) Integration**
   - Connect to MISP threat intelligence sources
   - Enrich existing data with external IOCs and threat intelligence

---

## 📊 Current Data Analysis

### Malpedia Indices Structure

#### `malpedia_actors` Index

**Total Documents**: 864 actors
**Size**: 6.3MB

**Schema**:
```json
{
  "name": "text (keyword)",           // Actor name
  "url": "text (keyword)",            // Malpedia URL
  "aka": "text (keyword)",            // Aliases/alternative names (array)
  "explicacao": "text (keyword)",     // Description/explanation
  "familias_relacionadas": "text (keyword)", // Related malware families (array)
  "referencias": [{                   // References (array of objects)
    "desc": "text (keyword)",
    "url": "text (keyword)"
  }],
  "erro": "text (keyword)"            // Error field (optional)
}
```

**Example Actor**:
```json
{
  "name": "GhostNet",
  "aka": ["Snooping Dragon"],
  "explicacao": "GhostNet is a cyber espionage campaign...",
  "familias_relacionadas": ["win.zeppelin", "win.portstarter", ...],
  "referencias": [...]
}
```

**Key Findings**:
- ✅ Has `familias_relacionadas` (related families) - bidirectional relationship exists
- ✅ Rich reference data from multiple threat intelligence sources
- ✅ Aliases tracked in `aka` field
- ❌ **NO MITRE ATT&CK data currently stored**

---

#### `malpedia_families` Index

**Total Documents**: 3,578 malware families
**Size**: 13.3MB

**Schema**:
```json
{
  "os": "text (keyword)",             // Operating system (Windows, Linux, Android, etc.)
  "name": "text (keyword)",           // Malware family name
  "update": "date",                   // Last update date
  "status": "text (keyword)",         // Status (e.g., "All samples unpacked")
  "url": "text (keyword)",            // Malpedia URL
  "aka": "text (keyword)",            // Aliases (array)
  "actors": "???",                    // Actor associations (array - EMPTY in all samples)
  "descricao": "text (keyword)",      // Description
  "referencias": [{                   // References (array of objects)
    "desc": "text (keyword)",
    "url": "text (keyword)"
  }],
  "yara_rules": [{                    // YARA rules (array of objects)
    "nome": "text (keyword)",
    "url": "text (keyword)",
    "conteudo": "text (keyword)"      // Full YARA rule content
  }]
}
```

**Example Family**:
```json
{
  "name": "IsaacWiper",
  "os": "Windows",
  "aka": ["LASAINRAW"],
  "actors": [],  // EMPTY - relationship not bidirectional
  "descricao": "Destructive malware that overwrites all physical disks...",
  "yara_rules": [...],
  "referencias": [...]
}
```

**Key Findings**:
- ✅ Rich descriptive data and YARA rules
- ✅ OS targeting information
- ✅ Extensive references to threat intelligence reports
- ⚠️ `actors` field exists but is **EMPTY in all samples** (relationship not bidirectional)
- ❌ **NO MITRE ATT&CK data currently stored**

---

### Data Relationship Analysis

**Actor → Family Relationship**:
- ✅ **WORKS**: `malpedia_actors.familias_relacionadas` contains malware family names
- Example: GhostNet actor → [`win.zeppelin`, `win.portstarter`, `elf.inc`, ...]

**Family → Actor Relationship**:
- ❌ **BROKEN**: `malpedia_families.actors` is **EMPTY** in all samples
- Expected: IsaacWiper → [actor names]
- Reality: IsaacWiper → `[]`

**Implication**:
To build a bidirectional dashboard, we need to:
1. Use `malpedia_actors.familias_relacionadas` as source of truth
2. Create derived/computed relationships for Family → Actor direction
3. Consider re-running enrichment pipeline to populate `actors` field

---

## 🎯 MITRE ATT&CK Integration Research

### Current State: NO ATT&CK Data

**Findings**:
```bash
# Search for MITRE ATT&CK fields
curl -s "http://localhost:9200/malpedia_families/_search" \
  -d '{"query": {"exists": {"field": "mitre_attack"}}}'
# Result: 0 documents
```

**Conclusion**: MITRE ATT&CK data is **NOT currently in Elasticsearch indices**.

---

### Integration Options

#### Option 1: Malpedia API (Current Data Source)

**Malpedia already has ATT&CK mappings on their website**:
- URL Pattern: `https://malpedia.caad.fkie.fraunhofer.de/details/win.isaacwiper`
- Each malware family page shows associated ATT&CK techniques
- Data available via Malpedia API

**API Endpoints**:
```
GET https://malpedia.caad.fkie.fraunhofer.de/api/get/family/{family_name}
GET https://malpedia.caad.fkie.fraunhofer.de/api/get/actor/{actor_name}
```

**Pros**:
- ✅ Already part of existing data source
- ✅ Curated by malware analysts
- ✅ Aligned with current enrichment pipeline

**Cons**:
- ❌ Requires API key for full access
- ❌ Need to re-run enrichment pipeline
- ❌ May have rate limits

---

#### Option 2: MITRE ATT&CK STIX/TAXII

**Official MITRE ATT&CK Data Sources**:

1. **ATT&CK STIX Data**:
   - Repository: https://github.com/mitre-attack/attack-stix-data
   - Format: STIX 2.1 JSON
   - Contains: Enterprise, Mobile, ICS matrices
   - Latest Release: https://github.com/mitre-attack/attack-stix-data/releases

2. **ATT&CK Python Library**:
   - Package: `mitreattack-python`
   - Install: `pip install mitreattack-python`
   - Capabilities:
     - Load ATT&CK data from STIX
     - Query techniques, tactics, groups, software
     - Generate Navigator layers

**Example Usage**:
```python
from mitreattack.stix20 import MitreAttackData

# Load ATT&CK data
mitre_attack = MitreAttackData("enterprise-attack.json")

# Get all techniques
techniques = mitre_attack.get_techniques()

# Get techniques for specific tactic
techniques_by_tactic = mitre_attack.get_techniques_by_tactic("TA0001")  # Initial Access

# Get software (malware/tools)
software = mitre_attack.get_software()
```

**Pros**:
- ✅ Official MITRE data source
- ✅ Comprehensive technique coverage
- ✅ Regularly updated
- ✅ No API key required
- ✅ Offline capable

**Cons**:
- ❌ Need to map malware family names to ATT&CK software IDs
- ❌ May not have all Malpedia families
- ❌ Requires additional processing

---

#### Option 3: Hybrid Approach (RECOMMENDED)

**Strategy**: Combine both sources for maximum coverage

1. **Primary Source**: Malpedia API
   - Use existing enrichment pipeline
   - Add ATT&CK technique extraction
   - Store in new field: `mitre_techniques`

2. **Fallback Source**: ATT&CK STIX
   - For families not in Malpedia
   - Use ATT&CK's software catalog
   - Manual mapping for high-value families

3. **Data Structure**:
```json
{
  "name": "IsaacWiper",
  "mitre_techniques": [
    {
      "technique_id": "T1485",
      "technique_name": "Data Destruction",
      "tactic": "Impact",
      "url": "https://attack.mitre.org/techniques/T1485/"
    },
    {
      "technique_id": "T1561",
      "technique_name": "Disk Wipe",
      "tactic": "Impact",
      "subtechnique_of": "T1561.001",
      "url": "https://attack.mitre.org/techniques/T1561/001/"
    }
  ]
}
```

**Implementation Steps**:
1. Modify `backend/malpedia_pipeline.py` to extract ATT&CK data
2. Add MITRE ATT&CK API calls during enrichment
3. Store techniques in Elasticsearch
4. Build frontend visualization

---

### MITRE ATT&CK Navigator Integration

**What is ATT&CK Navigator?**
- Interactive matrix visualization
- Show/hide techniques
- Color-coding for coverage
- Export/import layers

**Official Navigator**:
- Web: https://mitre-attack.github.io/attack-navigator/
- GitHub: https://github.com/mitre-attack/attack-navigator

**Integration Options**:

#### A. Embed Official Navigator (iFrame)
```typescript
<iframe
  src="https://mitre-attack.github.io/attack-navigator/"
  style="width: 100%; height: 800px;"
/>
```

**Pros**: ✅ Full functionality, ✅ No maintenance
**Cons**: ❌ Limited customization, ❌ External dependency

---

#### B. Use Navigator Layer Format

**ATT&CK Navigator Layer JSON**:
```json
{
  "name": "IsaacWiper Techniques",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Techniques used by IsaacWiper malware",
  "techniques": [
    {
      "techniqueID": "T1485",
      "tactic": "impact",
      "color": "#ff6666",
      "comment": "Data Destruction",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    }
  ]
}
```

**Frontend Approach**:
1. Generate layer JSON from selected actor/family
2. POST to Navigator: `https://mitre-attack.github.io/attack-navigator/`
3. Or build custom matrix visualization

---

#### C. Custom Matrix Visualization (RECOMMENDED)

**Build custom React component** using ATT&CK data:

**Libraries**:
- `d3.js` - For matrix rendering
- `react-grid-layout` - For interactive grid
- Custom SVG/Canvas visualization

**Features**:
- ✅ Show/hide techniques on click
- ✅ Color-code by actor/family
- ✅ Tooltips with technique details
- ✅ Filter by tactic
- ✅ Export to Navigator layer format

**UI/UX Flow**:
```
1. User selects Actor → Highlight all techniques from actor's families
2. User selects Family → Highlight family's techniques
3. Multi-select → Show union or intersection of techniques
4. Click technique → Show details sidebar with references
```

---

## 🔗 MISP Integration Research

### What is MISP?

**MISP** (Malware Information Sharing Platform):
- Open-source threat intelligence platform
- Share IOCs (Indicators of Compromise)
- Correlate threats across organizations
- STIX/TAXII support

**Official Site**: https://www.misp-project.org/

---

### MISP Integration Options

#### Option 1: PyMISP Library

**Install**:
```bash
pip install pymisp
```

**Basic Usage**:
```python
from pymisp import PyMISP

# Connect to MISP instance
misp = PyMISP(
    url='https://misp.instance.com',
    key='YOUR_API_KEY',
    ssl=True
)

# Search for events
events = misp.search(
    controller='events',
    type_attribute='sha256',
    value='hash_value'
)

# Get event details
event = misp.get_event(event_id)

# Get attributes
attributes = misp.search(
    controller='attributes',
    tags=['malware:family=\"emotet\"']
)
```

**Pros**:
- ✅ Official Python library
- ✅ Full API access
- ✅ STIX export support
- ✅ Event correlation

**Cons**:
- ❌ Requires MISP instance access
- ❌ API key management
- ❌ Need to handle rate limits

---

#### Option 2: Public MISP Feeds

**CIRCL MISP Feed**:
- URL: https://www.circl.lu/doc/misp/feed-osint/
- Format: JSON
- Free access
- Updated regularly

**Other Public Feeds**:
- MISP Galaxy: https://github.com/MISP/misp-galaxy
- Threat Intel feeds: https://github.com/MISP/MISP-feeds

**Usage**:
```python
import requests

# Fetch feed
feed_url = "https://www.circl.lu/doc/misp/feed-osint/recent.json"
response = requests.get(feed_url)
events = response.json()

# Process events
for event in events:
    # Extract IOCs
    # Match with existing data
    # Enrich malware families
```

---

#### Option 3: MISP Threat Intelligence Format

**Store MISP-style IOCs in Elasticsearch**:

**New Index**: `misp_iocs`

**Schema**:
```json
{
  "event_id": "uuid",
  "event_info": "text",
  "date": "date",
  "threat_level_id": "integer",
  "attributes": [{
    "type": "keyword",  // ip-dst, sha256, domain, etc.
    "category": "keyword",  // Network activity, Payload delivery, etc.
    "value": "keyword",  // Actual IOC value
    "to_ids": "boolean",
    "comment": "text",
    "tags": ["keyword"]
  }],
  "galaxies": [{
    "name": "keyword",  // threat-actor, malware, tool
    "type": "keyword",
    "values": ["keyword"]
  }]
}
```

**Integration with Malpedia**:
- Match `galaxies.type="malware"` with `malpedia_families.name`
- Match `galaxies.type="threat-actor"` with `malpedia_actors.name`
- Enrich with IOCs for detection

---

### MISP Integration Architecture

**Proposed Flow**:

```
┌─────────────────┐
│  MISP Instance  │
│  or Public Feed │
└────────┬────────┘
         │
         │ PyMISP or HTTP
         │
         ▼
┌─────────────────┐
│  Celery Task    │
│  (Scheduled)    │
│  - Fetch events │
│  - Parse IOCs   │
│  - Match with   │
│    Malpedia     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Elasticsearch  │
│  - misp_iocs    │
│  - Update       │
│    families     │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│  Frontend UI    │
│  - Show IOCs    │
│  - Timeline     │
│  - Correlations │
└─────────────────┘
```

---

## 🎨 Proposed Dashboard UI/UX

### Page Layout

```
┌──────────────────────────────────────────────────────┐
│ 🎯 Cyber Threat Intelligence Monitoring              │
├──────────────────────────────────────────────────────┤
│                                                       │
│  ┌─────────────────┐  ┌──────────────────────────┐  │
│  │  Actors (864)   │  │  MITRE ATT&CK Matrix     │  │
│  │  ─────────────  │  │  ──────────────────────  │  │
│  │  🔍 Search      │  │                          │  │
│  │                 │  │   [TA0001] [TA0002] ...  │  │
│  │  □ GhostNet     │  │   ┌───┬───┬───┬───┐     │  │
│  │  □ APT28        │  │   │ ✓ │   │ ✓ │   │     │  │
│  │  □ Lazarus      │  │   ├───┼───┼───┼───┤     │  │
│  │  ☑ Sandworm     │  │   │ ✓ │ ✓ │   │   │     │  │
│  │  ...            │  │   └───┴───┴───┴───┘     │  │
│  └─────────────────┘  │                          │  │
│                       │  Legend:                 │  │
│  ┌─────────────────┐  │  ✓ = Used by selection  │  │
│  │  Families(3578) │  │                          │  │
│  │  ─────────────  │  └──────────────────────────┘  │
│  │  🔍 Search      │                                 │
│  │  Filter:        │  ┌──────────────────────────┐  │
│  │  □ Windows      │  │  Technique Details       │  │
│  │  □ Linux        │  │  ──────────────────────  │  │
│  │  □ Android      │  │  T1485: Data Destruction │  │
│  │                 │  │                          │  │
│  │  ☑ IsaacWiper   │  │  Used by:                │  │
│  │  □ Emotet       │  │  • IsaacWiper            │  │
│  │  □ TrickBot     │  │  • CaddyWiper            │  │
│  │  ...            │  │                          │  │
│  └─────────────────┘  │  References: [...]       │  │
│                       └──────────────────────────┘  │
│                                                       │
│  ┌──────────────────────────────────────────────┐   │
│  │  Recent MISP Events                          │   │
│  │  ──────────────────────────────────────────  │   │
│  │  📅 2025-11-19 | IOC: 1.2.3.4 | Emotet       │   │
│  │  📅 2025-11-18 | Hash: abc123... | TrickBot  │   │
│  └──────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

---

### Interactive Features

1. **Actor Selection**:
   - Click actor → Highlight all techniques from actor's families
   - Show count: "Sandworm uses 45 techniques across 12 families"

2. **Family Selection**:
   - Click family → Highlight family's techniques
   - Show OS target, aliases, YARA rules

3. **Technique Hover**:
   - Tooltip: Technique name, tactic, description
   - Click → Open details panel

4. **Multi-Select**:
   - Ctrl+Click → Add to selection
   - Show union or intersection toggle

5. **Export**:
   - Download ATT&CK Navigator layer
   - Export as PDF/PNG
   - Export IOC list

---

## 📋 Implementation Roadmap

### Phase 1: MITRE ATT&CK Enrichment (Priority: HIGH)

**Backend Tasks**:
1. ✅ Research complete
2. ⬜ Modify Malpedia enrichment pipeline
3. ⬜ Add MITRE ATT&CK API integration
4. ⬜ Update Elasticsearch mappings
5. ⬜ Re-run enrichment for all families
6. ⬜ Create API endpoints for ATT&CK data

**Frontend Tasks**:
1. ⬜ Create CTI monitoring page
2. ⬜ Build actor/family selection lists
3. ⬜ Implement ATT&CK matrix visualization
4. ⬜ Add technique details panel
5. ⬜ Implement show/hide logic

**Estimated Effort**: 2-3 weeks

---

### Phase 2: MISP Integration (Priority: MEDIUM)

**Backend Tasks**:
1. ⬜ Set up PyMISP connection
2. ⬜ Create Celery task for MISP feed ingestion
3. ⬜ Design `misp_iocs` index schema
4. ⬜ Build IOC matching logic
5. ⬜ Create MISP API endpoints

**Frontend Tasks**:
1. ⬜ Add MISP events timeline
2. ⬜ Show IOCs in family/actor details
3. ⬜ Build correlation graph
4. ⬜ Add MISP search interface

**Estimated Effort**: 2-3 weeks

---

### Phase 3: Advanced Features (Priority: LOW)

**Ideas**:
1. ⬜ Timeline visualization of malware evolution
2. ⬜ Network graph of actor-family relationships
3. ⬜ Automated threat hunting based on IOCs
4. ⬜ Integration with YARA rule scanning
5. ⬜ RSS feed for new malware families
6. ⬜ Export to STIX/TAXII for sharing

**Estimated Effort**: 4-6 weeks

---

## 🔧 Technical Challenges

### Challenge 1: Bidirectional Actor-Family Relationship

**Problem**: `malpedia_families.actors` field is empty

**Solutions**:
1. **Backend Computation** (Recommended):
   ```python
   # During family query
   family = get_family("win.isaacwiper")
   family['actors'] = get_actors_using_family(family['name'])
   ```

2. **Re-enrich Data**:
   - Modify pipeline to populate `actors` field
   - Re-run for all 3,578 families

3. **Frontend Computation**:
   ```typescript
   // Build reverse mapping on page load
   const familyToActors = {};
   actors.forEach(actor => {
     actor.familias_relacionadas.forEach(family => {
       if (!familyToActors[family]) familyToActors[family] = [];
       familyToActors[family].push(actor.name);
     });
   });
   ```

---

### Challenge 2: MITRE ATT&CK Technique Mapping

**Problem**: Need to map 3,578 families to ATT&CK techniques

**Solutions**:
1. **Malpedia API** (Best coverage):
   - Use existing mappings
   - Requires API key
   - Rate limits apply

2. **ATT&CK Software Catalog** (Partial coverage):
   - Only ~400 software entries
   - Many Malpedia families not included

3. **Manual Mapping** (High-value targets):
   - Focus on top 100 families
   - Manual analysis for critical threats

4. **Hybrid**: Combine all three approaches

---

### Challenge 3: MISP Data Volume

**Problem**: MISP feeds can generate thousands of events daily

**Solutions**:
1. **Filtering**:
   - Only ingest events with `galaxies` tags
   - Filter by threat level
   - Focus on malware-related events

2. **Deduplication**:
   - Track event UUIDs
   - Skip already processed events

3. **TTL/Archiving**:
   - Set Elasticsearch TTL on old IOCs
   - Archive to S3/cold storage after 90 days

---

### Challenge 4: Matrix Visualization Performance

**Problem**: ATT&CK Enterprise has 14 tactics × ~200 techniques = 2,800 cells

**Solutions**:
1. **Virtualization**:
   - Only render visible cells
   - Use `react-window` or `react-virtualized`

2. **Lazy Loading**:
   - Load technique details on demand
   - Cache frequently accessed techniques

3. **Filtering**:
   - Show only tactics with matches
   - Collapse unused tactics

---

## 📚 References

### MITRE ATT&CK
- Main Site: https://attack.mitre.org/
- STIX Data: https://github.com/mitre-attack/attack-stix-data
- Python Library: https://github.com/mitre/mitreattack-python
- Navigator: https://github.com/mitre-attack/attack-navigator

### MISP
- Main Site: https://www.misp-project.org/
- PyMISP: https://github.com/MISP/PyMISP
- Public Feeds: https://www.circl.lu/doc/misp/feed-osint/

### Malpedia
- Main Site: https://malpedia.caad.fkie.fraunhofer.de/
- API Docs: https://malpedia.caad.fkie.fraunhofer.de/api/

---

## ✅ Next Steps

1. **Review this document with team/stakeholder**
2. **Decide on implementation priority**:
   - Phase 1 only (ATT&CK)?
   - Phase 1 + 2 (ATT&CK + MISP)?
   - All phases?

3. **Clarify requirements**:
   - Which visualizations are must-have?
   - MISP: Public feeds or private instance?
   - Performance targets?

4. **Get API access**:
   - Malpedia API key
   - MISP instance credentials (if using private instance)

5. **Begin implementation** after approval

---

**Documented with ❤️ for ADINT**
