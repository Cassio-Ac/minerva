# MISP Galaxy - Estudo e Análise

## 📚 O que é MISP Galaxy?

MISP Galaxy é uma **base de conhecimento estruturada** de objetos de threat intelligence organizados em **clusters**. Cada cluster contém elementos relacionados (threat actors, malware, tools, techniques) que podem ser anexados a eventos ou atributos do MISP para enriquecer análises de segurança.

## 🏗️ Arquitetura

### Conceitos Principais

1. **Galaxy** (Galáxia): Categoria/tipo de conhecimento (ex: "Threat Actor", "Malpedia", "Tool")
2. **Cluster**: Coleção de valores dentro de uma galaxy (ex: APT1, APT28, Lazarus Group)
3. **Value**: Elemento individual com metadados e relacionamentos

### Estrutura de Diretórios

```
misp-galaxy/
├── clusters/          # Dados JSON dos clusters
│   ├── threat-actor.json
│   ├── malpedia.json
│   ├── tool.json
│   └── ...
├── galaxies/          # Definições das galaxias
├── vocabularies/      # Vocabulários controlados
└── tools/            # Scripts de validação
```

## 📊 Estatísticas (Análise Realizada)

### Threat Actors
- **Total**: 864 threat actors
- **Versão**: 336
- **Cobertura de Metadados**:
  - 98.0% têm referências
  - 46.6% têm país de origem
  - 41.8% têm sinônimos
  - 18.9% têm attribution confidence
  - 16.9% têm vítimas suspeitas

### Malpedia (Malware)
- **Total**: 3.260 famílias de malware
- **Versão**: 21776
- **Cobertura**: 100% dos entries têm refs, synonyms e type

### Tools
- **Total**: 605 tools/malware
- **Versão**: 175
- **Cobertura**:
  - 90.6% têm referências
  - 24.8% têm sinônimos

## 🔑 Estrutura de Dados

### Schema de um Threat Actor

```json
{
  "uuid": "ed7efd4d-ce28-48c6-8db3-c718a32f9e3d",
  "value": "APT1",
  "description": "PLA Unit 61398 is a People's Liberation Army...",
  "meta": {
    "country": "CN",
    "attribution-confidence": "50",
    "cfr-suspected-state-sponsor": "China",
    "cfr-suspected-victims": ["US", "CA", "UK"],
    "cfr-target-category": ["Private sector", "Government"],
    "cfr-type-of-incident": ["Espionage"],
    "synonyms": ["COMMENT PANDA", "PLA Unit 61398", "Comment Crew"],
    "refs": [
      "https://attack.mitre.org/groups/G0006",
      "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
    ]
  },
  "related": [
    {
      "dest-uuid": "5e0a7cf2-6107-4d5f-9dd0-9df38b1fcba8",
      "tags": ["estimative-language:likelihood-probability=\"likely\""],
      "type": "similar"
    }
  ]
}
```

### Campos Principais

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `uuid` | string | Identificador único universal |
| `value` | string | Nome do ator/malware/tool |
| `description` | string | Descrição detalhada |
| `meta` | object | Metadados estruturados |
| `related` | array | Relacionamentos com outros clusters |

### Metadados Comuns (meta)

#### Threat Actors
- `country`: País de origem (código ISO)
- `attribution-confidence`: 0-100
- `cfr-suspected-state-sponsor`: Governo suspeito
- `cfr-suspected-victims`: Array de países/organizações
- `cfr-target-category`: Setores alvo
- `cfr-type-of-incident`: Tipos de ataque
- `synonyms`: Nomes alternativos
- `refs`: URLs de referência
- `targeted-sector`: Setores industriais alvo
- `motive`: Motivação do grupo

#### Malware (Malpedia)
- `refs`: URLs de documentação (100% cobertura)
- `synonyms`: Aliases do malware
- `type`: Categoria (RAT, Trojan, Ransomware, etc)

#### Tools
- `refs`: Referências externas
- `synonyms`: Nomes alternativos
- `type`: Tipo de ferramenta

## 🔗 Relacionamentos

O campo `related` estabelece conexões entre clusters:

```json
{
  "related": [
    {
      "dest-uuid": "uuid-do-cluster-relacionado",
      "tags": ["estimative-language:likelihood-probability=\"likely\""],
      "type": "similar" | "uses" | "targets" | "derives-from"
    }
  ]
}
```

**Tipos de Relacionamento**:
- `similar`: Atores/malware similares ou aliases
- `uses`: Ator usa ferramenta/malware
- `targets`: Alvo de ataques
- `derives-from`: Derivado de outro malware

## 📈 Casos de Uso

### 1. Enriquecimento de IOCs
Quando um IOC é detectado (ex: hash de malware), vincular ao cluster Malpedia correspondente traz:
- Nome da família de malware
- Sinônimos conhecidos
- Referências técnicas
- Tipo de ameaça

### 2. Análise de Threat Actors
Para cada threat actor, obter:
- País de origem
- Vítimas históricas
- Setores alvo preferidos
- Ferramentas/malware usados
- Confidence level de atribuição

### 3. Mapeamento de Campanhas
Conectar:
- IOCs → Malware (Malpedia)
- Malware → Tools usados
- Tools → Threat Actors que os usam
- Threat Actors → Campanhas conhecidas

### 4. Inteligência Geopolítica
Filtrar threat actors por:
- País de origem
- Estado-patrocinador suspeito
- Tipos de incidente (espionagem, sabotagem, crime financeiro)
- Setores alvo (governo, defesa, saúde, etc)

## 🎯 Principais Galaxias Disponíveis

### Essenciais
1. **threat-actor** (864 entries): APTs, grupos criminosos
2. **malpedia** (3.260 entries): Famílias de malware
3. **tool** (605 entries): Ferramentas usadas por atacantes
4. **ransomware** (300+ entries): Famílias de ransomware
5. **mitre-attack-pattern** (1.185 entries): MITRE ATT&CK

### Especializadas
- **botnet** (132 entries): Redes botnet conhecidas
- **exploit-kit** (52 entries): Kits de exploração
- **android** (435 entries): Malware mobile Android
- **backdoor** (350+ entries): Backdoors conhecidos
- **rat** (200+ entries): Remote Access Trojans

### Frameworks
- **mitre-attack** series: Enterprise, Mobile, ICS
- **mitre-d3fend**: Defensive techniques
- **disarm-techniques**: Contra-desinformação

## 💡 Oportunidades de Integração

### Phase 1: Import Básico
1. Download clusters JSON do GitHub
2. Parse e validação de dados
3. Importação para banco PostgreSQL
4. Indexação para busca rápida

### Phase 2: Enriquecimento
1. **Threat Actors ↔ IOCs**: Vincular IOCs MISP a threat actors conhecidos
2. **Malware ↔ IOCs**: Identificar família de malware por hash
3. **Tools ↔ Actors**: Mapear ferramentas usadas por cada grupo

### Phase 3: Análise Avançada
1. **Graph Database**: Visualizar relacionamentos (Neo4j)
2. **LLM Integration**: Usar LLM para análise de descrições
3. **Automatic Tagging**: Tag IOCs automaticamente com galaxy clusters
4. **Campaign Tracking**: Rastrear campanhas por actor+malware+iocs

### Phase 4: UI/UX
1. **Galaxy Browser**: Interface para explorar clusters
2. **Actor Profiles**: Páginas detalhadas de threat actors
3. **Malware Encyclopedia**: Catálogo de malware families
4. **Relationship Graphs**: Visualização de conexões

## 🔧 Modelo de Dados Proposto

### Tabela: `galaxy_clusters`

```sql
CREATE TABLE galaxy_clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    galaxy_type VARCHAR(50) NOT NULL,  -- 'threat-actor', 'malpedia', 'tool'
    uuid_galaxy VARCHAR(100) UNIQUE NOT NULL,  -- UUID do cluster
    value VARCHAR(255) NOT NULL,  -- Nome (APT1, Tinba, etc)
    description TEXT,

    -- Metadados comuns
    country VARCHAR(2),  -- ISO code
    attribution_confidence INTEGER,  -- 0-100
    synonyms JSONB,  -- Array de strings
    refs JSONB,  -- Array de URLs

    -- Threat Actor específicos
    suspected_state_sponsor VARCHAR(100),
    suspected_victims JSONB,
    target_category JSONB,
    type_of_incident JSONB,
    targeted_sector JSONB,
    motive TEXT,

    -- Malware específicos
    malware_type VARCHAR(50),  -- RAT, Trojan, Ransomware

    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    -- Full JSON para campos customizados
    raw_meta JSONB
);

CREATE INDEX idx_galaxy_type ON galaxy_clusters(galaxy_type);
CREATE INDEX idx_galaxy_value ON galaxy_clusters(value);
CREATE INDEX idx_galaxy_country ON galaxy_clusters(country);
CREATE INDEX idx_galaxy_synonyms ON galaxy_clusters USING GIN(synonyms);
```

### Tabela: `galaxy_relationships`

```sql
CREATE TABLE galaxy_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_cluster_id UUID REFERENCES galaxy_clusters(id),
    dest_cluster_uuid VARCHAR(100),  -- UUID do cluster destino
    relationship_type VARCHAR(50),  -- 'similar', 'uses', 'targets'
    tags JSONB,  -- estimative-language, etc
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_relationship_source ON galaxy_relationships(source_cluster_id);
CREATE INDEX idx_relationship_dest ON galaxy_relationships(dest_cluster_uuid);
CREATE INDEX idx_relationship_type ON galaxy_relationships(relationship_type);
```

## 📋 Próximos Passos

### Implementação Sugerida

1. ✅ **Análise e Estudo** (COMPLETO)
   - Download de clusters sample
   - Parse de estrutura JSON
   - Identificação de campos relevantes

2. 🔨 **Modelo de Dados**
   - Criar migrations Alembic
   - Definir models SQLAlchemy
   - Criar schemas Pydantic

3. 🔄 **Importação**
   - Service para download de clusters
   - Parser JSON → Database
   - Batch import com progress tracking

4. 📡 **API**
   - Endpoints REST para galaxies
   - Busca por tipo, país, sinônimos
   - Relacionamentos (graph queries)

5. 🎨 **Frontend**
   - Galaxy Browser page
   - Actor Detail cards
   - Relationship graph visualization

6. 🔗 **Integração**
   - Vincular IOCs a malware families
   - Tag threat actors em análises
   - Enriquecimento automático

## 🌟 Benefícios

### Para Analistas
- **Contexto Rico**: Cada IOC ganha contexto de threat actor e malware
- **Atribuição**: Identificar origem geográfica e patrocinadores
- **Campanhas**: Rastrear atividades de grupos conhecidos

### Para Gestão
- **Inteligência Geopolítica**: Quais países nos atacam?
- **Setores Alvo**: Estamos no perfil de vítimas de algum grupo?
- **Tendências**: Quais malware families estão crescendo?

### Para Operações
- **Detection Engineering**: Criar rules baseadas em TTPs conhecidas
- **Hunt Operations**: Buscar IOCs de campanhas ativas
- **Incident Response**: Identificar rápido a família de malware

## 🔗 Referências

- **GitHub**: https://github.com/MISP/misp-galaxy
- **Documentação MISP**: https://www.misp-project.org/galaxy.html
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Malpedia**: https://malpedia.caad.fkie.fraunhofer.de/
- **CFR Cyber Operations Tracker**: https://www.cfr.org/cyber-operations/

---

**Data da Análise**: 2025-01-21
**Clusters Analisados**: threat-actor, malpedia, tool
**Total de Entries**: 4.729 (864 + 3.260 + 605)
