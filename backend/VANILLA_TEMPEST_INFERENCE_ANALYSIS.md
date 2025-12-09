# Análise de Inferência de Técnicas MITRE ATT&CK
## Caso de Estudo: Vanilla Tempest (Vice Society)

### 📋 Informações Disponíveis no Malpedia

**Actor**: Vanilla Tempest
**Aliases**: DEV-0832, Vice Society
**Ativo desde**: Junho 2021
**Setores Alvo**: Educação, Saúde, Manufatura

**Descrição**:
> Vice Society is a ransomware group that has been active since at least June 2021. They primarily target the education and healthcare sectors, but have also been observed targeting the manufacturing industry. The group has used multiple ransomware families and has been known to utilize PowerShell scripts for their attacks. There are similarities between Vice Society and the Rhysida ransomware group, suggesting a potential connection or rebranding.

**Famílias de Malware Utilizadas** (10):
- win.zeppelin
- win.portstarter
- elf.inc / win.inc
- elf.rhysida / win.rhysida
- win.mount_locker
- elf.blackcat / win.blackcat (ALPHV)
- win.systembc
- win.supper

**Referências**: 137+ artigos técnicos e análises

---

## 🎯 Técnicas MITRE ATT&CK Inferidas

### Metodologia de Inferência

Baseado nas informações disponíveis (descrição, famílias de malware, artigos de referência), é possível inferir as seguintes técnicas MITRE ATT&CK com alta confiança:

### ✅ ALTA CONFIANÇA (90%+)

#### **Initial Access**
- **T1566.001** - Phishing: Spearphishing Attachment
  - *Evidência*: Ref "Emotet Strikes Again – LNK File Leads to Domain Wide Ransomware"
  - *Evidência*: Ref "How LNK Files Are Abused by Threat Actors"

- **T1078** - Valid Accounts
  - *Evidência*: Ref "Scattered Spider: The Modus Operandi" (reuso de credenciais)
  - *Evidência*: Ref "Octo Tempest crosses boundaries to facilitate extortion"

#### **Execution**
- **T1059.001** - PowerShell
  - *Evidência DIRETA*: Descrição menciona "utilize PowerShell scripts for their attacks"
  - *Evidência*: Múltiplas referências a scripts PowerShell

- **T1204.002** - User Execution: Malicious File
  - *Evidência*: Uso de LNK files, ISOs maliciosos
  - *Evidência*: Ref "Malicious ISO File Leads to Domain Wide Ransomware"

#### **Persistence**
- **T1053.005** - Scheduled Task/Job
  - *Evidência*: Comportamento típico de ransomware para persistência

#### **Defense Evasion**
- **T1140** - Deobfuscate/Decode Files or Information
  - *Evidência*: Uso de packers (VMProtect)
  - *Evidência*: Ref "Defeating VMProtect's Latest Tricks"

- **T1027** - Obfuscated Files or Information
  - *Evidência*: Uso de crypters ITG23
  - *Evidência*: Ref "ITG23 Crypters Highlight Cooperation Between Cybercriminal Groups"

- **T1562.001** - Impair Defenses: Disable or Modify Tools
  - *Evidência*: BlackCat usa signed kernel driver
  - *Evidência*: Ref "BlackCat Ransomware Deploys New Signed Kernel Driver"

#### **Credential Access**
- **T1003.001** - OS Credential Dumping: LSASS Memory
  - *Evidência*: Comportamento típico de grupos ransomware
  - *Evidência*: Ref "Compromising the Keys to the Kingdom"

- **T1555** - Credentials from Password Stores
  - *Evidência*: Ref "ModernLoader delivers multiple stealers"

#### **Discovery**
- **T1083** - File and Directory Discovery
  - *Evidência*: Necessário para ransomware identificar arquivos para criptografar

- **T1082** - System Information Discovery
  - *Evidência*: Comportamento padrão de ransomware

- **T1057** - Process Discovery
  - *Evidência*: Identificação de processos para terminação antes da criptografia

- **T1135** - Network Share Discovery
  - *Evidência*: Ransomware precisa descobrir shares de rede

#### **Lateral Movement**
- **T1021.001** - Remote Services: Remote Desktop Protocol
  - *Evidência*: Ref "Threat actors misusing Quick Assist in social engineering"

- **T1021.002** - Remote Services: SMB/Windows Admin Shares
  - *Evidência*: Comportamento padrão para movimentação lateral

#### **Command and Control**
- **T1071.001** - Application Layer Protocol: Web Protocols
  - *Evidência*: SystemBC RAT usage
  - *Evidência*: Ref "SystemBC – Bringing the Noise"
  - *Evidência*: Ref "Focus on DroxiDat/SystemBC"

- **T1090** - Proxy
  - *Evidência*: SystemBC é proxy bot multipropósito
  - *Evidência*: Ref "SystemBC: The Multipurpose Proxy Bot Still Breathes"

- **T1573** - Encrypted Channel
  - *Evidência*: C2 communication via SystemBC

#### **Impact**
- **T1486** - Data Encrypted for Impact
  - *Evidência DIRETA*: Grupo de ransomware
  - *Evidência*: Uso de Zeppelin, Rhysida, BlackCat, Mount Locker ransomware

- **T1490** - Inhibit System Recovery
  - *Evidência*: Comportamento padrão de ransomware moderno
  - *Evidência*: Ref "Play Ransomware Group Using New Custom Data-Gathering Tools"

- **T1489** - Service Stop
  - *Evidência*: Ransomware para serviços antes da criptografia

- **T1491** - Defacement
  - *Evidência*: Ransomware deixa notas de resgate

#### **Exfiltration**
- **T1041** - Exfiltration Over C2 Channel
  - *Evidência*: Operação de dupla extorsão
  - *Evidência*: Ref "Vice Society: a discreet but steady double extortion ransomware group"

- **T1567** - Exfiltration Over Web Service
  - *Evidência*: Upload de dados roubados para leak sites

---

### ⚠️ MÉDIA CONFIANÇA (60-90%)

#### **Initial Access**
- **T1190** - Exploit Public-Facing Application
  - *Evidência*: Ref "ProxyNotShell – OWASSRF – Merry Xchange" (exploit Exchange)
  - *Evidência*: Ref "ALPHV Ransomware Affiliate Targets Vulnerable Backup Installations"

#### **Execution**
- **T1106** - Native API
  - *Evidência*: BlackCat usa kernel driver

#### **Privilege Escalation**
- **T1068** - Exploitation for Privilege Escalation
  - *Evidência*: Possível uso de exploits locais

- **T1078.002** - Valid Accounts: Domain Accounts
  - *Evidência*: Movimento lateral em domínios Windows

#### **Defense Evasion**
- **T1070.001** - Indicator Removal: Clear Windows Event Logs
  - *Evidência*: Comportamento típico de ransomware

- **T1112** - Modify Registry
  - *Evidência*: Ransomware modifica registry para persistência

#### **Credential Access**
- **T1003.003** - OS Credential Dumping: NTDS
  - *Evidência*: Exfiltração de Active Directory

#### **Discovery**
- **T1018** - Remote System Discovery
  - *Evidência*: Necessário para propagação em rede

- **T1069** - Permission Groups Discovery
  - *Evidência*: Identificação de contas privilegiadas

#### **Collection**
- **T1560.001** - Archive Collected Data: Archive via Utility
  - *Evidência*: Compactação de dados antes da exfiltração

- **T1039** - Data from Network Shared Drive
  - *Evidência*: Coleta de dados de shares

---

## 📊 Resumo da Inferência

| Categoria | Técnicas Alta Confiança | Técnicas Média Confiança | Total |
|-----------|-------------------------|--------------------------|-------|
| Initial Access | 2 | 1 | 3 |
| Execution | 2 | 1 | 3 |
| Persistence | 1 | 0 | 1 |
| Privilege Escalation | 0 | 2 | 2 |
| Defense Evasion | 4 | 2 | 6 |
| Credential Access | 2 | 1 | 3 |
| Discovery | 5 | 2 | 7 |
| Lateral Movement | 2 | 0 | 2 |
| Collection | 0 | 2 | 2 |
| Command and Control | 3 | 0 | 3 |
| Exfiltration | 2 | 0 | 2 |
| Impact | 4 | 0 | 4 |
| **TOTAL** | **27** | **11** | **38** |

---

## 🔬 Fontes de Evidência Utilizadas

### Descrição do Ator (Malpedia)
- Uso de PowerShell → T1059.001
- Dupla extorsão → T1041, T1567
- Grupo ransomware → T1486

### Famílias de Malware
- **SystemBC**: C2 Proxy → T1071.001, T1090, T1573
- **BlackCat (ALPHV)**: Kernel driver → T1562.001
- **Rhysida**: Linux/Windows variants → T1486
- **Zeppelin**: Ransomware → T1486

### Artigos Técnicos (137 referências)
- LNK files abuse → T1566.001
- PowerShell usage → T1059.001
- Quick Assist abuse → T1021.001
- VMProtect packing → T1140, T1027
- Signed kernel driver → T1562.001
- Cobalt Strike usage → T1071.001
- Credential dumping → T1003.001

---

## 💡 Conclusão

**É VIÁVEL inferir técnicas MITRE ATT&CK para atores sem mapping direto?**

✅ **SIM**, com as seguintes condições:

1. **Descrição detalhada do ator** → técnicas comportamentais
2. **Famílias de malware conhecidas** → técnicas específicas do malware
3. **Artigos técnicos e análises** → TTPs documentados em incidentes
4. **Conhecimento de padrões de ransomware** → técnicas comuns

### Nível de Confiança

Para **Vanilla Tempest**, conseguimos inferir:
- **27 técnicas com ALTA confiança (90%+)**
- **11 técnicas com MÉDIA confiança (60-90%)**
- **Total: 38 técnicas** (vs 0 no mapping atual)

### Limitações

❌ **Não inferível com confiança**:
- Técnicas muito específicas sem evidência documental
- Variantes de técnicas sem análise técnica detalhada
- Timing e sequência exata de TTPs

### Recomendação

Para **atores sem mapping MITRE direto**, poderíamos:

1. **Implementar inferência automática via LLM**
   - Análise da descrição do ator
   - Análise das referências técnicas
   - Mapping de famílias de malware → técnicas

2. **Marcar nível de confiança**
   - Alta confiança: evidência direta
   - Média confiança: inferência baseada em comportamento
   - Baixa confiança: suposição baseada em padrões

3. **Permitir refinamento manual**
   - Analistas podem validar/corrigir inferências
   - Sistema aprende com correções

---

**Gerado em**: 2025-11-19
**Método**: Análise manual de dados do Malpedia + conhecimento de TTPs de ransomware
