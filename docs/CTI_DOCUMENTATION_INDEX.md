# 📚 CTI Module - Documentation Index

**Última Atualização**: 2025-11-20
**Status**: ✅ Módulo 100% Operacional e Documentado

---

## 📖 Guia de Documentação

Este índice organiza toda a documentação do módulo CTI (Cyber Threat Intelligence) da Minerva Intelligence Platform.

---

## 🎯 Documentos Principais

### 1. 🔄 [ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md) ⭐ **COMEÇE AQUI**

**O QUE É**: Guia completo de operação do sistema CTI

**QUANDO USAR**:
- Primeira vez configurando o sistema
- Executar rotinas de sincronização/enriquecimento
- Troubleshooting de problemas operacionais

**CONTEÚDO**:
- ✅ Rotina completa passo a passo (primeira execução)
- ✅ Rotina de atualização periódica (semanal/mensal)
- ✅ Rotina de manutenção e validação
- ✅ Scripts e comandos prontos para uso
- ✅ Troubleshooting detalhado
- ✅ Health checks e monitoramento

**LINHAS**: 850+ | **NÍVEL**: Operacional (prático)

---

### 2. 📋 [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md)

**O QUE É**: Documentação técnica completa do processo de backend

**QUANDO USAR**:
- Entender a arquitetura do sistema
- Desenvolver novas features
- Debug de problemas técnicos

**CONTEÚDO**:
- ✅ Visão geral da arquitetura (3 camadas)
- ✅ Sincronização Malpedia (web scraping)
- ✅ Enriquecimento MITRE ATT&CK (oficial)
- ✅ Enriquecimento LLM (inferência GPT-4o Mini)
- ✅ Estrutura de índices Elasticsearch
- ✅ Fluxo completo de dados
- ✅ APIs disponíveis
- ✅ Estatísticas e métricas
- ✅ Roadmap futuro

**LINHAS**: 586 | **NÍVEL**: Técnico (arquitetura)

---

### 3. 🏗️ [CTI_UPDATE_ARCHITECTURE.md](../backend/CTI_UPDATE_ARCHITECTURE.md)

**O QUE É**: Arquitetura de atualização incremental e enriquecida

**QUANDO USAR**:
- Entender o sistema de detecção de mudanças
- Implementar novos tipos de enrichment
- Otimizar performance

**CONTEÚDO**:
- ✅ Comparação: Pipeline atual vs. proposta
- ✅ Arquitetura de índices Elasticsearch
- ✅ Fluxo de atualização incremental
- ✅ Algoritmo de detecção de mudanças (content hash)
- ✅ Estrutura do cache enriquecido
- ✅ Estratégia de inferência LLM
- ✅ Implementação prática (Celery tasks)
- ✅ Próximos passos e benefícios

**LINHAS**: 483 | **NÍVEL**: Arquitetural (design)

---

### 4. 📥 [MALPEDIA_SYNC_README.md](../backend/MALPEDIA_SYNC_README.md)

**O QUE É**: Documentação específica do processo de sincronização Malpedia

**QUANDO USAR**:
- Troubleshooting de problemas de sync
- Entender o algoritmo de detecção de mudanças
- Otimizar performance de sync

**CONTEÚDO**:
- ✅ Arquitetura do pipeline de sincronização
- ✅ Estrutura de arquivos e scripts
- ✅ Comandos de uso (manual sync)
- ✅ Algoritmo de detecção de mudanças
- ✅ Estrutura de documentos
- ✅ Performance (incremental vs full)
- ✅ Configuração e rate limiting
- ✅ Cálculo de hash (MD5)
- ✅ Monitoramento e logs
- ✅ Troubleshooting específico de sync

**LINHAS**: 511 | **NÍVEL**: Operacional (sync específico)

---

### 5. 🔬 [VANILLA_TEMPEST_INFERENCE_ANALYSIS.md](../backend/VANILLA_TEMPEST_INFERENCE_ANALYSIS.md)

**O QUE É**: Análise técnica de um caso real de inferência LLM

**QUANDO USAR**:
- Entender como funciona a inferência LLM
- Validar qualidade das inferências
- Ajustar prompts e parâmetros

**CONTEÚDO**:
- ✅ Caso de estudo: VANILLA TEMPEST
- ✅ Comparação: MITRE direto vs. LLM inference
- ✅ Análise de técnicas inferidas
- ✅ Nível de confiança e reasoning
- ✅ Validação de acurácia
- ✅ Insights sobre o processo de inferência

**LINHAS**: 272 | **NÍVEL**: Análise técnica (case study)

---

## 📊 Documentos Complementares

### 6. 🚀 [CTI_MODULE_PROGRESS.md](CTI_MODULE_PROGRESS.md)

**O QUE É**: Relatório de progresso do desenvolvimento

**CONTEÚDO**:
- Estrutura modular criada
- Backend schemas (Pydantic)
- Services implementados
- API endpoints
- Integração com main app
- Documentação criada
- Próximos passos

**LINHAS**: 418 | **NÍVEL**: Status de desenvolvimento

---

### 7. 📑 [CTI_FEATURES_RESEARCH.md](CTI_FEATURES_RESEARCH.md)

**O QUE É**: Pesquisa detalhada de features possíveis

**CONTEÚDO**:
- Análise dos dados Malpedia
- Opções de integração MITRE ATT&CK
- Opções de integração MISP
- Desafios técnicos e soluções

**LINHAS**: 7000+ | **NÍVEL**: Research (exploratório)

---

### 8. 📝 [CTI_FEATURES_SUMMARY.md](CTI_FEATURES_SUMMARY.md)

**O QUE É**: Resumo executivo das features

**CONTEÚDO**:
- Executive summary
- Decisões necessárias
- Recomendações
- Roadmap

**LINHAS**: ~500 | **NÍVEL**: Executive (decisão)

---

### 9. 🎨 [CTI_DASHBOARD_MOCKUP.md](CTI_DASHBOARD_MOCKUP.md)

**O QUE É**: Mockup visual do dashboard CTI

**CONTEÚDO**:
- Mockup visual completo
- Fluxos de usuário
- Especificações de componentes

**LINHAS**: ~800 | **NÍVEL**: UI/UX (frontend)

---

## 🗂️ Organização por Caso de Uso

### 👤 Sou Operador: Preciso executar rotinas

**Leia nesta ordem:**
1. ⭐ [ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md) - Guia completo
2. 📥 [MALPEDIA_SYNC_README.md](../backend/MALPEDIA_SYNC_README.md) - Se tiver problemas de sync

---

### 👨‍💻 Sou Desenvolvedor: Preciso entender a arquitetura

**Leia nesta ordem:**
1. 📋 [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md) - Arquitetura geral
2. 🏗️ [CTI_UPDATE_ARCHITECTURE.md](../backend/CTI_UPDATE_ARCHITECTURE.md) - Design do sistema
3. 🚀 [CTI_MODULE_PROGRESS.md](CTI_MODULE_PROGRESS.md) - Status atual
4. 🔬 [VANILLA_TEMPEST_INFERENCE_ANALYSIS.md](../backend/VANILLA_TEMPEST_INFERENCE_ANALYSIS.md) - Caso real

---

### 🎯 Sou Product Manager: Preciso tomar decisões

**Leia nesta ordem:**
1. 📝 [CTI_FEATURES_SUMMARY.md](CTI_FEATURES_SUMMARY.md) - Executive summary
2. 📋 [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md) - Seção "Roadmap Futuro"
3. 📑 [CTI_FEATURES_RESEARCH.md](CTI_FEATURES_RESEARCH.md) - Se precisar de detalhes

---

### 🎨 Sou Designer: Preciso implementar UI

**Leia nesta ordem:**
1. 🎨 [CTI_DASHBOARD_MOCKUP.md](CTI_DASHBOARD_MOCKUP.md) - Mockups e specs
2. 🚀 [CTI_MODULE_PROGRESS.md](CTI_MODULE_PROGRESS.md) - APIs disponíveis

---

## 📈 Estatísticas da Documentação

```
Total de Documentos: 9
Total de Linhas: ~11,500+
Páginas Estimadas: ~350 páginas A4

Por Categoria:
- Operacional: 2 docs (~1,350 linhas)
- Técnico/Arquitetura: 3 docs (~1,550 linhas)
- Research: 1 doc (~7,000 linhas)
- Status/Progresso: 2 docs (~900 linhas)
- UI/UX: 1 doc (~800 linhas)
```

---

## 🔍 Busca Rápida

### Por Tópico

| Tópico | Documento Principal |
|--------|---------------------|
| **Como executar sync** | [ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md) |
| **Como funciona enrichment** | [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md) |
| **Detecção de mudanças** | [CTI_UPDATE_ARCHITECTURE.md](../backend/CTI_UPDATE_ARCHITECTURE.md) |
| **LLM Inference** | [VANILLA_TEMPEST_INFERENCE_ANALYSIS.md](../backend/VANILLA_TEMPEST_INFERENCE_ANALYSIS.md) |
| **Troubleshooting** | [ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md) #troubleshooting |
| **APIs disponíveis** | [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md) #apis |
| **Estrutura de dados** | [ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md) #estrutura-de-dados |
| **Performance** | [MALPEDIA_SYNC_README.md](../backend/MALPEDIA_SYNC_README.md) #performance |
| **Roadmap** | [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md) #roadmap |

---

### Por Palavra-chave

- **Malpedia**: Docs 1, 2, 4
- **MITRE ATT&CK**: Docs 1, 2, 3, 5
- **LLM**: Docs 1, 2, 3, 5
- **Elasticsearch**: Docs 1, 2, 3, 4
- **Cache**: Docs 1, 2, 3
- **Sync**: Docs 1, 4
- **Enrichment**: Docs 1, 2, 3, 5
- **API**: Docs 2, 6
- **Scripts**: Docs 1, 4
- **Performance**: Docs 1, 4

---

## ✅ Checklist de Leitura

Para operadores:
- [ ] Li ROTINAS_CTI_COMPLETAS.md
- [ ] Executei primeira rotina com sucesso
- [ ] Sei como fazer troubleshooting
- [ ] Sei como executar health check

Para desenvolvedores:
- [ ] Li CTI_BACKEND_PROCESS.md
- [ ] Li CTI_UPDATE_ARCHITECTURE.md
- [ ] Entendo a arquitetura de 3 camadas
- [ ] Entendo o algoritmo de content hash
- [ ] Li um caso de estudo (VANILLA_TEMPEST)

Para product managers:
- [ ] Li CTI_FEATURES_SUMMARY.md
- [ ] Entendo as capabilities do sistema
- [ ] Conheço as limitações
- [ ] Vi o roadmap de features

---

## 🔄 Últimas Atualizações

**2025-11-20**:
- ✅ Criado ROTINAS_CTI_COMPLETAS.md (guia operacional definitivo)
- ✅ Sistema 100% operacional (864/864 actors enriquecidos)
- ✅ Documentação consolidada e indexada

**2025-11-19**:
- ✅ Criado CTI_BACKEND_PROCESS.md
- ✅ Criado CTI_UPDATE_ARCHITECTURE.md
- ✅ Criado MALPEDIA_SYNC_README.md
- ✅ Criado VANILLA_TEMPEST_INFERENCE_ANALYSIS.md

---

## 📞 Suporte

**Dúvidas sobre operação**: Consulte [ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md)

**Dúvidas sobre arquitetura**: Consulte [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md)

**Problemas técnicos**: Veja seção Troubleshooting em [ROTINAS_CTI_COMPLETAS.md](../ROTINAS_CTI_COMPLETAS.md)

**Feature requests**: Veja Roadmap em [CTI_BACKEND_PROCESS.md](../CTI_BACKEND_PROCESS.md)

---

**Documentação compilada com ❤️ para ADINT**

**Autor**: Angello Cassio
**Data**: 2025-11-20
**Versão**: 1.0
