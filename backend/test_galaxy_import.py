#!/usr/bin/env python3
"""
Script de teste para importação do MISP Galaxy
"""
import asyncio
import sys
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.cti.services.misp_galaxy_service import MISPGalaxyService

async def test_galaxy_import():
    """Testa a importação de clusters MISP Galaxy"""

    # Criar engine async
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        service = MISPGalaxyService(session)

        print("🚀 Testando importação do MISP Galaxy")
        print("=" * 60)

        # Testar importação de threat-actors (apenas 10 para teste rápido)
        print("\n📥 Importando threat-actors (limit=10)...")
        try:
            result = await service.import_cluster(
                cluster_type="threat-actor",
                limit=10,
                skip_relationships=True  # Skip relationships para teste mais rápido
            )

            print(f"\n✅ Importação concluída!")
            print(f"   - Tipo: {result['cluster_type']}")
            print(f"   - Total disponível: {result['total_available']}")
            print(f"   - Total processado: {result['total_processed']}")
            print(f"   - Importados: {result['imported']}")
            print(f"   - Relacionamentos: {result['relationships']}")

        except Exception as e:
            print(f"\n❌ Erro na importação: {e}")
            import traceback
            traceback.print_exc()
            return False

        # Buscar estatísticas
        print("\n📊 Buscando estatísticas...")
        try:
            stats = await service.get_stats()
            print(f"\n✅ Estatísticas:")
            print(f"   - Total clusters: {stats['total_clusters']}")
            print(f"   - Por tipo: {stats['by_type']}")
            if stats['by_country']:
                print(f"   - Por país (top 5): {dict(list(stats['by_country'].items())[:5])}")
            print(f"   - Relacionamentos: {stats['total_relationships']}")

        except Exception as e:
            print(f"\n❌ Erro ao buscar stats: {e}")
            return False

        # Buscar um cluster específico
        print("\n🔍 Buscando clusters...")
        try:
            search_result = await service.search_clusters(
                cluster_type="threat-actor",
                limit=5
            )

            print(f"\n✅ Encontrados {search_result['total']} clusters:")
            for cluster in search_result['clusters']:
                print(f"   - {cluster['value']}: {cluster.get('country', 'N/A')} "
                      f"(confidence: {cluster.get('attribution_confidence', 'N/A')})")

        except Exception as e:
            print(f"\n❌ Erro na busca: {e}")
            return False

        print("\n" + "=" * 60)
        print("✅ Todos os testes passaram com sucesso!")
        return True

if __name__ == "__main__":
    success = asyncio.run(test_galaxy_import())
    sys.exit(0 if success else 1)
