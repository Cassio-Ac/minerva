#!/usr/bin/env python3
"""
Script para verificar se o banco de dados está corretamente configurado
Verifica tabelas, índices e dados essenciais
"""
import sys
import os
import asyncio
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

# Adicionar path do projeto
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def check_database():
    """Verifica estrutura do banco de dados"""
    from dotenv import load_dotenv

    # Carregar .env.local
    load_dotenv('.env.local')

    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        print("❌ DATABASE_URL não configurada!")
        return False

    print(f"🔍 Conectando ao banco: {database_url.split('@')[1] if '@' in database_url else 'database'}")

    try:
        engine = create_async_engine(database_url, echo=False)

        async with engine.connect() as conn:
            # Verificar tabelas essenciais
            result = await conn.execute(text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
            """))

            tables = [row[0] for row in result]

            # Tabelas esperadas (principais)
            expected_tables = [
                'users',
                'es_servers',
                'rss_feeds',
                'llm_providers',
                'telegram_accounts',
                'alembic_version'
            ]

            print(f"\n📊 Tabelas encontradas: {len(tables)}")
            for table in tables:
                status = "✅" if table in expected_tables else "ℹ️ "
                print(f"   {status} {table}")

            # Verificar se tabelas críticas existem
            missing_tables = [t for t in expected_tables if t not in tables]
            if missing_tables:
                print(f"\n⚠️  Tabelas esperadas mas não encontradas: {missing_tables}")

            # Verificar usuário admin
            result = await conn.execute(text("""
                SELECT COUNT(*) FROM users WHERE role = 'admin'
            """))
            admin_count = result.scalar()

            if admin_count > 0:
                print(f"\n✅ Usuários admin encontrados: {admin_count}")
            else:
                print(f"\n⚠️  NENHUM usuário admin encontrado!")
                print("   Execute o seed para criar usuário admin padrão.")

            # Verificar índices da tabela users
            result = await conn.execute(text("""
                SELECT indexname
                FROM pg_indexes
                WHERE tablename = 'users'
            """))
            indices = [row[0] for row in result]
            print(f"\n📑 Índices da tabela 'users': {len(indices)}")
            for idx in indices:
                print(f"   ✅ {idx}")

            print("\n✅ Verificação do banco de dados concluída!")
            return True

    except Exception as e:
        print(f"\n❌ ERRO ao verificar banco de dados: {e}")
        return False
    finally:
        await engine.dispose()

if __name__ == "__main__":
    success = asyncio.run(check_database())
    sys.exit(0 if success else 1)
