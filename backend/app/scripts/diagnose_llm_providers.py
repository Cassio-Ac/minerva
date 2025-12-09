#!/usr/bin/env python3
"""
LLM Provider Diagnostic Script
Checks all LLM providers and their configurations
"""

import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.db.database import async_session_maker
from app.services.llm_provider_service import get_llm_provider_service
from app.services.llm_factory import LLMFactory


async def diagnose():
    """Run comprehensive diagnostics on LLM providers"""

    print("=" * 70)
    print("🔍 LLM PROVIDER DIAGNOSTICS")
    print("=" * 70)

    async with async_session_maker() as db:
        service = get_llm_provider_service(db)

        # 1. List all providers
        print("\n📋 STEP 1: Listing all LLM providers")
        print("-" * 70)
        try:
            providers = await service.list_providers()

            if not providers:
                print("❌ No providers found in database!")
                print("   Please configure at least one provider in Settings > LLM")
                return

            print(f"✅ Found {len(providers)} provider(s):\n")

            for i, p in enumerate(providers, 1):
                print(f"{i}. {p['name']}")
                print(f"   Type: {p['provider_type']}")
                print(f"   Model: {p['model_name']}")
                print(f"   Active: {'✅' if p['is_active'] else '❌'}")
                print(f"   Default: {'✅' if p['is_default'] else '❌'}")
                print(f"   Temperature: {p.get('temperature', 'N/A')}")
                print(f"   Max Tokens: {p.get('max_tokens', 'N/A')}")
                if p.get('api_base_url'):
                    print(f"   Base URL: {p['api_base_url']}")
                print()

        except Exception as e:
            print(f"❌ Error listing providers: {e}")
            return

        # 2. Check default provider
        print("\n🎯 STEP 2: Checking default provider")
        print("-" * 70)
        try:
            default_provider = await service.get_default_provider_with_key()

            if not default_provider:
                print("❌ No default provider configured!")
                print("   Please set a provider as default in Settings > LLM")

                # Check if any provider exists but none is default
                active_providers = [p for p in providers if p['is_active']]
                if active_providers:
                    print(f"\n💡 Suggestion: Set one of these active providers as default:")
                    for p in active_providers:
                        print(f"   - {p['name']} ({p['provider_type']})")
                return

            print(f"✅ Default provider found: {default_provider['name']}")
            print(f"   Type: {default_provider['provider_type']}")
            print(f"   Model: {default_provider['model_name']}")

            # Check if API key is present
            has_api_key = bool(default_provider.get('api_key'))
            if has_api_key:
                api_key = default_provider['api_key']
                print(f"   API Key: {'*' * 10}{api_key[-4:] if len(api_key) > 4 else '****'} (last 4 chars)")
            else:
                print("   API Key: ❌ MISSING!")
                print("   This provider cannot be used without an API key.")
                return

        except Exception as e:
            print(f"❌ Error getting default provider: {e}")
            import traceback
            traceback.print_exc()
            return

        # 3. Test client creation
        print("\n🔧 STEP 3: Testing LLM client creation")
        print("-" * 70)
        try:
            client = LLMFactory.create_client_from_config(default_provider)

            if not client:
                print("❌ Failed to create LLM client!")
                print("   Check the API key and configuration.")
                return

            print("✅ LLM client created successfully!")

            # Get provider info
            info = client.get_provider_info()
            print(f"\n📊 Client Information:")
            print(f"   Provider: {info['provider_type']}")
            print(f"   Model: {info['model_name']}")
            print(f"   Temperature: {info['temperature']}")
            print(f"   Max Tokens: {info['max_tokens']}")
            print(f"   Supports Tools: {'✅' if info.get('supports_tools') else '❌'}")
            print(f"   Supports Streaming: {'✅' if info.get('supports_streaming') else '❌'}")

        except Exception as e:
            print(f"❌ Error creating client: {e}")
            import traceback
            traceback.print_exc()
            return

        # 4. Test basic API call (optional, can be slow)
        print("\n🧪 STEP 4: Testing basic API call")
        print("-" * 70)
        print("⏳ Sending test message to LLM...")

        try:
            # Simple test message
            test_messages = [{"role": "user", "content": "Say 'hello' in one word"}]

            response = await client.generate(
                messages=test_messages,
                temperature=0.1,
                max_tokens=10
            )

            print("✅ API call successful!")
            print(f"   Response: {response.get('content', 'N/A')}")
            print(f"   Model: {response.get('model', 'N/A')}")

            if 'usage' in response:
                usage = response['usage']
                print(f"   Tokens: {usage.get('input_tokens', 0)} in / {usage.get('output_tokens', 0)} out")

        except Exception as e:
            print(f"❌ API call failed: {e}")
            print("\n🔍 Common issues:")
            print("   1. Invalid API key")
            print("   2. Insufficient credits/quota")
            print("   3. Network connectivity issues")
            print("   4. Incorrect base URL (for Databricks)")
            print("   5. Model name mismatch")

            import traceback
            traceback.print_exc()
            return

        # 5. Summary
        print("\n" + "=" * 70)
        print("✅ DIAGNOSTICS COMPLETE - ALL CHECKS PASSED!")
        print("=" * 70)
        print(f"\n🎉 Your LLM provider '{default_provider['name']}' is ready to use!")
        print("   You can now send messages and create widgets via chat.")


if __name__ == "__main__":
    try:
        asyncio.run(diagnose())
    except KeyboardInterrupt:
        print("\n\n⚠️  Diagnostics interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
