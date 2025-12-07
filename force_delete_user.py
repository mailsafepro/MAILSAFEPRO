#!/usr/bin/env python3
"""Script para forzar la eliminación de un usuario eliminando TODAS las posibles claves"""

import asyncio
import sys
from redis.asyncio import Redis
from app.config import settings


async def force_delete_user(email: str):
    """Fuerza la eliminación eliminando todas las posibles variantes"""
    redis_url = str(settings.redis_url)
    if "redis://redis:" in redis_url or redis_url.startswith("redis://redis"):
        redis_url = redis_url.replace("redis://redis:", "redis://localhost:")
        redis_url = redis_url.replace("redis://redis/", "redis://localhost/")
    
    redis = Redis.from_url(redis_url, decode_responses=False)
    
    try:
        await redis.ping()
        print(f"✅ Conectado a Redis")
        
        email_variants = [
            email,
            email.lower(),
            email.upper(),
            email.lower().strip(),
            email.strip(),
        ]
        
        print(f"\n🗑️  FORZANDO eliminación de: {email}")
        print(f"   Eliminando todas las variantes posibles...\n")
        
        deleted_count = 0
        
        # 1. Eliminar todas las variantes de user:email:*
        for variant in email_variants:
            key = f"user:email:{variant}"
            if await redis.exists(key):
                await redis.delete(key)
                print(f"✅ Eliminado: {key}")
                deleted_count += 1
            else:
                print(f"   No existe: {key}")
        
        # 2. Eliminar del set users:emails
        for variant in email_variants:
            result = await redis.srem("users:emails", variant)
            if result:
                print(f"✅ Eliminado de users:emails: {variant}")
                deleted_count += 1
        
        # 3. Buscar y eliminar cualquier clave que contenga el email
        print(f"\n🔍 Buscando claves que contengan el email...")
        all_keys = await redis.keys("*")
        for key in all_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            if email.lower() in key_str.lower():
                if await redis.exists(key_str):
                    await redis.delete(key_str)
                    print(f"✅ Eliminado: {key_str}")
                    deleted_count += 1
        
        # 4. Buscar user:* que pueda contener el email en su valor
        print(f"\n🔍 Buscando en valores de claves user:*...")
        user_keys = await redis.keys("user:*")
        for key in user_keys:
            key_str = key.decode() if isinstance(key, bytes) else key
            if key_str.startswith("user:email:"):
                continue  # Ya lo procesamos
            
            # Si es un hash, buscar en los valores
            if key_str.startswith("user:") and ":" not in key_str.split("user:")[1].split(":")[0]:
                # Es un hash de usuario
                user_hash = await redis.hgetall(key_str)
                for field, value in user_hash.items():
                    field_str = field.decode() if isinstance(field, bytes) else field
                    value_str = value.decode() if isinstance(value, bytes) else value
                    if email.lower() in value_str.lower() and field_str == "email":
                        print(f"✅ Encontrado email en: {key_str}")
                        await redis.delete(key_str)
                        print(f"   Eliminado: {key_str}")
                        deleted_count += 1
                        break
        
        print(f"\n✅ Proceso completado")
        print(f"   Total de claves eliminadas: {deleted_count}")
        
        # Verificar si ahora se puede registrar
        print(f"\n🔍 Verificando si el usuario puede registrarse ahora...")
        test_key = f"user:email:{email.lower().strip()}"
        exists = await redis.exists(test_key)
        if exists:
            print(f"   ⚠️  Aún existe: {test_key}")
        else:
            print(f"   ✅ No existe: {test_key}")
            print(f"   El usuario debería poder registrarse ahora")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await redis.aclose()


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else "pabloagudo01@yahoo.com"
    asyncio.run(force_delete_user(email))

