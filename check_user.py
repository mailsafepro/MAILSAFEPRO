#!/usr/bin/env python3
"""Script para verificar si un usuario existe en Redis"""

import asyncio
import json
import sys
from redis.asyncio import Redis
from app.config import settings


async def check_user(email: str):
    """Verifica si un usuario existe y muestra sus datos"""
    # Conectar a Redis
    redis_url = str(settings.redis_url)
    if "redis://redis:" in redis_url or redis_url.startswith("redis://redis"):
        redis_url = redis_url.replace("redis://redis:", "redis://localhost:")
        redis_url = redis_url.replace("redis://redis/", "redis://localhost/")
    
    redis = Redis.from_url(redis_url, decode_responses=False)
    
    try:
        await redis.ping()
        print(f"✅ Conectado a Redis")
        
        # Buscar por email exacto
        email_key = f"user:email:{email}"
        print(f"\n🔍 Buscando: {email_key}")
        email_data = await redis.get(email_key)
        
        if email_data:
            email_str = email_data.decode() if isinstance(email_data, bytes) else email_data
            print(f"✅ Encontrado en índice: {email_str}")
            user_data = json.loads(email_str)
            user_id = user_data.get("id")
            
            # Buscar datos del usuario
            user_key = f"user:{user_id}"
            user_hash = await redis.hgetall(user_key)
            if user_hash:
                user_dict = {}
                for k, v in user_hash.items():
                    key = k.decode() if isinstance(k, bytes) else k
                    val = v.decode() if isinstance(v, bytes) else v
                    user_dict[key] = val
                print(f"✅ Datos del usuario:")
                for k, v in user_dict.items():
                    print(f"   {k}: {v}")
        else:
            print(f"❌ No encontrado en índice")
            
            # Buscar variaciones (lowercase, uppercase)
            email_lower = email.lower()
            email_upper = email.upper()
            
            for variant in [email_lower, email_upper]:
                variant_key = f"user:email:{variant}"
                variant_data = await redis.get(variant_key)
                if variant_data:
                    print(f"✅ Encontrado variación: {variant_key}")
                    email_str = variant_data.decode() if isinstance(variant_data, bytes) else variant_data
                    print(f"   Datos: {email_str}")
                    break
        
        # Buscar en el set de emails
        print(f"\n🔍 Buscando en users:emails set...")
        all_emails = await redis.smembers("users:emails")
        if all_emails:
            print(f"✅ Encontrados {len(all_emails)} emails en el set:")
            for e in all_emails:  # Mostrar todos
                email_str = e.decode() if isinstance(e, bytes) else e
                print(f"   - {email_str}")
        else:
            print(f"❌ Set users:emails vacío")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await redis.aclose()


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else "pabloagudo01@yahoo.com"
    asyncio.run(check_user(email))

