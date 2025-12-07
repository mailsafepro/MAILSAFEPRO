#!/usr/bin/env python3
"""Script para buscar un usuario de forma exhaustiva en Redis"""

import asyncio
import json
import sys
from redis.asyncio import Redis
from app.config import settings


async def find_user(email: str):
    """Busca un usuario de forma exhaustiva"""
    # Conectar a Redis
    redis_url = str(settings.redis_url)
    if "redis://redis:" in redis_url or redis_url.startswith("redis://redis"):
        redis_url = redis_url.replace("redis://redis:", "redis://localhost:")
        redis_url = redis_url.replace("redis://redis/", "redis://localhost/")
    
    redis = Redis.from_url(redis_url, decode_responses=False)
    
    try:
        await redis.ping()
        print(f"✅ Conectado a Redis")
        
        email_lower = email.lower().strip()
        email_variants = [
            email,
            email_lower,
            email.upper(),
            email_lower.replace("@yahoo.com", "@yahoo.com"),
        ]
        
        print(f"\n🔍 Buscando usuario: {email}")
        print(f"   Variantes a buscar: {email_variants}")
        
        found = False
        
        # 1. Buscar en índices de email
        for variant in email_variants:
            email_key = f"user:email:{variant}"
            email_data = await redis.get(email_key)
            
            if email_data:
                email_str = email_data.decode() if isinstance(email_data, bytes) else email_data
                print(f"\n✅ ENCONTRADO en índice: {email_key}")
                print(f"   Datos: {email_str}")
                
                try:
                    user_data = json.loads(email_str)
                    user_id = user_data.get("id")
                    print(f"   User ID: {user_id}")
                    
                    # Buscar datos completos del usuario
                    user_key = f"user:{user_id}"
                    user_hash = await redis.hgetall(user_key)
                    if user_hash:
                        print(f"\n✅ Datos completos del usuario ({user_key}):")
                        user_dict = {}
                        for k, v in user_hash.items():
                            key = k.decode() if isinstance(k, bytes) else k
                            val = v.decode() if isinstance(v, bytes) else v
                            user_dict[key] = val
                            print(f"   {key}: {val}")
                        found = True
                    else:
                        print(f"   ⚠️  Hash del usuario no encontrado: {user_key}")
                except json.JSONDecodeError:
                    print(f"   ⚠️  Error parseando JSON: {email_str}")
                break
        
        if not found:
            # 2. Buscar todas las claves que empiecen con "user:email:"
            print(f"\n🔍 Buscando en todas las claves user:email:*...")
            all_email_keys = await redis.keys("user:email:*")
            print(f"   Encontradas {len(all_email_keys)} claves")
            
            for key in all_email_keys:
                key_str = key.decode() if isinstance(key, bytes) else key
                email_from_key = key_str.replace("user:email:", "")
                
                # Verificar si coincide (case-insensitive)
                if email_lower in email_from_key.lower() or email_from_key.lower() in email_lower:
                    print(f"\n✅ Posible coincidencia: {key_str}")
                    email_data = await redis.get(key_str)
                    if email_data:
                        email_str = email_data.decode() if isinstance(email_data, bytes) else email_data
                        print(f"   Datos: {email_str}")
                        try:
                            user_data = json.loads(email_str)
                            user_id = user_data.get("id")
                            print(f"   User ID: {user_id}")
                            found = True
                        except:
                            pass
        
        if not found:
            # 3. Buscar en el set de emails
            print(f"\n🔍 Buscando en users:emails set...")
            all_emails = await redis.smembers("users:emails")
            if all_emails:
                print(f"   Encontrados {len(all_emails)} emails en el set:")
                for e in all_emails:
                    email_str = e.decode() if isinstance(e, bytes) else e
                    if email_lower in email_str.lower():
                        print(f"   ✅ Coincidencia: {email_str}")
                        found = True
        
        if not found:
            print(f"\n❌ Usuario no encontrado en ninguna búsqueda")
            print(f"   Esto es extraño si el registro dice 'User already exists'")
            print(f"   Puede ser que el usuario esté en otra base de datos Redis")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await redis.aclose()


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else "pabloagudo01@yahoo.com"
    asyncio.run(find_user(email))

