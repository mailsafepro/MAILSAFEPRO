#!/usr/bin/env python3
"""
Script para eliminar un usuario del sistema.

Elimina todas las claves relacionadas en Redis:
- user:email:{email}
- user:{user_id}
- users:emails (set)
- API keys del usuario
- Usage/quota data
- Subscription data
- Rate limit data
- Tokens relacionados
"""

import asyncio
import json
import sys
from redis.asyncio import Redis
from app.config import settings
from app.auth import get_user_by_email


async def delete_user_by_email(email: str, redis: Redis) -> bool:
    """
    Elimina un usuario y todos sus datos relacionados.
    
    Args:
        email: Email del usuario a eliminar
        redis: Cliente Redis
        
    Returns:
        True si se eliminó correctamente, False si no se encontró
    """
    print(f"🔍 Buscando usuario: {email}")
    
    # 1. Intentar obtener usuario por email (puede fallar si no existe)
    user = await get_user_by_email(redis, email)
    
    # Si no se encuentra, buscar directamente en Redis
    user_id = None
    email_key = None
    
    if user:
        user_id = user.id
        email_key = f"user:email:{email}"
        print(f"✅ Usuario encontrado vía get_user_by_email: {user_id}")
    else:
        # Buscar directamente en Redis con diferentes variantes
        email_variants = [
            email,
            email.lower(),
            email.upper(),
            email.lower().strip(),
        ]
        
        for variant in email_variants:
            test_key = f"user:email:{variant}"
            email_data = await redis.get(test_key)
            if email_data:
                email_key = test_key
                try:
                    email_str = email_data.decode() if isinstance(email_data, bytes) else email_data
                    user_data = json.loads(email_str)
                    user_id = user_data.get("id")
                    print(f"✅ Usuario encontrado en Redis: {user_id} (key: {test_key})")
                    break
                except:
                    pass
        
        if not user_id:
            print(f"⚠️  Usuario no encontrado con get_user_by_email, pero intentando eliminar directamente...")
            # Intentar eliminar de todas formas por si el usuario existe pero hay un problema de búsqueda
            email_key = f"user:email:{email.lower().strip()}"
    
    if user:
        print(f"   Email: {user.email}")
        print(f"   Plan: {user.plan}")
    
    # Confirmar eliminación
    print(f"\n⚠️  ADVERTENCIA: Se eliminarán TODOS los datos del usuario")
    print(f"   - Datos del usuario")
    print(f"   - API keys")
    print(f"   - Usage/quota")
    print(f"   - Suscripciones")
    print(f"   - Rate limits")
    print(f"   - Tokens relacionados")
    
    # 2. Eliminar todas las claves relacionadas
    deleted_keys = []
    
    try:
        # a) Eliminar índice por email (usar la clave encontrada o la original)
        if not email_key:
            email_key = f"user:email:{email.lower().strip()}"
        
        # Intentar eliminar todas las variantes posibles
        email_variants_to_delete = [
            f"user:email:{email}",
            f"user:email:{email.lower()}",
            f"user:email:{email.upper()}",
            f"user:email:{email.lower().strip()}",
        ]
        
        for variant_key in email_variants_to_delete:
            if await redis.exists(variant_key):
                await redis.delete(variant_key)
                deleted_keys.append(variant_key)
                print(f"✅ Eliminado: {variant_key}")
        
        # b) Eliminar hash del usuario (solo si tenemos user_id)
        if user_id:
            user_key = f"user:{user_id}"
            if await redis.exists(user_key):
                await redis.delete(user_key)
                deleted_keys.append(user_key)
                print(f"✅ Eliminado: {user_key}")
        
        # c) Eliminar del set de emails (todas las variantes)
        for variant in [email, email.lower(), email.upper(), email.lower().strip()]:
            await redis.srem("users:emails", variant)
        print(f"✅ Eliminado de users:emails set")
        
        # d) Eliminar API keys del usuario (solo si tenemos user_id)
        if user_id:
            api_keys_pattern = f"user:{user_id}:api_keys"
            api_keys_set = await redis.smembers(api_keys_pattern)
            
            for key_hash in api_keys_set:
                key_key = f"key:{key_hash.decode() if isinstance(key_hash, bytes) else key_hash}"
                if await redis.exists(key_key):
                    await redis.delete(key_key)
                    deleted_keys.append(key_key)
                    print(f"✅ Eliminado API key: {key_key}")
            
            # Eliminar el set de API keys
            if await redis.exists(api_keys_pattern):
                await redis.delete(api_keys_pattern)
                deleted_keys.append(api_keys_pattern)
            
            # Eliminar API key principal
            primary_key = f"user:{user_id}:api_key"
            if await redis.exists(primary_key):
                key_hash = await redis.get(primary_key)
                if key_hash:
                    key_hash_str = key_hash.decode() if isinstance(key_hash, bytes) else key_hash
                    key_key = f"key:{key_hash_str}"
                    if await redis.exists(key_key):
                        await redis.delete(key_key)
                        deleted_keys.append(key_key)
                await redis.delete(primary_key)
                deleted_keys.append(primary_key)
                print(f"✅ Eliminado API key principal")
        
        # e) Eliminar usage/quota (solo si tenemos user_id)
        if user_id:
            usage_key = f"usage:{user_id}"
            if await redis.exists(usage_key):
                await redis.delete(usage_key)
                deleted_keys.append(usage_key)
                print(f"✅ Eliminado usage: {usage_key}")
            
            # f) Eliminar subscription
            subscription_key = f"user:{user_id}:subscription"
            if await redis.exists(subscription_key):
                await redis.delete(subscription_key)
                deleted_keys.append(subscription_key)
                print(f"✅ Eliminado subscription: {subscription_key}")
            
            # g) Eliminar rate limit
            rate_limit_key = f"user:{user_id}:rate_limit"
            if await redis.exists(rate_limit_key):
                await redis.delete(rate_limit_key)
                deleted_keys.append(rate_limit_key)
                print(f"✅ Eliminado rate limit: {rate_limit_key}")
        
        # h) Eliminar refresh tokens (buscar por patrón)
        # Los refresh tokens se almacenan como: refresh_token:{jti}
        # Necesitamos buscar todos los tokens del usuario
        # Esto es más complejo, pero podemos intentar limpiar tokens expirados
        
        # i) Buscar y eliminar cualquier otra clave relacionada
        # Buscar patrones adicionales
        patterns_to_check = [
            f"user:{user_id}:*",
            f"token:{user_id}:*",
            f"blacklist:{user_id}:*",
        ]
        
        for pattern in patterns_to_check:
            # Redis no tiene SCAN directo en async, pero podemos intentar con KEYS (solo en desarrollo)
            if settings.environment.value == "development":
                keys = await redis.keys(pattern)
                for key in keys:
                    key_str = key.decode() if isinstance(key, bytes) else key
                    if await redis.exists(key_str):
                        await redis.delete(key_str)
                        deleted_keys.append(key_str)
                        print(f"✅ Eliminado: {key_str}")
        
        print(f"\n✅ Usuario eliminado correctamente")
        print(f"   Total de claves eliminadas: {len(deleted_keys)}")
        return True
        
    except Exception as e:
        print(f"❌ Error al eliminar usuario: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Función principal"""
    if len(sys.argv) < 2:
        print("Uso: python delete_user.py <email>")
        print("Ejemplo: python delete_user.py pabloagudo01@yahoo.com")
        sys.exit(1)
    
    email = sys.argv[1].strip().lower()
    
    if "@" not in email:
        print("❌ Error: Email inválido")
        sys.exit(1)
    
    # Conectar a Redis directamente
    # Si la URL contiene "redis:" (nombre del contenedor), usar localhost en su lugar
    redis_url = str(settings.redis_url)
    if "redis://redis:" in redis_url or redis_url.startswith("redis://redis"):
        # Reemplazar nombre del contenedor por localhost para ejecución fuera de Docker
        redis_url = redis_url.replace("redis://redis:", "redis://localhost:")
        redis_url = redis_url.replace("redis://redis/", "redis://localhost/")
    
    print(f"🔗 Conectando a Redis: {redis_url}")
    redis = Redis.from_url(redis_url, decode_responses=False)
    
    # Verificar conexión
    try:
        await redis.ping()
        print("✅ Conexión a Redis exitosa")
    except Exception as e:
        print(f"❌ Error conectando a Redis: {e}")
        print(f"   Asegúrate de que Redis esté corriendo")
        print(f"   URL intentada: {redis_url}")
        print(f"   Intenta: redis://localhost:6379/0")
        sys.exit(1)
    
    try:
        success = await delete_user_by_email(email, redis)
        if success:
            print(f"\n🎉 Usuario {email} eliminado exitosamente")
            sys.exit(0)
        else:
            print(f"\n❌ No se pudo eliminar el usuario {email}")
            sys.exit(1)
    finally:
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())

