# Tests de Auditoría de Seguridad

Este directorio contiene tests que demuestran problemas de seguridad identificados en la auditoría técnica.

## Ejecutar Tests

```bash
# Ejecutar todos los tests de auditoría
pytest audit-tests/ -v

# Ejecutar un test específico
pytest audit-tests/test_md5_vulnerability.py -v

# Ejecutar con cobertura
pytest audit-tests/ --cov=app --cov-report=html
```

## Tests Incluidos

### test_md5_vulnerability.py
- **Problema:** Uso de MD5 para caché HTTP (vulnerable a colisiones)
- **Ubicación:** `app/asgi_middleware.py:353`
- **Severidad:** CRITICAL

### test_jwt_exceptions_missing.py
- **Problema:** `JWTError` y `JWTClaimsError` no están importados
- **Ubicación:** `app/auth.py:910,1025,1066`
- **Severidad:** CRITICAL

### test_rate_limit_fail_open.py
- **Problema:** Rate limiting permite todas las requests cuando Redis falla
- **Ubicación:** `app/main.py:698`, `app/rate_limiting/distributed_limiter.py:74`
- **Severidad:** CRITICAL

### test_pii_in_logs.py
- **Problema:** Emails completos expuestos en logs
- **Ubicación:** Múltiples archivos
- **Severidad:** HIGH

### test_token_revocation.py
- **Verifica:** Tokens revocados no pueden usarse
- **Estado:** Test de verificación de funcionalidad correcta

### test_token_expiration.py
- **Verifica:** Tokens expirados son rechazados
- **Estado:** Test de verificación de funcionalidad correcta

## Notas

- Algunos tests están diseñados para **fallar** antes de aplicar los patches, demostrando los problemas.
- Después de aplicar los patches, los tests deben **pasar** o al menos demostrar que el problema está resuelto.
- Los tests de revocación y expiración verifican que la funcionalidad existente funciona correctamente.

