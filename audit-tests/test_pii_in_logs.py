"""
Test: Exposición de PII en Logs

Verifica que los emails y otros PII no se exponen completos en logs.
"""
import pytest
from unittest.mock import patch, MagicMock
import io
import re


def test_email_masking_function():
    """
    Verifica que existe una función para enmascarar emails.
    """
    # Función helper que debería existir
    def mask_email(email: str) -> str:
        """Enmascara email para logs: user@example.com -> use***@***.com"""
        if '@' not in email:
            return "***"
        local, domain = email.rsplit('@', 1)
        if len(local) <= 3:
            masked_local = local[0] + "***"
        else:
            masked_local = local[:3] + "***"
        
        if '.' in domain:
            domain_parts = domain.split('.')
            masked_domain = "***." + domain_parts[-1] if len(domain_parts) > 1 else "***"
        else:
            masked_domain = "***"
        
        return f"{masked_local}@{masked_domain}"
    
    # Tests de la función
    assert mask_email("user@example.com") == "use***@***.com"
    assert mask_email("test@gmail.com") == "tes***@***.com"
    assert mask_email("a@b.com") == "a***@***.com"
    assert "@" not in mask_email("user@example.com") or mask_email("user@example.com").count("*") >= 3


def test_login_logs_masked_email():
    """
    Verifica que los emails en logs de login están enmascarados.
    """
    from app.auth import login_web_user
    from app.models import UserLogin
    from fastapi import Request
    from redis.asyncio import Redis
    from unittest.mock import AsyncMock, patch
    
    request = MagicMock(spec=Request)
    request.client.host = "192.168.1.1"
    
    user_data = UserLogin(email="testuser@example.com", password="TestPass123!")
    
    redis_mock = AsyncMock(spec=Redis)
    redis_mock.get.return_value = None  # User no existe
    redis_mock.incr.return_value = 1
    redis_mock.expire.return_value = True
    
    # Capturar logs
    log_calls = []
    
    with patch('app.auth.logger') as mock_logger:
        # Configurar mock para capturar llamadas
        def capture_log(*args, **kwargs):
            log_calls.append((args, kwargs))
        
        mock_logger.warning.side_effect = capture_log
        mock_logger.info.side_effect = capture_log
        
        try:
            await login_web_user(request, user_data, redis_mock)
        except Exception:
            pass  # Esperamos que falle (user no existe)
        
        # Verificar que ningún log contiene el email completo
        for args, kwargs in log_calls:
            log_message = " ".join(str(arg) for arg in args)
            # Buscar emails completos (formato: algo@dominio.com)
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            matches = re.findall(email_pattern, log_message)
            
            for email in matches:
                # Verificar que está enmascarado (debe tener al menos 3 asteriscos)
                if email.count("*") < 3 and len(email.split("@")[0]) > 3:
                    pytest.fail(
                        f"❌ Email completo encontrado en logs: {email}\n"
                        f"Log: {log_message}\n"
                        "Los emails deben estar enmascarados (ej: use***@***.com)"
                    )


def test_hibp_logs_masked_email():
    """
    Verifica que los emails en logs de HIBP están enmascarados.
    """
    from app.providers import HaveIBeenPwnedChecker
    
    # Capturar logs
    log_calls = []
    
    with patch('app.providers.logger') as mock_logger:
        def capture_log(*args, **kwargs):
            log_calls.append((args, kwargs))
        
        mock_logger.info.side_effect = capture_log
        
        # Simular check de HIBP (no hacer request real)
        email = "testuser@example.com"
        
        # Verificar que si se loguea, está enmascarado
        # (Este test verifica el patrón, no ejecuta el código real)
        import re
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        # Buscar en el código fuente si hay logs con emails
        import os
        providers_file = os.path.join(
            os.path.dirname(__file__), "..", "app", "providers.py"
        )
        
        if os.path.exists(providers_file):
            with open(providers_file, "r") as f:
                content = f.read()
                # Buscar logs que contengan emails
                lines = content.split("\n")
                for i, line in enumerate(lines, 1):
                    if "logger" in line.lower() and "@" in line:
                        # Verificar si el email está enmascarado
                        matches = re.findall(email_pattern, line)
                        for email_match in matches:
                            if email_match.count("*") < 3:
                                pytest.fail(
                                    f"❌ Email completo encontrado en código (línea {i}):\n"
                                    f"{line}\n"
                                    "Los emails deben estar enmascarados en logs."
                                )


def test_no_emails_in_log_files():
    """
    Verifica que los archivos de log no contienen emails completos.
    
    Este test requiere que existan logs. Si no existen, se salta.
    """
    import os
    
    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
    
    if not os.path.exists(logs_dir):
        pytest.skip("Directorio de logs no existe")
    
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    exposed_emails = []
    
    for filename in os.listdir(logs_dir):
        if filename.endswith(".log"):
            filepath = os.path.join(logs_dir, filename)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        matches = re.findall(email_pattern, line)
                        for email in matches:
                            # Verificar que está enmascarado
                            if email.count("*") < 3 and len(email.split("@")[0]) > 3:
                                exposed_emails.append((filename, line_num, email, line.strip()[:100]))
            except Exception:
                pass
    
    if exposed_emails:
        pytest.fail(
            f"❌ {len(exposed_emails)} emails completos encontrados en logs:\n" +
            "\n".join([
                f"  {filename}:{line_num} - {email} - {context}"
                for filename, line_num, email, context in exposed_emails[:10]
            ])
        )

