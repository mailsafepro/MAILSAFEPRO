import os
import aiosmtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from jinja2 import Template
from app.config import settings
from app.logger import logger
from typing import Optional
from app.pii_mask import mask_email

class EmailService:
    def __init__(self):
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_username = settings.smtp_username
        self.smtp_password = settings.smtp_password
        self.from_email = settings.from_email
        self.from_name = settings.from_name or "Email Validation API"
        
        # Verificar configuración
        if not all([self.smtp_host, self.smtp_port, self.smtp_username, self.smtp_password]):
            logger.warning("SMTP configuration incomplete. Email notifications will be logged instead of sent.")

    async def send_email(self, to_email: str, subject: str, html_content: str, text_content: Optional[str] = None) -> bool:
        """
        Envía un email usando SMTP con autenticación
        """
        # Si la configuración de SMTP está incompleta, solo loguear
        if not all([self.smtp_host, self.smtp_port, self.smtp_username, self.smtp_password]):
            logger.info(f"Email notification (simulated): To: {mask_email(to_email)}, Subject: {subject}")
            logger.debug(f"Email content: {text_content or html_content}")
            return True
            
        try:
            # Crear mensaje
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = formataddr((self.from_name, self.from_email))
            message["To"] = to_email
            
            # Crear versión texto plano si no se proporciona
            if not text_content:
                # Conversión simple de HTML a texto
                import re
                text_content = re.sub('<[^<]+?>', '', html_content.replace('<br>', '\n').replace('</p>', '\n\n'))
            
            # Añadir partes
            message.attach(MIMEText(text_content, "plain"))
            message.attach(MIMEText(html_content, "html"))
            
            # CONEXIÓN MEJORADA - Solución al error SSL
            smtp = aiosmtplib.SMTP(
                hostname=self.smtp_host,
                port=self.smtp_port,
                use_tls=True,
                validate_certs=True
            )
            
            await smtp.connect()
            await smtp.login(self.smtp_username, self.smtp_password)
            await smtp.send_message(message)
            await smtp.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False

    async def send_plan_change_notification(self, to_email: str, old_plan: str, new_plan: str) -> bool:
        """
        Envía notificación de cambio de plan usando plantilla HTML externa
        """
        try:
            # Cargar plantilla desde archivo
            template_path = os.path.join(os.path.dirname(__file__), "templates", "email_plan_change.html")
            with open(template_path, "r", encoding="utf-8") as file:
                html_template = file.read()
        except Exception as e:
            logger.error(f"Error loading email template: {str(e)}")
            # Fallback a plantilla básica
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
                    .content { padding: 30px; background-color: #fff; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #6c757d; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Email Validation API</h2>
                    </div>
                    <div class="content">
                        <h3>Your plan has been updated</h3>
                        <p>Hello,</p>
                        <p>Your subscription plan has been successfully changed from {{ old_plan }} to {{ new_plan }}.</p>
                        <p>All your API keys have been automatically updated to reflect the new plan limits and features.</p>
                        <p>If you did not request this change, please contact our support team immediately.</p>
                    </div>
                    <div class="footer">
                        <p>© {{ current_year }} Email Validation API. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
        
        # Renderizar plantilla
        from datetime import datetime
        template = Template(html_template)
        html_content = template.render(
            old_plan=old_plan,
            new_plan=new_plan,
            effective_date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            current_year=datetime.now().year
        )
        
        # Versión texto plano
        text_content = f"""
        Email Validation API - Plan Change Notification
        
        Your subscription plan has been changed:
        
        Old Plan: {old_plan}
        New Plan: {new_plan}
        Effective Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}
        
        All your API keys have been automatically updated to reflect the new plan limits and features.
        
        If you did not request this change or have any questions, please contact our support team immediately.
        
        Thank you for using our service!
        
        © {datetime.now().year} Email Validation API. All rights reserved.
        This is an automated message, please do not reply to this email.
        """
        
        # Asunto del email
        subject = f"Your plan has been changed to {new_plan}"
        
        # Enviar email
        return await self.send_email(to_email, subject, html_content, text_content)

# Instancia global del servicio de email
email_service = EmailService()