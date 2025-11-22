## Seguridad

### Autenticación
- Header requerido: `X-API-Key`
- Ejemplo: `curl -H "X-API-Key: tu_clave" https://api.dominio.com/validate-email`

### Límites de Uso
- 30 peticiones por minuto por IP
- Headers de respuesta:
  - `X-RateLimit-Limit`: Límite máximo
  - `X-RateLimit-Remaining`: Peticiones restantes

### Health Check
Endpoint público para monitoreo:
```bash
GET /healthz
``````

docker compose build
docker compose up -d
(docker compose ps)
(docker compose logs -f)


docker compose down
docker compose build --no-cache
docker compose up -d

docker-compose down
docker-compose up -d --build

docker exec toni-api-1 python create_api_key.py
docker exec toni-api-1 python generate_token_free.py
docker exec toni-api-1 python generate_token_premium.py
curl -H "X-API-Key: afab00426f3745678afcc90412cb431a" http://localhost:8000/metrics
curl http://localhost:8000/health 

./test_api_keys.sh
86-CosgVwccSYbxeuc7r3l2SsjTlQyw_caCcPUTjRO4


http://localhost:8000/docs
http://localhost:8000/redoc

🧩 Reglas de autenticación según el plan:
Plan free:
	•	Solo requiere la API Key (X-API-Key).
	•	NO necesita token JWT.
	•	SMTP no está permitido → debe devolver smtp_checked: false y mensaje explicativo.
Plan premium:
	•	Requiere API Key + JWT válido (Bearer token).
	•	SMTP sí está permitido.

Tabla comparativa: Planes Free vs Premium

Diferencias por plan (ejemplo de 4 niveles):

API Key
Es una cadena secreta (p. ej. YwEQn-...) que el cliente guarda y envía en cada petición (header X-API-Key u otro).
Serviría como “contraseña” para identificar una aplicación/cliente.
Suele almacenarse en el servidor en forma hasheada (p. ej. sha256) y asociarse a metadatos (plan, estado).
Ventajas: simple de usar. Desventajas: difícil de revocar por petición (hay que invalidar la key), y si se compromete hay que rotarla.
JWT (JSON Web Token)
Es un token con firma (HMAC/RSA) que contiene claims (datos) en su payload, por ejemplo sub, exp, scopes, jti, plan.
Se usa para autenticar al usuario sin consultar DB cada petición (la firma garantiza que no fue manipulada).
Ventajas: portable, tiene expiración, se puede verificar offline (con la clave).
Desventajas: si quieres revocarlo necesitas una lista negra o mapa en Redis; si pones secretos en el token (por ejemplo la API key cruda) eso es inseguro.
En tu sistema: usas ambos. Las API Keys son la "identidad primaria" (guardada en Redis hashed). /auth/login emite JWTs basados en una API Key. get_current_client valida JWTs y los convierte a TokenData.


1️⃣ Qué son las API Keys en tu sistema
	•	Una API Key es como una contraseña larga que identifica a un usuario o cliente que quiere usar tu API.
	•	Tu API no funciona sin una clave válida, porque sirve para controlar quién puede hacer qué y para llevar el conteo de uso (cuotas, límites de plan, etc.).
	•	En tu sistema, cada API Key se almacena en Redis pero solo su hash (SHA-256), por seguridad.
	•	Ejemplo: tu clave “920e86ef0f9…cf75a” se convierte en un hash y Redis guarda key:<hash> → active.
	•	Además, cada API Key puede tener sub-keys que se crean para diferentes propósitos o planes del usuario.

⸻

2️⃣ Cómo funciona la validación

Cuando alguien hace un request a tu API con: X-API-Key: 920e86ef0f9883b3ab1d663699dd8284665d5246f264f7d1ae275cc3774cf75a , Tu sistema:
	1.	Hace hash de esa clave (SHA-256).
	2.	Busca en Redis key:<hash>.
	3.	Si existe, la clave es válida.
	4.	Si no existe, devuelve Invalid API Key.
	5.	Si la clave está marcada como deprecated o revoked, devuelve un error correspondiente.

💡 Esto significa que aunque tú veas la API Key en tu frontend, lo que realmente importa para el backend es su hash y que exista en Redis.

⸻

3️⃣ Para qué sirven las API Keys en tu sistema
	1.	Autenticación: Saber quién está haciendo la petición.
	2.	Control de planes: Cada clave puede tener un plan (FREE, PREMIUM, ENTERPRISE).
	3.	Limitación de uso: Guardas en Redis cuántas peticiones ha hecho la clave hoy.
	4.	Revocación: Puedes desactivar una clave sin afectar a otras.

6️⃣ Flujo de uso típico
	1.	Usuario recibe su API Key raíz o se registra y obtiene un JWT.
	2.	Con esa clave puede:
	•	Llamar a /api-keys para crear sub-keys (nuevas claves que puede usar en apps, integraciones, etc.).
	•	Consultar su uso con /usage.
	3.	Cada petición que haga un cliente debe autenticarse con su API Key o token JWT.
	4.	Redis guarda:
	•	Hash de la clave (key:<hash> → active)
	•	Meta info (plan, creación, revocada)
	•	Sets de sub-keys por cliente (api_keys:<hash_cliente> → hash de sub-keys)

⸻

💡 En pocas palabras:
	•	API Key = contraseña para usar tu API.
	•	Hash en Redis = la clave real que valida tu backend, por seguridad.
	•	JWT = token temporal que representa la API Key o el usuario, útil para no exponer la clave raíz todo el tiempo.
	•	Sub-keys = claves secundarias que tu API permite crear para organizar planes y límites.
	•	Redis = donde se guarda todo el control de claves y límites de uso.

Calcular el hash de una API KEY: python3 -c "import hashlib; print(hashlib.sha256('X7geXXVb3_Gc9Kor09Dpv3WqGO3h23FP3VlH80d3wP4'.encode()).hexdigest())"

# listar keys de api keys
docker exec -it toni-redis-1 redis-cli KEYS "key:*"

# ver el JSON guardado bajo key:<hash>
docker exec -it toni-redis-1 redis-cli GET "key:<hash>"

# ver cache de subscription
docker exec -it toni-redis-1 redis-cli GET "user:<hash>:subscription"

# ver datos HGET en user:<hash>
docker exec -it toni-redis-1 redis-cli HGETALL "user:<hash>"

# borrar cache
docker exec -it toni-redis-1 redis-cli DEL "user:<hash>:subscription"

#ver los errores del webhook
docker exec -it toni-redis-1 redis-cli LRANGE stripe:webhook:errors 0 -1

#cambiar de plan
docker exec -it toni-redis-1 redis-cli HSET "user:964a664f-728a-4a8b-88b8-1c997e7b5dc0" plan FREE

#REGISTRAR USUARIO
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@gmail.com",
    "password": "password123",
    "plan": "FREE"
  }'

# LOGIN -> devuelve access_token y user
curl -s -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"pabloagudo01@yahoo.com","password":"qwerty"}' | jq .


python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

grep -Rl "typing.Annotated" ~/Desktop/toni

docker compose restart
uvicorn app.main:app --port 8000
python -m app.jobs.jobs_worker


Descripción General - MailSafePro Email Validation API
Validación y Análisis Profesional de Emails

Servicio profesional de validación y análisis de direcciones de email con enfoque en calidad de datos, seguridad y reputación, que incluye verificación sintáctica conforme a estándares de correo y comprobaciones de entrega.​

Integra señales de riesgo multi-factor y consultas de breaches mediante Have I Been Pwned para enriquecer la decisión, posicionándose como alternativa avanzada frente a proveedores del mercado.

Infraestructura en Producción

Desplegado en Render (Frankfurt, EU) con Redis colocado en la misma región para minimizar latencia, garantizando tiempos de respuesta óptimos y cumplimiento GDPR.​

Monitoreo 24/7 con Better Uptime que supervisa tres endpoints críticos cada 3 minutos: healthcheck general, autenticación y validación, con status page público en mailsafepro.betteruptime.com para transparencia total ante usuarios.​

Documentación interactiva en producción con Swagger UI y ReDoc accesibles públicamente, utilizando CDN estable y Content Security Policy optimizada para garantizar carga sin errores y máxima compatibilidad.​

Autenticación y Control de Acceso

Soporta autenticación de múltiples capas con API Keys y JWT Bearer, con scopes granulares y metadatos de plan embebidos en los tokens para control fino de acceso.

Incluye revocación segura y listas negras sincronizadas, además de validaciones estrictas del token conforme a las recomendaciones del estándar JWT con verificación de iss, aud, nbf y exp.

Gestión Multi-Key

Permite generar y nombrar múltiples API Keys por usuario para aislar integraciones y rotarlas con período de gracia sin interrupciones de servicio.

Las claves heredan de forma automática permisos y límites del plan vigente, facilitando la administración por entorno y caso de uso.

Integración Stripe

Integra Stripe para suscripciones y cambios de plan en tiempo real, utilizando sesiones de Checkout y webhooks firmados para garantizar autenticidad de eventos.

Expone endpoints para consultar el plan actual y el próximo cobro, actualizando de inmediato el acceso y los scopes tras los eventos de Stripe.

Rate Limiting y Cuotas

Implementa rate limiting por usuario e IP con umbrales para acciones sensibles (checkout, login, creación de claves) y control de consumo por plan.

Mantiene cuotas diarias/mensuales diferenciadas por tier (FREE, PREMIUM, ENTERPRISE) y detiene el uso cuando se alcanzan los límites definidos.

Validación Sintáctica y de Dominio

Valida sintaxis de email conforme a RFC 5322 y semántica básica de dirección, constituyendo la primera barrera de calidad.

Analiza DNS y seguridad de dominio con señales de SPF, DKIM y DMARC para evaluar autenticación de origen y alineación de políticas.

Detecta dominios desechables y direcciones de rol, emite sugerencias de typos y calcula un puntaje de riesgo multi-factor para apoyar decisiones de aceptación o revisión.

Verificación SMTP y Breaches

Verifica existencia de buzón vía SMTP a nivel de servidor para aumentar la certeza de entregabilidad, respetando el comportamiento y respuestas del protocolo.

Integra Have I Been Pwned para comprobar presencia en breaches conocidos y enriquecer el perfil de riesgo del email consultado.

Procesamiento Batch Asíncrono

Permite crear jobs asíncronos que procesan cientos o miles de emails sin bloquear la solicitud, con cola persistente y procesamiento ordenado.

Ofrece ingesta por lista directa o token de carga de archivo, modos de sandbox o validación con DNS/SMTP, y resultados paginados para consultas eficientes.

Admite concurrencia interna configurable y especificación de callback con firma y timestamp para notificaciones de finalización, con idempotencia en la creación de jobs.

Webhooks y Callbacks Seguros

Emite notificaciones firmadas HMAC mediante Stripe-Signature compatible para garantizar integridad y autenticidad en callbacks.

Soporta claves de idempotencia en solicitudes sensibles para evitar duplicados en reintentos de clientes o ante fallos transitorios.

Redis y Caché Inteligente

Usa Redis para caché y coordinación, con scripts Lua para operaciones atómicas que preservan la consistencia bajo alta concurrencia.

Cachea resultados de validaciones para reducir latencia y llamadas, con expiración y políticas que equilibran frescura y rendimiento.

Observabilidad y Monitoreo

Incluye logging estructurado con correlation IDs y métricas de ejecución para seguimiento extremo a extremo y análisis de rendimiento.​

Expone indicadores de profundidad de cola, estados de jobs y tiempos de validación por plan para monitoreo operativo y capacidad de reacción.

Healthchecks especializados con soporte HEAD y GET para compatibilidad con monitores externos, excluyendo redirecciones HTTPS en endpoints de salud para garantizar respuestas 200 OK directas.​

Seguridad en Producción

Content Security Policy (CSP) diferenciado por ruta: restrictivo para endpoints de API, permisivo para documentación permitiendo CDN de Swagger/ReDoc, bloqueando XSS y scripts maliciosos.​

Middleware de seguridad multicapa con validación de Content-Type, detección de patrones XSS, headers de seguridad (HSTS, X-Frame-Options, Referrer-Policy) y redirect HTTPS selectivo excluyendo healthchecks.​

Modos de Uso

Ofrece validación individual en tiempo real con tiempos de respuesta en segundos y detalle de proveedor, reputación y señales de seguridad.

Permite cargas en lote (CSV/TXT/ZIP) con resultados consolidados, totales válidos/inválidos y tiempos por dirección para facilitar decisiones masivas.

Configuración y Ajustes

Centraliza configuración por ambientes y valida secretos críticos, incluyendo timeouts de DNS/MX y credenciales de SMTP.

Brinda ajustes dinámicos por plan para tamaño de lotes y concurrencia, alineando rendimiento con garantías de cuota y fair use.

Contratos de API

Define contratos claros para validación individual, avanzada y batch, con respuestas JSON que incluyen IDs, timestamps y metadatos técnicos.

Incluye estructuras de autenticación con JWT y manejo de claves que reflejan scopes y plan del cliente.

Manejo de Errores

Estandariza respuestas de error con tipo, título, estado HTTP, detalle, trace_id y timestamp para diagnóstico consistente.​

Registra intentos fallidos relevantes para seguridad y control de abuso, integrándolos a la capa de observabilidad para mitigaciones.

Flujo Batch

POST /v1/jobs para crear el job, seguido de GET /v1/jobs/{job_id} para estado y GET /v1/jobs/{job_id}/results para resultados paginados y consumo eficiente.

La autenticación usa Bearer con scopes granulares para creación, lectura y obtención de resultados, segregando permisos por rol y plan.

Ventaja Competitiva

Tu API combina verificación sintáctica y de transporte con señales de autenticación de dominio y de brechas para una calificación de riesgo robusta.

La arquitectura asíncrona con Redis y webhooks firmados, más planes con cuotas y límites por acción, habilita escalabilidad con gobernanza y trazabilidad de nivel empresarial.

Infraestructura de producción empresarial con despliegue en región EU (Frankfurt), monitoreo proactivo 24/7 con Better Uptime, status page público con 99.9% uptime, documentación interactiva accesible y healthchecks optimizados para máxima disponibilidad.​

Plataforma Integral

Incluye además un exhaustivo mecanismo de monitoreo y observabilidad mediante logging estructurado, métricas y trazabilidad, así como una arquitectura escalable basada en procesamiento asíncrono con Redis y manejo eficiente de jobs para soportar cargas masivas.​

Status page transparente que permite a usuarios verificar el estado en tiempo real de todos los servicios (API, autenticación, validación) con historial de uptime de 90 días y notificaciones automáticas de incidentes.​

Todo ello hace que el servicio no solo sea una herramienta de validación sino una plataforma integral para la gestión segura y eficiente de emails en entornos profesionales con garantías de disponibilidad y observabilidad de nivel empresarial.

Hemos desarrollado un SDK en JavaScript/TypeScript para MailSafePro que ofrece una integración completa y profesional para la validación de emails, tanto individual como en batch. El SDK incorpora autenticación dual con API Keys y JWT, control avanzado de tasas (rate limiting), reintentos automáticos con backoff exponencial, y manejo detallado de errores con clases tipadas. Además, integra funcionalidades enfocadas en seguridad y rendimiento, como verificación SMTP, detección de dominios desechables, uso de Redis para caché y coordinación, y soporte tanto para entornos Node.js como navegadores modernos con un bundle CDN optimizado. Todo ello respaldado por un robusto sistema de tests con más del 85% de cobertura, documentación completa y despliegue listo para producción.

Se ha desarrollado un SDK en Python para MailSafePro que ofrece una integración profesional y completa para la validación de emails con funcionalidades avanzadas de seguridad. Este SDK soporta autenticación dual con API Key y JWT (con auto-refresco dinámico), validación exhaustiva que abarca formato, DNS, SMTP, y detección de emails desechables, además de controles de seguridad como detección de spam traps, comprobación de brechas, y detección de emails de rol. Permite la validación individual y por batch de miles de correos, con soporte para carga de archivos CSV y TXT. Incorpora reintentos automáticos con backoff exponencial para gestionar límites de tasa y errores temporales, manejo detallado y tipado de errores, y proporciona resultados ricos en datos con puntuaciones de riesgo, calidad y acciones sugeridas. Cuenta con completas anotaciones de tipos para mejor autocompletado y robustez en el desarrollo. Todo respaldado por documentación integral, ejemplos prácticos y un sistema de tests con alta cobertura, listo para integración en entornos de producción seguros y confiables.

MailSafePro Zapier Integration Una integración robusta y segura diseñada para equipos de alto rendimiento. Construida sobre nuestra API v1, ofrece capacidades completas de validación dentro del ecosistema no-code:

Triggers y Acciones Disponibles:

Validate Email Premium: Acción de alta precisión que devuelve score de riesgo, detección de trampas de spam (honeypots), validación SMTP profunda y análisis de DNS/MX.
Batch Validation: Procesa miles de correos asíncronamente con manejo automático de reintentos y estados.
Get Usage: Consulta programática de cuotas, proyecciones de consumo y alertas de límites.
Características Técnicas:

Manejo inteligente de Rate Limiting con Backoff Exponencial.
Deduplicación de peticiones para optimizar tu cuota.
Tiempos de respuesta optimizados (<500ms) para flujos críticos.

🔗 Enlaces de Producción
API en producción: https://email-validation-api-jlra.onrender.com

Documentación Swagger: https://email-validation-api-jlra.onrender.com/docs

Documentación ReDoc: https://email-validation-api-jlra.onrender.com/redoc

Status page público: https://mailsafepro.betteruptime.com

Región: Frankfurt (EU) - GDPR Compliant

| Capacidad                                    | Tu API | ZeroBounce | NeverBounce | Kickbox | Verifalia |
| -------------------------------------------- | ------ | ---------- | ----------- | ------- | --------- |
| Sintaxis RFC 5322                            | ✅      | ✅          | ✅           | ✅       | ✅         |
| Verificación SMTP                            | ✅      | ✅          | ✅           | ✅       | ✅         |
| Desechables                                  | ✅      | ✅          | ✅           | ✅       | ✅         |
| Emails de rol                                | ✅      | ✅          | ✅           | ✅       | ✅         |
| Spam traps/abuse/toxic                       | ✅      | ✅          | ❌           | ❌       | ✅         |
| Breaches (HIBP)                              | ✅      | ❌          | ❌           | ❌       | ❌         |
| Tiempo real (API)                            | ✅      | ✅          | ✅           | ✅       | ✅         |
| Lotes/list cleaning                          | ✅      | ✅          | ✅           | ✅       | ✅         |
| Integraciones/plugins                        | ✅      | ✅          | ✅           | ✅       | ✅         |
| Estados estándar (Deliverable/Risky/Unknown) | ✅      | ✅          | ✅           | ✅       | ✅         |
| Sugerencias de typos                         | ✅      | ✅          | ❌           | ❌       | ❌         |
| Señales de actividad/engagement              | ❌      | ✅          | ❌           | ✅       | ❌         |
| Certificaciones (GDPR/SOC/ISO)               | ❌      | ✅          | ✅           | ✅       | ❌         |


usuario	owner_validador
contraseña &i1rf0JPh5MW()#b3hF49sY0
FbZCT3fQuFq9Eq3053_kvn_faTSLbySRo4QKBVgN1hY

PyPI recovery codes
8bdd1c2d29ff0135
047109e9b2846c06
e744d4764be5a246
6e258d482f7933f2
15eecf9474b0a67f
15d3cff9c6863b28
03763d438a202c9f
14c1f7078d8c08ec

pypi-AgEIcHlwaS5vcmcCJDVmOGEzZDY0LTQ0OTktNDJhNy1hMDkzLTU3ODlhYTYwZjc4NAACKlszLCJmYTE0OTNhMi02MDI5LTQwMzMtYjJmNC02OGNkNmRjMWI5NGQiXQAABiBe9yYhhRGR04ktPGcntzzt2vh598auSKBupsaSLFCKSg

gh auth logout --hostname github.com
✓ Logged out of github.com account mailsafepro
(base) pablo@MacBook-Air-de-Pablo MailSafePro-sdk % gh auth login --hostname github.com --web