# Guardar como test_final.sh
#!/bin/bash

API_BASE="http://localhost:8000"
API_KEY="sKKvMFH16imDtrCz_ocaBE4eeSM7dBUEn3kADR3ltQA"

echo "🧪 Test Final - IP Detection & Rate Limiting"
echo "=============================================="

# Test 1: Sin proxy header
echo "1️⃣  Test sin proxy header..."
curl -X POST "$API_BASE/validate/email" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"email":"test@gmail.com"}' \
  -v 2>&1 | grep -E "(X-Client-IP|HTTP/)" | head -2

sleep 1

# Test 2: Con X-Forwarded-For
echo ""
echo "2️⃣  Test con X-Forwarded-For..."
curl -X POST "$API_BASE/validate/email" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -d '{"email":"test@gmail.com"}' \
  -v 2>&1 | grep -E "(X-Client-IP|HTTP/)" | head -2

sleep 1

# Test 3: Con X-Real-IP
echo ""
echo "3️⃣  Test con X-Real-IP..."
curl -X POST "$API_BASE/validate/email" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Real-IP: 5.6.7.8" \
  -d '{"email":"test@gmail.com"}' \
  -v 2>&1 | grep -E "(X-Client-IP|HTTP/)" | head -2

echo ""
echo "✅ Tests completados. Verificar logs con:"
echo "   docker logs toni-api-1 --tail 30 | grep 'Client IP'"
