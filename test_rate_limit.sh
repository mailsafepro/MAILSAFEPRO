#!/bin/bash

# ============================================
# Test Script para Rate Limiting
# ============================================

API_BASE="http://localhost:8000"
API_KEY="sKKvMFH16imDtrCz_ocaBE4eeSM7dBUEn3kADR3ltQA"

echo "==================================="
echo "Test 1: Validación básica"
echo "==================================="

curl -X POST "$API_BASE/validate/email" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"email":"test@gmail.com"}' \
  -w "\nHTTP: %{http_code}\n\n"

echo "==================================="
echo "Test 2: Detección de IP con X-Forwarded-For"
echo "==================================="

curl -X POST "$API_BASE/validate/email" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -d '{"email":"test@gmail.com"}' \
  -v 2>&1 | grep -E "(X-Client-IP|X-RateLimit)"

echo ""
echo "==================================="
echo "Test 3: Detección de IP con X-Real-IP"
echo "==================================="

curl -X POST "$API_BASE/validate/email" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Real-IP: 5.6.7.8" \
  -d '{"email":"test@gmail.com"}' \
  -v 2>&1 | grep -E "(X-Client-IP|X-RateLimit)"

echo ""
echo "==================================="
echo "Test 4: Rate Limit (primeros 30 requests)"
echo "==================================="

success_count=0
rate_limited_count=0
error_count=0

for i in {1..30}; do
  response=$(curl -X POST "$API_BASE/validate/email" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{\"email\":\"test${i}@gmail.com\"}" \
    -w "%{http_code}" \
    --silent --output /dev/null)
  
  if [ "$response" = "200" ] || [ "$response" = "201" ]; then
    success_count=$((success_count + 1))
    echo "✅ Request $i: OK ($response)"
  elif [ "$response" = "429" ]; then
    rate_limited_count=$((rate_limited_count + 1))
    echo "⚠️  Request $i: Rate Limited ($response)"
  else
    error_count=$((error_count + 1))
    echo "❌ Request $i: Error ($response)"
  fi
  
  sleep 0.05  # 50ms entre requests
done

echo ""
echo "==================================="
echo "Resumen:"
echo "==================================="
echo "Exitosos:     $success_count"
echo "Rate Limited: $rate_limited_count"
echo "Errores:      $error_count"
echo "Total:        30"
echo "==================================="
