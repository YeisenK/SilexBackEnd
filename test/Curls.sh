# Solicita un OTP
curl -s -X POST http://localhost:3001/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"phone": "+14155552671"}' | jq .

# Verifica el OTP (devuelve JWT)
curl -s -X POST http://localhost:3001/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"phone": "+14155552671", "code": "XXXXXX"}' | jq .

# Ruta protegida (devuelve userId y sessionId)
curl -s http://localhost:3001/me \
  -H "Authorization: Bearer TU_JWT" | jq .

# Sube key bundle
curl -s -X POST http://localhost:3001/keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TU_JWT" \
  -d '{
    "identityKey": "base64encodedIdentityKey==",
    "signedPrekey": "base64encodedSignedPrekey==",
    "signedPrekeySignature": "base64encodedSignature==",
    "signedPrekeyId": 1,
    "oneTimePrekeys": [
      {"id": 1, "key": "base64encodedOTPK1=="},
      {"id": 2, "key": "base64encodedOTPK2=="},
      {"id": 3, "key": "base64encodedOTPK3=="}
    ]
  }' | jq .

# Descarga key bundle de otro usuario y consume una OTPK
curl -s http://localhost:3001/keys/USER_ID \
  -H "Authorization: Bearer TU_JWT" | jq .