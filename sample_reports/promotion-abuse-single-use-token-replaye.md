# Promotion Abuse — single-use token replayed

**Finding ID:** `AP-2175D060`  
**Severity:** Medium  
**Impact class:** Promotion Abuse / Single-Use Replay  
**Effect-class:** `COUPON`  
**Endpoint:** `POST /api/coupon/redeem`  
**Classification source:** contract

## Summary
The action violates the conservation law **COUPON: redemptions(token) ≤ declared_limit**, which is true by the definition of the `COUPON` effect-class. The violation was **confirmed by proven Δstate**, not a status-code diff.

## Causal path (proof)
1. Principal 'B' issued POST /api/coupon/redeem and received 200.
2. EIL law violated → COUPON: redemptions(token) ≤ declared_limit: coupon/single-use token 'SAVE20' redeemed 2 times, exceeding declared limit 1 — single-use replay
3. Confirmed by Δstate via measured redemption count across exchanges: BEFORE [declared single-use limit = 1] → AFTER [token redeemed 2 times with effect each time] (read back as 'B').

## Proof of Δstate
```
method : measured redemption count across exchanges
before : declared single-use limit = 1
after  : token redeemed 2 times with effect each time
read as: B
detail : single-use token replayed with additional effect
```

## Reproduction (PoC)
1. As 'B', send: POST /api/coupon/redeem with body {"coupon": "SAVE20", "limit": 1}
2. Observe the privileged effect succeed (200).
3. As the legitimate owner 'B', read the state back to confirm the change/leak persisted.

```bash
curl -X POST 'https://demo.local/api/coupon/redeem' -H 'Authorization: Bearer $TOKEN_B' -H 'Content-Type: application/json' -d '{"coupon": "SAVE20", "limit": 1}'
curl -X GET 'https://demo.local/api/coupon/redeem' -H 'Authorization: Bearer $TOKEN_B'
```

> Replace $TOKEN_<pid> with each principal's session credential. Run only within authorised program scope.

## Impact
Promotion Abuse / Single-Use Replay.
