# Price Manipulation — client total trusted as authoritative

**Finding ID:** `AP-C80BBA96`  
**Severity:** High  
**Impact class:** Financial Loss / Price Manipulation  
**Effect-class:** `PRICE`  
**Endpoint:** `POST /api/cart/price`  
**Classification source:** contract

## Summary
The action violates the conservation law **PRICE: total == Σ(line items)**, which is true by the definition of the `PRICE` effect-class. The violation was **confirmed by proven Δstate**, not a status-code diff.

## Causal path (proof)
1. Principal 'B' issued POST /api/cart/price and received 200.
2. EIL law violated → PRICE: total == Σ(line items): client total=5.0 ≠ Σ(line items)=90.0 — client-supplied amount is advisory only and must not be authoritative
3. Confirmed by Δstate via server-side total reconciliation: BEFORE [line-item sum = 90.0] → AFTER [server accepted client total = 5.0] (read back as 'B').

## Proof of Δstate
```
method : server-side total reconciliation
before : line-item sum = 90.0
after  : server accepted client total = 5.0
read as: B
detail : client-supplied amount was treated as authoritative
```

## Reproduction (PoC)
1. As 'B', send: POST /api/cart/price with body {"total": 5.0, "items": [{"sku": "y", "price": 90.0, "qty": 1}]}
2. Observe the privileged effect succeed (200).
3. As the legitimate owner 'B', read the state back to confirm the change/leak persisted.

```bash
curl -X POST 'https://demo.local/api/cart/price' -H 'Authorization: Bearer $TOKEN_B' -H 'Content-Type: application/json' -d '{"total": 5.0, "items": [{"sku": "y", "price": 90.0, "qty": 1}]}'
curl -X GET 'https://demo.local/api/cart/price' -H 'Authorization: Bearer $TOKEN_B'
```

> Replace $TOKEN_<pid> with each principal's session credential. Run only within authorised program scope.

## Impact
Financial Loss / Price Manipulation.
