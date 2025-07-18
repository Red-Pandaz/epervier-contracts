# Advanced Testing Plan

## Overview

This plan defines 7 comprehensive advanced test scenarios that cover all edge cases and complex flows for the PQRegistry contract. These tests exercise all 11 functions (3 main actions × 2 steps + 5 revoke functions) in realistic combinations.

## The 7 Advanced Test Scenarios

### **Test 1: ETH Registration → PQ Removes → ETH Retries → PQ Confirms**
**Flow:** AliceETH creates registration intent → AlicePQ removes it → AliceETH creates new intent → AlicePQ confirms
**Tests:** ETH can retry after PQ removal, proper nonce progression (0→1→2→3)
**Functions Tested:** submitRegistrationIntent, removeRegistrationIntentByPQ, submitRegistrationIntent, confirmRegistration

### **Test 2: PQ Registration → ETH Removes → PQ Retries → ETH Confirms**
**Flow:** BobPQ creates registration intent → BobETH removes it → BobPQ creates new intent → BobETH confirms
**Tests:** PQ can retry after ETH removal, proper nonce progression (0→1→2→3)
**Functions Tested:** submitRegistrationIntent, removeRegistrationIntentByETH, submitRegistrationIntent, confirmRegistration

### **Test 3: Multiple Actors Concurrent Registrations**
**Flow:** Alice, Bob, Charlie all register their unique ETH/PQ pairs simultaneously → verify all succeed independently
**Tests:** Concurrent registration handling, proper state management with multiple actors, confirmation order independence
**Functions Tested:** submitRegistrationIntent (multiple actors), confirmRegistration (different order than intent submission)

### **Test 4: Change ETH → PQ Cancels → Change to Different ETH → Confirms**
**Flow:** Alice registers with AliceETH → AlicePQ tries to change AliceETH to BobETH → AlicePQ cancels → AlicePQ changes to CharlieETH → AlicePQ confirms
**Tests:** PQ can cancel and retry with different ETH address, proper nonce progression
**Functions Tested:** submitChangeETHAddressIntent, removeChangeETHAddressIntentByPQ, submitChangeETHAddressIntent, confirmChangeETHAddress

### **Test 5: Change ETH → ETH Cancels → Change to Different ETH → Confirms**
**Flow:** Alice registers with AliceETH → AlicePQ tries to change AliceETH to BobETH → BobETH cancels → AlicePQ changes to CharlieETH → AlicePQ confirms
**Tests:** ETH can cancel and PQ can retry with different ETH address, proper nonce progression
**Functions Tested:** submitChangeETHAddressIntent, removeChangeETHAddressIntentByETH, submitChangeETHAddressIntent, confirmChangeETHAddress

### **Test 6: Multiple Registration Attempts**
**Flow:** AlicePQ send register intent for AliceETH → AliceETH cancels → AlicePQ send register intent for BobETH → AlicePQ cancels  →  AlicePQ send register intent for CharlieETH → confirms
**Tests:** Multiple register attempts, proper state transitions, nonce progression
**Functions Tested:** submitRegistrationIntent removeRegistrationIntentByETH, removeRegistrationIntentByPQ, ConfirmRegistrationIntent

### **Test 7: Multiple Change Attempts**
**Flow:** Alice registers with AliceETH → AlicePQ changes AliceETH to BobETH → BobETH cancels → AlicePQ changes to CharlieETH → AlicePQ cancels → AlicePQ changes to DanielleETH → confirms
**Tests:** Multiple change attempts, proper state transitions, nonce progression
**Functions Tested:** submitChangeETHAddressIntent, removeChangeETHAddressIntentByPQ, removeChangeETHAddressIntentBy, confirmChangeETHAddress

### **Test 8: Unregister → Revoke → Unregister Again → Confirm**
**Flow:** Alice registers with AliceETH → AlicePQ initiates unregistration → AlicePQ revokes → AlicePQ initiates again → AliceETH confirms
**Tests:** PQ can revoke and retry unregistration, proper nonce progression
**Functions Tested:** submitUnregistrationIntent, removeUnregistrationIntent, submitUnregistrationIntent, confirmUnregistration

### **Test 9: Full Lifecycle: Registration → Change → Unregistration → Re-registration**
**Flow:** AlicePQ registers with AliceETH → AlicePQ changes to bind with BobETH → AlicePQ and BobETH unregister → AliceETH registers with BobPQ
**Tests:** Complete lifecycle for a single actor (Alice) using different key combinations, all functions work together, proper nonce progression through entire flow
**Functions Tested:** All 11 functions in sequence
**Actor Relationships:** 
- Alice owns both AliceETH and BobPQ keys
- Bob owns BobETH key  
- Flow demonstrates Alice's complete lifecycle: same person using different key combinations

## Vector Requirements

### **Available Vectors (nonce 0):**
- Registration intent vectors (10 actors)
- Registration confirmation vectors (10 actors)
- Registration ETH removal vectors (10 actors)
- Registration PQ removal vectors (10 actors)
- Change ETH address intent vectors (10 actors)
- Change ETH address confirmation vectors (10 actors)
- Change ETH address cancel ETH vectors (10 actors)
- Change ETH address cancel PQ vectors (10 actors)
- Unregistration intent vectors (10 actors)
- Unregistration confirmation vectors (10 actors)
- Unregistration removal vectors (10 actors)

### **Vectors Needed for Each Test:**

#### Test 1: ETH Registration → PQ Removes → ETH Retries → PQ Confirms
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration PQ removal vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ❌ Registration intent vector (alice, ETH nonce 1, PQ nonce 0) - **NEED TO GENERATE**
- ❌ Registration confirmation vector (alice, ETH nonce 1, PQ nonce 1) - **NEED TO GENERATE**

#### Test 2: PQ Registration → ETH Removes → PQ Retries → ETH Confirms
- ✅ Registration intent vector (bob, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration ETH removal vector (bob, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ❌ Registration intent vector (bob, ETH nonce 0, PQ nonce 1) - **NEED TO GENERATE**
- ❌ Registration confirmation vector (bob, ETH nonce 1, PQ nonce 1) - **NEED TO GENERATE**

#### Test 3: Multiple Actors Concurrent Registrations
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration intent vector (bob, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration intent vector (charlie, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration confirmation vectors for all three - **AVAILABLE**

#### Test 4: Change ETH → PQ Cancels → Change to Different ETH → Confirms
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration confirmation vector (alice, ETH nonce 1, PQ nonce 1) - **AVAILABLE**
- ✅ Change ETH intent vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ✅ Change ETH cancel PQ vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ❌ Change ETH intent vector (alice, ETH nonce 2, PQ nonce 3) - **NEED TO GENERATE** (different new ETH address)
- ❌ Change ETH confirmation vector (alice, ETH nonce 3, PQ nonce 4) - **NEED TO GENERATE**

#### Test 5: Change ETH → ETH Cancels → Change to Different ETH → Confirms
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration confirmation vector (alice, ETH nonce 1, PQ nonce 1) - **AVAILABLE**
- ✅ Change ETH intent vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ✅ Change ETH cancel ETH vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ❌ Change ETH intent vector (alice, ETH nonce 2, PQ nonce 3) - **NEED TO GENERATE** (different new ETH address)
- ❌ Change ETH confirmation vector (alice, ETH nonce 3, PQ nonce 4) - **NEED TO GENERATE**

#### Test 6: Multiple Registration Attempts
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration ETH removal vector (alice, ETH nonce 1, PQ nonce 1) - **AVAILABLE**
- ❌ Registration intent vector (bob, ETH nonce 0, PQ nonce 1) - **NEED TO GENERATE**
- ❌ Registration PQ removal vector (bob, ETH nonce 0, PQ nonce 2) - **NEED TO GENERATE**
- ❌ Registration intent vector (charlie, ETH nonce 0, PQ nonce 3) - **NEED TO GENERATE**
- ❌ Registration confirmation vector (charlie, ETH nonce 1, PQ nonce 4) - **NEED TO GENERATE**

#### Test 7: Multiple Change Attempts
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration confirmation vector (alice, ETH nonce 1, PQ nonce 1) - **AVAILABLE**
- ✅ Change ETH intent vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ❌ Change ETH intent vector (alice, ETH nonce 2, PQ nonce 3) - **NEED TO GENERATE** (different new ETH address)
- ❌ Change ETH confirmation vector (alice, ETH nonce 3, PQ nonce 4) - **NEED TO GENERATE**

#### Test 8: Unregister → Revoke → Unregister Again → Confirm
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration confirmation vector (alice, ETH nonce 1, PQ nonce 1) - **AVAILABLE**
- ✅ Unregistration intent vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ✅ Unregistration removal vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ❌ Unregistration intent vector (alice, ETH nonce 1, PQ nonce 3) - **NEED TO GENERATE**
- ❌ Unregistration confirmation vector (alice, ETH nonce 2, PQ nonce 4) - **NEED TO GENERATE**

#### Test 9: Full Lifecycle: Registration → Change → Unregistration → Re-registration
- ✅ Registration intent vector (alice, ETH nonce 0, PQ nonce 0) - **AVAILABLE**
- ✅ Registration confirmation vector (alice, ETH nonce 1, PQ nonce 1) - **AVAILABLE**
- ✅ Change ETH intent vector (alice, ETH nonce 1, PQ nonce 2) - **AVAILABLE**
- ✅ Change ETH confirmation vector (alice, ETH nonce 2, PQ nonce 3) - **AVAILABLE**
- ✅ Unregistration intent vector (alice, ETH nonce 2, PQ nonce 4) - **AVAILABLE**
- ✅ Unregistration confirmation vector (alice, ETH nonce 3, PQ nonce 5) - **AVAILABLE**
- ❌ Registration intent vector (alice, ETH nonce 4, PQ nonce 6) - **NEED TO GENERATE** (new PQ key)
- ❌ Registration confirmation vector (alice, ETH nonce 5, PQ nonce 7) - **NEED TO GENERATE**

## Implementation Strategy

### Phase 1: Use Available Vectors
- Implement Tests 3 using only nonce 0 vectors
- Validate basic flows work with existing vectors

### Phase 2: Generate Higher Nonce Vectors
- Create generators for nonce 1, 2, 3+ vectors
- Focus on the specific vectors needed for each test
- Ensure proper nonce progression

### Phase 3: Implement All 7 Tests
- Build each test using appropriate vectors
- Validate state transitions and nonce progression
- Test conflict prevention and edge cases

## Coverage Summary

**All 11 Functions Covered:**
- ✅ submitRegistrationIntent
- ✅ confirmRegistration  
- ✅ submitChangeETHAddressIntent
- ✅ confirmChangeETHAddress
- ✅ submitUnregistrationIntent
- ✅ confirmUnregistration
- ✅ removeRegistrationIntentByETH
- ✅ removeRegistrationIntentByPQ
- ✅ removeChangeETHAddressIntentByETH
- ✅ removeChangeETHAddressIntentByPQ
- ✅ removeUnregistrationIntent

**All 5 Intent Revokes Covered:**
- ✅ Registration ETH removal (Test 2)
- ✅ Registration PQ removal (Test 1)
- ✅ Change ETH ETH cancellation (Test 4b)
- ✅ Change ETH PQ cancellation (Test 4a)
- ✅ Unregistration PQ revocation (Test 6)

This plan provides comprehensive coverage of all contract functionality through 7 well-designed integration tests. 