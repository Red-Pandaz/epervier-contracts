
# PQRegistry Test Checklist

## Core Registration Functions

### 1. submitRegistrationIntent
**Function**: `submitRegistrationIntent(bytes calldata ethMessage, uint8 v, bytes32 r, bytes32 s)`
- [ ] **Valid registration intent with correct signatures**
    - [ ] ETH signature is valid and from the intent address
    - [ ] PQ signature components (salt, cs1, cs2, hint) are valid
    - [ ] PQ nonce is correct
    - [ ] ETH nonce is correct
    - [ ] Recovered ETH address matches the PQ message
    - [ ] Recovered PQ address is not already registered
    - [ ] ETH address is not already registered
    - [ ] No pending intents exist for the addresses
    - [ ] Intent is stored correctly
    - [ ] Event is emitted

- [ ] **Message validation and consistency**
    - [ ] ETH address in PQ message matches recovered ETH address from ETH signature
    - [ ] PQ fingerprint in ETH message matches recovered PQ fingerprint from PQ signature
    - [ ] Message format follows expected schema (intent type, addresses, nonces)
    - [ ] Message length is correct for the operation type
    - [ ] All required fields are present in the message
    - [ ] Message content is not tampered with (e.g., flipped bits in addresses)
    - [ ] Domain separator is correct (keccak256("PQRegistry"))
    - [ ] Message starts with correct domain separator
    - [ ] Expected pattern is found in message (e.g., "Intent to pair Epervier Key")

- [ ] **Invalid ETH signature**
    - [ ] Rejects with invalid v, r, s components
    - [ ] Rejects with signature from wrong address
    - [ ] Rejects with zero address from signature recovery
    - [ ] Rejects with signature malleability issues

- [ ] **Invalid PQ signature**
    - [ ] Rejects with invalid salt length
    - [ ] Rejects with invalid cs1/cs2 arrays
    - [ ] Rejects with invalid hint

- [ ] **Nonce validation**
    - [ ] Rejects with incorrect ETH nonce
    - [ ] Rejects with incorrect PQ nonce
    - [ ] Rejects with future nonces
    - [ ] Rejects with reused nonces

- [ ] **Conflict prevention**
    - [ ] Rejects if ETH address already has registered PQ key
    - [ ] Rejects if PQ key already has registered ETH address
    - [ ] Rejects if PQ fingerprint has pending change intent
    - [ ] Rejects if ETH address has pending unregistration intent
    - [ ] Rejects if recovered ETH address does not match address in PQ message
    - [ ] Rejects if PQ fingerprint has pending registration intent
    - [ ] Rejects if ETH address has pending registration intent

### 2. confirmRegistration
**Function**: `confirmRegistration(bytes calldata pqMessage, bytes calldata salt, uint256[] calldata cs1, uint256[] calldata cs2, uint256 hint)`
- [ ] **Valid confirmation with correct signatures**
    - [ ] PQ signature components are valid
    - [ ] Recovered PQ fingerprint matches stored intent
    - [ ] ETH address in PQ message matches stored intent
    - [ ] ETH nonce is correct
    - [ ] PQ nonce is correct
    - [ ] Registration is completed
    - [ ] Intent is cleared
    - [ ] Event is emitted

- [ ] **Message validation and consistency**
    - [ ] ETH address in PQ message matches the ETH address from stored intent
    - [ ] PQ fingerprint in confirmation message matches stored intent
    - [ ] Message format follows expected confirmation schema
    - [ ] Message references the correct intent (nonce, addresses)
    - [ ] Message content is not tampered with
    - [ ] Confirmation message includes all required fields
    - [ ] Domain separator is correct (keccak256("PQRegistry"))
    - [ ] Message starts with correct domain separator
    - [ ] Expected pattern is found in message (e.g., "Confirm binding ETH Address ")

- [ ] **Invalid PQ signature**
    - [ ] Rejects with invalid salt length
    - [ ] Rejects with invalid cs1/cs2 arrays
    - [ ] Rejects with invalid hint

- [ ] **Intent validation**
    - [ ] Rejects if no pending intent exists
    - [ ] Rejects if recovered PQ fingerprint doesn't match stored intent
    - [ ] Rejects if ETH address in message doesn't match stored intent
    - [ ] Rejects if intent has expired (if applicable)
    - [ ] Rejects if intent is for wrong operation type
ls

- [ ] **Nonce validation**
    - [ ] Rejects with incorrect ETH nonce
    - [ ] Rejects with incorrect PQ nonce
    - [ ] Rejects with future nonces

## Registration Removal Functions

### 3. removeIntent (ETH controlled)
**Function**: `removeIntent(bytes calldata ethMessage, uint8 v, bytes32 r, bytes32 s)`
- [ ] **Valid removal with correct signature**
  - [ ] ETH signature is valid and from the intent address
  - [ ] PQ fingerprint in message matches stored intent
  - [ ] ETH nonce is correct
  - [ ] Intent is cleared
  - [ ] Bidirectional mapping is cleared
  - [ ] Event is emitted

- [ ] **Invalid signature**
  - [ ] Rejects with invalid ETH signature

- [ ] **Intent validation**
  - [ ] Rejects if no pending intent exists
  - [ ] Rejects if PQ fingerprint doesn't match

- [ ] **Nonce validation**
  - [ ] Rejects with incorrect ETH nonce

### 4. removeIntentByPQ (PQ controlled)
**Function**: `removeIntentByPQ(bytes calldata pqMessage, bytes calldata salt, uint256[] calldata cs1, uint256[] calldata cs2, uint256 hint)`
- [ ] **Valid removal with correct PQ signature**
  - [ ] PQ signature is valid
  - [ ] Recovered fingerprint matches stored intent
  - [ ] ETH address in message matches stored intent
  - [ ] PQ nonce is correct
  - [ ] Intent is cleared
  - [ ] Event is emitted

- [ ] **Invalid PQ signature**
  - [ ] Rejects with invalid signature components

- [ ] **Intent validation**
  - [ ] Rejects if no pending intent exists
  - [ ] Rejects if addresses don't match

- [ ] **Nonce validation**
  - [ ] Rejects with incorrect PQ nonce

## Change ETH Address Functions

### 5. submitChangeETHAddressIntent
**Function**: `submitChangeETHAddressIntent(bytes calldata ethMessage, uint8 v, bytes32 r, bytes32 s)`
- [ ] **Valid change intent with correct signatures**
  - [ ] ETH signature is valid and from current ETH address
  - [ ] PQ signature components are valid
  - [ ] Recovered PQ fingerprint matches current registration
  - [ ] Old ETH address matches current registration
  - [ ] New ETH address is different from current
  - [ ] New ETH address is not already registered
  - [ ] ETH nonce is correct
  - [ ] Intent is stored correctly
  - [ ] Event is emitted

- [ ] **Invalid signatures**
  - [ ] Rejects with invalid ETH signature
  - [ ] Rejects with invalid PQ signature

- [ ] **Registration validation**
  - [ ] Rejects if PQ key not registered to current address
  - [ ] Rejects if old ETH address doesn't match current

- [ ] **Address validation**
  - [ ] Rejects if new address same as current
  - [ ] Rejects if new address already has registered PQ key

- [ ] **Conflict prevention**
  - [ ] Rejects if PQ fingerprint has pending registration intent
  - [ ] Rejects if new ETH address has pending registration intent
  - [ ] Rejects if current ETH address has pending unregistration intent
  - [ ] Rejects if new ETH address has pending unregistration intent
  - [ ] Rejects if PQ fingerprint has pending change intent

### 6. confirmChangeETHAddress
**Function**: `confirmChangeETHAddress(bytes calldata ethMessage, uint8 v, bytes32 r, bytes32 s)`
- [ ] **Valid confirmation with correct signatures**
  - [ ] ETH signature is valid and from new ETH address
  - [ ] PQ signature components are valid
  - [ ] Recovered PQ fingerprint matches stored intent
  - [ ] New ETH address matches stored intent
  - [ ] Old ETH address matches current registration
  - [ ] ETH nonce is correct
  - [ ] Change is completed
  - [ ] Intent is cleared
  - [ ] Event is emitted

- [ ] **Invalid signatures**
  - [ ] Rejects with invalid ETH signature
  - [ ] Rejects with invalid PQ signature

- [ ] **Intent validation**
  - [ ] Rejects if no pending change intent exists
  - [ ] Rejects if addresses don't match stored intent

- [ ] **Registration validation**
  - [ ] Rejects if old ETH address not registered to PQ fingerprint

### 7. removeChangeETHAddressIntent (PQ controlled)
**Function**: `removeChangeETHAddressIntent(bytes calldata pqMessage, bytes calldata salt, uint256[] calldata cs1, uint256[] calldata cs2, uint256 hint)`
- [ ] **Valid removal with correct PQ signature**
  - [ ] PQ signature is valid
  - [ ] Recovered fingerprint matches current registration
  - [ ] Current ETH address is correct
  - [ ] PQ nonce is correct
  - [ ] Intent is cleared
  - [ ] Event is emitted

- [ ] **Invalid PQ signature**
  - [ ] Rejects with invalid signature components

- [ ] **Registration validation**
  - [ ] Rejects if PQ key not registered to current address

- [ ] **Intent validation**
  - [ ] Rejects if no pending change intent exists

- [ ] **Nonce validation**
  - [ ] Rejects with incorrect PQ nonce

### 8. removeChangeETHAddressIntentByETH (ETH controlled)
**Function**: `removeChangeETHAddressIntentByETH(bytes calldata ethMessage, uint8 v, bytes32 r, bytes32 s)`
- [ ] **Valid removal with correct ETH signature**
  - [ ] ETH signature is valid and from current ETH address
  - [ ] PQ fingerprint in message matches current registration
  - [ ] ETH address is registered to PQ fingerprint
  - [ ] ETH nonce is correct
  - [ ] Intent is cleared
  - [ ] Event is emitted

- [ ] **Invalid ETH signature**
  - [ ] Rejects with invalid signature components

- [ ] **Registration validation**
  - [ ] Rejects if ETH address not registered to PQ fingerprint
  - [ ] Rejects if PQ fingerprint not registered to ETH address

- [ ] **Intent validation**
  - [ ] Rejects if no pending change intent exists

- [ ] **Nonce validation**
  - [ ] Rejects with incorrect ETH nonce

## Unregistration Functions

### 9. submitUnregistrationIntent
**Function**: `submitUnregistrationIntent(bytes calldata pqMessage, bytes calldata salt, uint256[] calldata cs1, uint256[] calldata cs2, uint256 hint, uint256[2] calldata publicKey)`
- [ ] **Valid unregistration intent with correct signatures**
  - [ ] PQ signature is valid
  - [ ] ETH signature embedded in PQ message is valid
  - [ ] Recovered addresses match
  - [ ] ETH address has registered PQ key
  - [ ] ETH nonce is correct
  - [ ] PQ nonce is 0
  - [ ] Intent is stored correctly
  - [ ] Event is emitted

- [ ] **Invalid signatures**
  - [ ] Rejects with invalid PQ signature
  - [ ] Rejects with invalid ETH signature

- [ ] **Registration validation**
  - [ ] Rejects if ETH address has no registered PQ key

- [ ] **Nonce validation**
  - [ ] Rejects with incorrect ETH nonce
  - [ ] Rejects with non-zero PQ nonce

- [ ] **Conflict prevention**
  - [ ] Rejects if ETH address has pending registration intent
  - [ ] Rejects if PQ fingerprint has pending registration intent
  - [ ] Rejects if PQ fingerprint has pending change intent
  - [ ] Rejects if ETH address has pending unregistration intent

### 10. confirmUnregistration
**Function**: `confirmUnregistration(bytes calldata ethMessage, uint8 v, bytes32 r, bytes32 s)`
- [ ] **Valid confirmation with correct signatures**
  - [ ] ETH signature is valid and from the ETH address
  - [ ] PQ signature components are valid
  - [ ] Recovered PQ fingerprint matches stored intent
  - [ ] ETH address matches stored intent
  - [ ] ETH nonce is correct
  - [ ] PQ nonce is 0
  - [ ] Unregistration is completed
  - [ ] Intent is cleared
  - [ ] Event is emitted

- [ ] **Invalid signatures**
  - [ ] Rejects with invalid ETH signature
  - [ ] Rejects with invalid PQ signature

- [ ] **Intent validation**
  - [ ] Rejects if no pending unregistration intent exists
  - [ ] Rejects if addresses don't match stored intent

- [ ] **Registration validation**
  - [ ] Rejects if ETH address not registered to PQ fingerprint

### 11. removeUnregistrationIntent (PQ controlled)
**Function**: `removeUnregistrationIntent(bytes calldata pqMessage, bytes calldata salt, uint256[] calldata cs1, uint256[] calldata cs2, uint256 hint)`

**Purpose**: Remove a pending unregistration intent using PQ signature

**Security Model**: PQ-controlled (only the PQ key can cancel its own unregistration intent)

**Parameters**:
- `pqMessage`: PQ message containing the removal request
- `salt`: PQ signature salt (40 bytes)
- `cs1`: PQ signature cs1 component (32 uint256 array)
- `cs2`: PQ signature cs2 component (32 uint256 array)
- `hint`: PQ signature hint

**Message Format**: `DOMAIN_SEPARATOR + "Remove unregistration intent from ETH Address " + ethAddress + pqNonce`

**Validation**:
- Verify PQ signature and recover fingerprint
- Parse ETH Address from PQ message
- Check if there's a pending unregistration intent
- Verify the public key address matches the intent
- Verify the PQ message contains the correct removal text
- Clear the intent

**Events**: `UnregistrationIntentRemoved(address indexed ethAddress)`

**Nonce Management**: None (PQ nonce not incremented for removal)

## Edge Cases and Security Tests

### General Security
- [ ] **Replay attack prevention**
  - [ ] All nonces increment correctly after successful operations
  - [ ] Old nonces are rejected
  - [ ] Nonces cannot be reused

- [ ] **Signature validation**
  - [ ] Invalid signature components are rejected
  - [ ] Zero addresses from signature recovery are rejected
  - [ ] Signature malleability is handled correctly

- [ ] **Access control**
  - [ ] Only authorized addresses can perform operations
  - [ ] Cross-function access is properly validated

### State Consistency
- [ ] **Mapping consistency**
  - [ ] `epervierKeyToAddress` and `addressToEpervierKey` stay in sync
  - [ ] Intent mappings are properly cleared
  - [ ] No orphaned state after operations

- [ ] **Intent lifecycle**
  - [ ] Intents are properly created, validated, and cleared
  - [ ] No conflicting intents can exist simultaneously
  - [ ] Intent timestamps are set correctly

### Error Handling
- [ ] **Graceful failure**
  - [ ] Invalid operations fail with clear error messages
  - [ ] Gas costs are reasonable for failed operations
  - [ ] State remains consistent after failed operations

- [ ] **Boundary conditions**
  - [ ] Zero addresses are handled correctly
  - [ ] Maximum values are handled correctly
  - [ ] Empty messages are rejected appropriately

## Integration Tests

### Multi-step Workflows
- [ ] **Complete registration workflow**
  - [ ] Submit intent → Confirm registration → Verify state
  - [ ] Submit intent → Remove intent → Verify state

- [ ] **Complete change address workflow**
  - [ ] Submit change intent → Confirm change → Verify state
  - [ ] Submit change intent → Remove intent → Verify state

- [ ] **Complete unregistration workflow**
  - [ ] Submit unregistration intent → Confirm unregistration → Verify state
  - [ ] Submit unregistration intent → Remove intent → Verify state

### Concurrent Operations
- [ ] **Multiple users**
  - [ ] Multiple users can register simultaneously
  - [ ] Multiple users can change addresses simultaneously
  - [ ] Multiple users can unregister simultaneously

- [ ] **Race conditions**
  - [ ] Conflicting operations are properly rejected
  - [ ] State remains consistent under concurrent access

## Performance Tests

### Gas Optimization
- [ ] **Gas costs**
  - [ ] Registration operations are within acceptable gas limits
  - [ ] Change address operations are within acceptable gas limits
  - [ ] Unregistration operations are within acceptable gas limits

- [ ] **Gas efficiency**
  - [ ] Operations use minimal gas for their complexity
  - [ ] No unnecessary storage operations
  - [ ] Efficient signature verification

### Scalability
- [ ] **Large number of users**
  - [ ] Contract performs well with many registered users
  - [ ] Gas costs don't increase significantly with user count
  - [ ] No bottlenecks in common operations

## Documentation Tests

### Function Documentation
- [ ] **NatSpec comments**
  - [ ] All functions have proper NatSpec documentation
  - [ ] Parameters are clearly documented
  - [ ] Return values are documented
  - [ ] Events are documented

- [ ] **Error messages**
  - [ ] Error messages are clear and helpful
  - [ ] Error codes are consistent
  - [ ] Error messages help with debugging

## Deployment Tests

### Contract Deployment
- [ ] **Constructor validation**
  - [ ] Contract deploys with valid verifier address
  - [ ] Contract rejects zero address verifier
  - [ ] Initial state is correct

- [ ] **Upgrade considerations**
  - [ ] State layout is compatible with potential upgrades
  - [ ] No hardcoded addresses that would prevent upgrades
  - [ ] Events are properly indexed for external monitoring

---

## Test Execution Notes

### Test Environment Setup
- [ ] Use Foundry for testing
- [ ] Set up test accounts with both ETH and PQ keys
- [ ] Deploy mock Epervier verifier for testing
- [ ] Use deterministic test vectors

### Test Data Management
- [ ] Use centralized actor config for consistent test data
- [ ] Generate test vectors programmatically
- [ ] Validate test vectors against schema
- [ ] Use realistic PQ signatures and ETH signatures

### Continuous Integration
- [ ] Run all tests on every commit
- [ ] Generate test coverage reports
- [ ] Validate gas usage on every test run
- [ ] Check for regressions in performance 