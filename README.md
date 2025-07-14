# Epervier Registry - Post-Quantum Smart Contract System

> **⚠️ EXPERIMENTAL SOFTWARE WARNING ⚠️**
> 
> This is an **experimental smart contract stack** built with AI assistance on top of an **unaudited EVM-compatible variant** of the Falcon signature standard created by [ZKNoxHQ](https://github.com/ZKNoxHQ/ETHFALCON).
> 
> **🚫 DO NOT USE IN PRODUCTION** - This software is for research and development purposes only.
> 
> **Risk factors:**
> - ⚡ **Experimental cryptography** - ETHFALCON is not yet production-ready
> - 🤖 **AI-assisted development** - Code generated with AI tools requires careful review  
> - 🔬 **Research prototype** - Intended for academic and experimental use only
> - 🚫 **No security audits** - Smart contracts have not undergone professional security audits
> - 🙋 **One person team** - There is currently no one else developing, reviewing or maintaining this work

A comprehensive post-quantum cryptographic smart contract system built on Ethereum, featuring quantum-resistant digital signatures and NFT transfers using the Evervier variant of the ETHFALCON signature scheme.

## 🚀 Live Deployment (OP Sepolia)

### Core Contracts

| Contract | Address | Description |
|----------|---------|-------------|
| **PQRegistry** | [`0x18E3bc34fc2645bDCe2b85AF6f9e0ac3cD26637e`](https://sepolia-optimistic.etherscan.io/address/0x18E3bc34fc2645bDCe2b85AF6f9e0ac3cD26637e) | Main registry for post-quantum key management |
| **PQERC721** | [`0x9f6A2b8560FceF521ACe81c651CFd8A07381B950`](https://sepolia-optimistic.etherscan.io/address/0x9f6A2b8560FceF521ACe81c651CFd8A07381B950) | Post-quantum secured NFT contract |
| **EpervierVerifier** | [`0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B`](https://sepolia-optimistic.etherscan.io/address/0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B) | Epervier signature verifier deployed by ZKNoxHQ |

### Logic Contracts (Modular Architecture)

| Contract | Address | Purpose |
|----------|---------|---------|
| **MessageParser** | [`0x804B4EDe5f9e37Bd6bbdb0C02629dB80930029D5`](https://sepolia-optimistic.etherscan.io/address/0x804B4EDe5f9e37Bd6bbdb0C02629dB80930029D5) | Parses structured intent messages |
| **MessageValidation** | [`0xDBB242BBF5c6Ea43807Db09F93C8160aa8058bb8`](https://sepolia-optimistic.etherscan.io/address/0xDBB242BBF5c6Ea43807Db09F93C8160aa8058bb8) | Validates message formats and constraints |
| **SignatureExtractor** | [`0x15DC6b3a0Fc5fB51404fC4ed40d125D6aEBf6A3d`](https://sepolia-optimistic.etherscan.io/address/0x15DC6b3a0Fc5fB51404fC4ed40d125D6aEBf6A3d) | Extracts and validates Epervier signatures |
| **AddressUtils** | [`0x283E2d56804D5577d4751885BEeef9cC430c20B0`](https://sepolia-optimistic.etherscan.io/address/0x283E2d56804D5577d4751885BEeef9cC430c20B0) | Address derivation and validation utilities |
| **RegistrationLogic** | [`0xEda9fbfe78df1274B33F81b3d62B6aD287D32fEB`](https://sepolia-optimistic.etherscan.io/address/0xEda9fbfe78df1274B33F81b3d62B6aD287D32fEB) | Handles PQ key registration workflow |
| **UnregistrationLogic** | [`0x0EA8C0Fa222b3EFD3FDdec18b18819130512b01E`](https://sepolia-optimistic.etherscan.io/address/0x0EA8C0Fa222b3EFD3FDdec18b18819130512b01E) | Manages key unregistration process |
| **ChangeAddressLogic** | [`0xAc4fE28b070330aE9644cF06Be0bf48eD01F4913`](https://sepolia-optimistic.etherscan.io/address/0xAc4fE28b070330aE9644cF06Be0bf48eD01F4913) | Handles ETH address changes |

### Network Details
- **Network**: Optimism Sepolia Testnet
- **Chain ID**: 11155420
- **Block Explorer**: [Optimistic Etherscan](https://sepolia-optimistic.etherscan.io/)

## 📖 System Overview

### PQRegistry Contract

The **PQRegistry** is the core contract that manages post-quantum cryptographic key registrations and intent-based operations. It provides a secure, quantum-resistant alternative to traditional ECDSA-based systems.

#### Key Features:
- **Post-Quantum Address Fingerprints**: Epervier signatures use a recovery function that consistently derives deterministic Ethereum-style addresses from PQ signatures, creating unique 20-byte fingerprints for post-quantum keys. While these fingerprint addresses cannot natively control ETH or ECDSA-based tokens, they can own PQ-compatible assets and potentially back smart contract wallets that bridge post-quantum security to traditional Ethereum assets.
  > **⚠️ WARNING ABOUT USAGE OF FINGERPRINTS ⚠️**
  > 
  > As specified above, **Epervier fingerprints are not regular Ethereum addresses**. Do not **under any circumstance** send ETH or regular ERC20/ERC721 tokens to a fingerprint, **permanent loss of funds WILL occur**!
  > 
- **Hybrid Key Registration**: Users register Epervier public keys linked to their Ethereum addresses, creating a bridge between classical and post-quantum cryptographic systems.
- **Intent-Based Operations**: Supports registration, unregistration, and address change intents with cryptographic proofs and optional revocation.
- **Dual Signature Validation**: Requires both Epervier (post-quantum) and ECDSA (Ethereum) signatures for critical operations, ensuring security in both classical and quantum threat models.
- **Modular Architecture**: Built with separate logic contracts for maintainability and upgradability
- **EIP-712 Compliance**: Uses standard domain separators for secure message signing.

#### Core Operations:
1. **Registration Intent**: Submit intent to register a new PQ key with Epervier signature
2. **Remove Registration Intent by ETH**: Remove a registration intent using just the ECDSA key from the intent
3. **Remove Registration Intent by PQ**: Remove a registration intent using just the PQ key from the intent
4. **Registration Confirmation**: Confirm registration with both Epervier and ECDSA signatures
5. **Unregistration Intent**: Submit intent to remove a PQ key
6. **Remove Unregistration Intent by PQ**: Remove an unregistration intent using just the PQ key from the intent (note: no ETH equivalent)
7. **Unregistration Confirmation**: Confirm unregistration of both PQ and ECDSA keys
8. **Address Change Intent**: Submit intent to change the associated Ethereum address
9. **Remove Address Change Intent by ETH**: Remove an address change intent using just the ECDSA key for the new ETH address from the intent (Note: only the new address can use this function, in case of compromised keys)
10. **Remove Address Change Intent by PQ**: Remove an address change intent using just the PQ key from the intent
11. **Address Change Confirmation**: Confirm address changes with proper validation

### PQERC721 Contract

The **PQERC721** extends the standard ERC721 NFT contract with post-quantum transfer capabilities, enabling quantum-resistant NFT ownership and transfers.

#### Key Features:
- **Proof of Post-Quantum Keys**: Tokens can only be minted by successfully pairing an Epervier ffingerprint to an Ethereum address
- **Post-Quantum Transfers**: Supports transfers using Epervier signatures instead of ECDSA
- **Registry Integration**: Automatically validates transfers against registered Ethereum addresses

#### New PQTransferFrom method:
- **PQ-backed**: Transfering is **only possible** through with a valid Epervier signature
- **Extends security to Ethereum addresses via registry**: A token can be moved by a signature that recovers to either the owner of the token or the owner's registered Epervier fingerprint

### Future Developments (possibly):
- **Front-end app**: Improve UX by building an interface that allows generating PQ keys all well as performing registry operations
- **PQ smart contract wallet**: Extend PQ security to ECDSA-backed assets
- **Extensive PQ token contract library**: The proof of concept PQERC721 is one of at least 8 potential token variants
  - PQ tokens can be either ERC20 or ERC721, backwards compatible or PQ-only, and extend ownership via the registry or not
  - Backwards compatible tokens would behave as regular ECDSA tokens but would also have a PQTransferFrom so they could be moved by fingerprints
  - Tokens can reference the registry to extend PQ security to registered Ethereum addresses
- **Oracle service for verifying credentials**: Allow users to bind their Epervier fingerprints with verified email addresses, PGP and ML-KEM/Kyber pubkeys
  - Users sign an intent message to bind a given email address and send it to the oracle
  - Oracle verifies signature, then cosigns the message and calculates the hash of the message + oracle sig
  - User commits hash onchain alongside intent message and signature components and the oracle subequently sends the unhashed signature to the intent email address
  - If the user does have access to this address they will be able to retrieve the signature and put it onchain alongside a signed confirmation message
  = All signatures get verified and the intent message + oracle sig hash is verified
  - After email verification, users can complete a similar process to register PGP or ML-KEM/Kyber pubkeys
  - In these cases the emailed signature will be encrypted with their alleged public key for users to demonstrate proof of keys


## 🔐 Epervier/ETHFALCON Integration

### What is Epervier?

Epervier is an EVM-optimized variant of the ETHFALCON post-quantum digital signature scheme, which is based on the FALCON lattice-based cryptographic algorithm. It provides quantum-resistant signatures that remain secure even against quantum computer attacks.

#### Key Properties:
- **Quantum Resistance**: Secure against both classical and quantum computer attacks
- **Lattice-Based**: Built on the mathematical hardness of lattice problems
- **NIST Standardized**: Based on FALCON, a NIST post-quantum cryptography standard, although Epervier and other ETHFALCON variants are themselves **not standardized**
- **Efficient Verification**: Optimized for blockchain verification with reasonable gas costs

### Integration Architecture

The system implements three primary workflows with dual-signature validation:

#### 1. Registration Workflow
```mermaid
flowchart TD
  subgraph Registration
    A[User] --> B["Sign Intent with Epervier Key"]
    B --> C["Produce Epervier Signature"]
    C --> D["Sign Payload (Epervier Key + Signature + Intent) with Ethereum Key"]
    D --> E["Produce Ethereum Signature"]
    E --> F["Send Registration Payload to Smart Contract"]
  end

  subgraph "Optional Revocation"
    F --> X1["Revoke Intent with Epervier Key"] --> X3["Cancel Pending Registration"]
    F --> X2["Revoke Intent with Ethereum Key"] --> X3
  end

  subgraph Confirmation
    F --> G["Sign Confirmation Message with Ethereum Key"]
    G --> H["Produce Ethereum Confirmation Signature"]
    H --> I["Create Epervier Confirmation Message (Includes ETH Msg + Sig)"]
    I --> J["Sign with Epervier Key"]
    J --> K["Send Final Confirmation Payload"]
    K --> L["Mutual Ownership Proven"]
  end
```

#### 2. Address Change Workflow
```mermaid
flowchart TD
  subgraph Intent
    A[User] --> B["Sign Intent with New ETH Key"]
    B --> C["Produce New ETH Signature"]
    C --> D["Create PQ Intent (Includes ETH Msg + Sig)"]
    D --> E["Sign PQ Intent with Epervier Key"]
    E --> F["Send Change Intent Payload"]
  end

  subgraph "Optional Revocation"
    F --> X1["Revoke with PQ Key"] --> X3["Cancel Pending Change"]
    F --> X2["Revoke with New ETH Key"] --> X3
  end

  subgraph Confirmation
    F --> G["Sign Confirmation with PQ Key"]
    G --> H["Create ETH Confirmation (Includes PQ Msg + Sig)"]
    H --> I["Sign Final Confirmation with New ETH Key"]
    I --> J["Send Final Confirmation Payload"]
    J --> K["ETH Address Updated"]
  end
```

#### 3. Unregistration Workflow
```mermaid
flowchart TD
  subgraph Intent
    A[User] --> B["Sign Unregister Intent with ETH Key"]
    B --> C["Produce ETH Signature"]
    C --> D["Create PQ Unregister Intent (Includes ETH Msg + Sig)"]
    D --> E["Sign PQ Intent with Epervier Key"]
    E --> F["Send Unregister Intent Payload"]
  end

  subgraph "Optional Revocation"
    F --> X1["Revoke with PQ Key"] --> X2["Cancel Pending Unregistration"]
  end

  subgraph Confirmation
    F --> G["Sign Unregister Confirmation with PQ Key"]
    G --> H["Create ETH Confirmation (Includes PQ Msg + Sig)"]
    H --> I["Sign Final Confirmation with ETH Key"]
    I --> J["Send Final Confirmation Payload"]
    J --> K["Unregistration Complete"]
  end
```

### Signature Process

1. **Key Generation**: Users generate Epervier key pairs using the reference implementation
2. **Message Signing**: Intent messages are signed with Epervier private keys
3. **On-Chain Verification**: The EpervierVerifier contract validates Epervier signatures
4. **State Updates**: Successful verifications update the registry state
5. **Dual Authentication**: Critical operations require additional ECDSA confirmation

### Security Model

The system implements a **hybrid security model**:

- **Post-Quantum Security**: Epervier signatures protect against quantum attacks
- **Immediate Compatibility**: ECDSA signatures ensure current Ethereum compatibility
- **Progressive Migration**: Users can opt-in to post-quantum security while maintaining backward compatibility
- **Intent-Confirmation Pattern**: Two-phase operations prevent replay attacks and ensure user consent

## 🏗️ Architecture

### Modular Design

The system uses a modular architecture where logic is separated into dedicated contracts:

- **MessageParser**: Handles structured message parsing and validation
- **SignatureExtractor**: Extracts and validates cryptographic signatures
- **MessageValidation**: Enforces business logic and constraint validation
- **AddressUtils**: Provides address derivation and utility functions
- **Logic Contracts**: Separate contracts for each major operation (registration, unregistration, address changes)

### Benefits:
- **Upgradability**: Logic contracts can be upgraded without changing the main registry
- **Maintainability**: Separation of concerns makes the codebase easier to maintain
- **Testing**: Individual components can be tested in isolation

### Limitations:

#### Gas Costs

The system's cryptographic operations result in high gas costs due to extensive message parsing and post-quantum signature verification:

| Operation | Gas Range | Description |
|-----------|-----------|-------------|
| **Registration Intent** | ~9-9.5M gas | Submit intent with dual signatures |
| **Registration Confirmation** | ~7.8-8.3M gas | Confirm with dual signatures |
| **Total Registration** | ~16.8-17.8M gas | Complete registration process |
| **PQ Token Transfer** | ~7M gas | ERC721 transfer using Epervier signature |

**Note**: These costs make the system impractical for Ethereum L1. The current deployment is on OP Sepolia to work with the official Epervier contract. OP Mainnet and Base are potential candidates for mainnet implementation.

On-chain Post-Quantum signature verification is inherently gas-intensive. This contract stack intentionally prioritizes security over gas-optimization. One could theoretically create a working registry that only relies on a single message signed with both an Ethereum and an Epervier key; this suite however utilizes nested signatures with both an intent and a confirm transaction. This gives either key the opportunity to cancel the intent and requires a more concerted effort to successfully pair keys. This was designed with the consideration that following a successful registration, the Ethereum key loses substantial privileges as the Epervier key becomes the primary identity on the contract.

#### PQ Key Storage

Epervier and other Falcon variants have extremely large key sizes, and their signature requirements exceed the capabilities of modern hardware wallets. If and when a front-end for this contract stack is developed it will likely use some sort of password-protected encryption and will store keys in IndexedDB.

## 🚀 Getting Started

### For Developers

1. **Clone the Repository**:
   ```bash
   git clone --recurse-submodules https://github.com/your-repo/epervier-registry
   cd epervier-registry
   ```
   
   **Or if already cloned without submodules**:
   ```bash
   git submodule update --init --recursive
   ```

2. **Install Dependencies**:
   ```bash
   forge install
   ```

3. **Set up ETHFALCON CLI**:
   ```bash
   # Navigate to ETHFALCON python environment
   cd ETHFALCON/python-ref
   
   # Create virtual environment (if not exists)
   python3 -m venv myenv
   source myenv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Return to project root
   cd ../..
   ```

4. **Run Tests**:
   ```bash
   forge test
   ```

5. **Deploy Locally**:
   ```bash
   # Set up local environment
   source script/setup_env.sh
   
   # Deploy to local testnet
   forge script script/DeployLocalEpervier.s.sol --broadcast
   ```

### For Users

1. **Generate Epervier Keys**: Use the ETHFALCON reference implementation to generate post-quantum key pairs
2. **Register Your Key**: Submit a registration intent with an Epervier signature nested inside an Ethereum message
3. **Confirm Registration**: Confirm registration with an Ethereum signature nested inside an Epervier message
4. **Use PQ Features**: Transfer NFTs and perform operations using post-quantum signatures from any Ethereum address

## 📚 Documentation

- [OP Sepolia Deployment Guide](script/README_OP_SEPOLIA.md)
- [ETHFALCON Documentation](ETHFALCON/README.md)
- [Message Schemas](preregistry_message_schema.json)

## 🔬 Research & Development

This project represents innovative research in post-quantum cryptography for blockchain applications. Key innovations include:

- **First practical PQ-secured NFT implementation**
- **Intent-based cryptographic workflows**
- **Nested signature model with a two-step process proving two keys have ownership of one-another**
- **Hybrid classical/post-quantum security models**

## 🤝 Contributing

We welcome contributions to advance post-quantum cryptography in blockchain systems. Please see our contribution guidelines and open issues for areas where help is needed.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Security Notice

This is experimental software created for demonstration/research purposes. It implments bleeding edge cryptographic techniques, and while thoroughly tested, it should be absolutely not be used in any production environment. Post-quantum cryptography is an evolving field, and standards may change.

---

*Built with ❤️ for a quantum-safe future*
