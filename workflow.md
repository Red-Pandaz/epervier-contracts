```mermaid
flowchart TD
  subgraph Registration
    A[User] --> B["Sign Intent with Epervier Key"]
    B --> C["Produce Epervier Signature"]
    C --> D["Sign Payload (Epervier Key + Signature + Intent) with Ethereum Key"]
    D --> E["Produce Ethereum Signature"]
    E --> F["Send Registration Payload to Smart Contract"]
  end

  subgraph Optional Revocation
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
  ```mermaid
```mermaid
flowchart TD
  subgraph Intent
    A[User] --> B["Sign Intent with New ETH Key"]
    B --> C["Produce New ETH Signature"]
    C --> D["Create PQ Intent (Includes ETH Msg + Sig)"]
    D --> E["Sign PQ Intent with Epervier Key"]
    E --> F["Send Change Intent Payload"]
  end

  subgraph Optional Revocation
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
```mermaid
```mermaid


  flowchart TD
  subgraph Intent
    A[User] --> B["Sign Unregister Intent with ETH Key"]
    B --> C["Produce ETH Signature"]
    C --> D["Create PQ Unregister Intent (Includes ETH Msg + Sig)"]
    D --> E["Sign PQ Intent with Epervier Key"]
    E --> F["Send Unregister Intent Payload"]
  end

  subgraph Optional Revocation
    F --> X1["Revoke with PQ Key"] --> X2["Cancel Pending Unregistration"]
  end

  subgraph Confirmation
    F --> G["Sign Unregister Confirmation with PQ Key"]
    G --> H["Create ETH Confirmation (Includes PQ Msg + Sig)"]
    H --> I["Sign Final Confirmation with ETH Key"]
    I --> J["Send Final Confirmation Payload"]
    J --> K["Unregistration Complete"]
  end



