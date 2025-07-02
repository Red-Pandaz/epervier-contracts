const { keccak256, toUtf8Bytes } = require('ethers');

// Calculate type hashes for the updated structs
const typeHashes = {
    REGISTRATION_INTENT: keccak256(toUtf8Bytes("RegistrationIntent(bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage,uint256 ethNonce)")),
    REGISTRATION_CONFIRMATION: keccak256(toUtf8Bytes("RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)")),
    REMOVE_INTENT: keccak256(toUtf8Bytes("RemoveIntent(address pqFingerprint,uint256 ethNonce)")),
    CHANGE_ETH_ADDRESS_INTENT: keccak256(toUtf8Bytes("ChangeETHAddressIntent(address newETHAddress,address pqFingerprint,uint256 ethNonce)")),
    CHANGE_ETH_ADDRESS_CONFIRMATION: keccak256(toUtf8Bytes("ChangeETHAddressConfirmation(address oldETHAddress,address pqFingerprint,uint256 ethNonce)")),
    UNREGISTRATION_INTENT: keccak256(toUtf8Bytes("UnregistrationIntent(address pqFingerprint,uint256 ethNonce)")),
    UNREGISTRATION_CONFIRMATION: keccak256(toUtf8Bytes("UnregistrationConfirmation(address pqFingerprint,uint256 ethNonce)")),
    REMOVE_CHANGE_INTENT: keccak256(toUtf8Bytes("RemoveChangeIntent(address pqFingerprint,uint256 ethNonce)")),
    REMOVE_UNREGISTRATION_INTENT: keccak256(toUtf8Bytes("RemoveUnregistrationIntent(uint256 ethNonce)"))
};

console.log("Updated EIP-712 Type Hashes:");
console.log("=============================");
for (const [name, hash] of Object.entries(typeHashes)) {
    console.log(`${name}: ${hash}`);
} 