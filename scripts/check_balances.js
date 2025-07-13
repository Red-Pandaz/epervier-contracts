async function main() {
    // query ETH balances on Arbitrum, Base, Optimism, and OP Sepolia
    const chains = [42161, 8453, 10, 11155420]
    
    for (const chain of chains) {
        // Using Etherscan V2 API with chainid parameter - one key for all chains
        try {
            const query = await fetch(`https://api.etherscan.io/v2/api?chainid=${chain}&module=account&action=balance&address=0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511&tag=latest&apikey=3J7J3ZRTT2BW75ATR9D29A1HWSH7GWKRVZ`)
               
            const response = await query.json()
            
            if (response.status === "1") {
                const balance = response.result
                const balanceInEth = (parseInt(balance) / 1e18).toFixed(4)
                const chainName = getChainName(chain)
                console.log(`${chainName} (${chain}): ${balance} wei (${balanceInEth} ETH)`)
            } else {
                console.log(`${getChainName(chain)} (${chain}): Error - ${response.message}`)
                console.log(`  Full response:`, JSON.stringify(response, null, 2))
            }
            
        } catch (error) {
            console.error(`Error querying chain ${chain}:`, error.message)
        }
    }
}


function getChainName(chainId) {
    const chainNames = {
        42161: "Arbitrum",
        8453: "Base", 
        10: "Optimism",
        11155420: "OP Sepolia"
    }
    return chainNames[chainId] || `Chain ${chainId}`
}

main() 