#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/alloy.jpg",
    html_favicon_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/favicon.ico"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! ENS Name resolving utilities.

use alloy_primitives::{address, Address, Keccak256, B256};
use std::{borrow::Cow, str::FromStr};

/// ENS Universal Resolver address (`0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe`).
///
/// The primary entry-point for ENSv2 name resolution. This upgradable proxy,
/// governed by the ENS DAO, supports wildcard resolvers and CCIP Read (ERC-3668)
/// for L2 and offchain names.
pub const ENS_UNIVERSAL_RESOLVER_ADDRESS: Address =
    address!("0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe");


/// Coin types for ENS multichain address resolution.
///
/// Ethereum uses SLIP-0044 coin type `60`. Other EVM-compatible chains follow
/// ENSIP-11: `coinType = 0x80000000 | chainId`. Use [`evm_chain`][coin_type::evm_chain] to
/// compute the coin type for any EVM chain ID.
pub mod coin_type {
    /// Ethereum mainnet (SLIP-0044, coin type 60).
    pub const ETH: u64 = 60;

    /// Computes the ENSIP-11 EVM coin type for the given chain ID.
    ///
    /// Equivalent to `0x80000000 | chain_id`.
    pub const fn evm_chain(chain_id: u32) -> u64 {
        0x8000_0000u64 | chain_id as u64
    }
}

#[cfg(feature = "contract")]
pub use contract::*;

#[cfg(feature = "provider")]
pub use provider::*;

/// ENS name or Ethereum Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameOrAddress {
    /// An ENS Name (format does not get checked)
    Name(String),
    /// An Ethereum Address
    Address(Address),
}

impl NameOrAddress {
    /// Resolves the name to an Ethereum Address.
    #[cfg(feature = "provider")]
    pub async fn resolve<N: alloy_provider::Network, P: alloy_provider::Provider<N>>(
        &self,
        provider: &P,
    ) -> Result<Address, EnsError> {
        match self {
            Self::Name(name) => provider.resolve_name(name).await,
            Self::Address(addr) => Ok(*addr),
        }
    }
}

impl From<String> for NameOrAddress {
    fn from(name: String) -> Self {
        Self::Name(name)
    }
}

impl From<&String> for NameOrAddress {
    fn from(name: &String) -> Self {
        Self::Name(name.clone())
    }
}

impl From<Address> for NameOrAddress {
    fn from(addr: Address) -> Self {
        Self::Address(addr)
    }
}

impl FromStr for NameOrAddress {
    type Err = <Address as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Address::from_str(s) {
            Ok(addr) => Ok(Self::Address(addr)),
            Err(err) => {
                // Treat any dot-separated string longer than 2 chars as a potential ENS name.
                // This covers .eth names, imported DNS domains (e.g. ensfairy.xyz), subdomains,
                // and emoji domains as required by ENSv2.
                if s.contains('.') && s.len() > 2 {
                    Ok(Self::Name(s.to_string()))
                } else {
                    Err(err)
                }
            }
        }
    }
}

/// Error returned by [`dns_encode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsEncodeError {
    /// A label in the name is empty (e.g., consecutive dots or leading/trailing dot).
    EmptyLabel,
    /// A label exceeds the 63-byte maximum DNS length.
    LabelTooLong,
}

impl std::fmt::Display for DnsEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLabel => f.write_str("ENS name contains an empty label"),
            Self::LabelTooLong => f.write_str("ENS name label exceeds 63 bytes"),
        }
    }
}

impl std::error::Error for DnsEncodeError {}

/// DNS wire-format encodes an ENS name for use with the Universal Resolver's `resolve()`.
///
/// Each label is prefixed with its byte length and the sequence is terminated with `\x00`.
/// For example, `"foo.eth"` encodes to `[3, 'f', 'o', 'o', 3, 'e', 't', 'h', 0]`.
///
/// Returns an error if any label is empty or exceeds 63 bytes.
pub fn dns_encode(name: &str) -> Result<Vec<u8>, DnsEncodeError> {
    if name.is_empty() {
        return Ok(vec![0]);
    }

    // Strip variation selector as in namehash.
    const VARIATION_SELECTOR: char = '\u{fe0f}';
    let name = if name.contains(VARIATION_SELECTOR) {
        Cow::Owned(name.replace(VARIATION_SELECTOR, ""))
    } else {
        Cow::Borrowed(name)
    };

    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            return Err(DnsEncodeError::EmptyLabel);
        }
        if bytes.len() > 63 {
            return Err(DnsEncodeError::LabelTooLong);
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    Ok(out)
}

#[cfg(feature = "contract")]
mod contract {
    use alloy_sol_types::sol;

    // ENS Registry, Resolver, and Universal Resolver contracts.
    sol! {
        /// ENS Resolver interface (ENSIP-1).
        #[sol(rpc)]
        contract EnsResolver {
            /// Returns the Ethereum address associated with the specified node.
            function addr(bytes32 node) view returns (address);

            /// Returns the name associated with an ENS node, for reverse records.
            function name(bytes32 node) view returns (string);

            /// Returns the txt record value for the specified key.
            function text(bytes32 node, string calldata key) view virtual returns (string memory);
        }

        /// ENS Multicoin Resolver interface (ENSIP-11).
        ///
        /// Provides multichain address resolution. Use with the Universal Resolver and
        /// coin type constants from [`coin_type`][crate::coin_type].
        #[sol(rpc)]
        contract EnsMulticoinResolver {
            /// Returns the address for `node` on the chain identified by `coin_type`.
            ///
            /// The returned bytes are the raw address encoding for that coin type
            /// (e.g., 20-byte ABI-encoded address for EVM chains, script bytes for Bitcoin).
            function addr(bytes32 node, uint256 coin_type) view returns (bytes memory);
        }

        /// ENS Universal Resolver (ENSv2).
        ///
        /// The single entry-point for all ENS resolution. Handles routing to wildcard
        /// resolvers and CCIP Read (ERC-3668) for L2 and offchain names.
        ///
        /// Note: CCIP Read requires client-side handling of the `OffchainLookup` revert
        /// (ERC-3668). Alloy does not currently implement this; calls to names that require
        /// CCIP Read will surface as [`EnsError::Resolve`].
        #[sol(rpc)]
        contract UniversalResolver {
            /// Resolves `name` (DNS wire-format) using the encoded `data` call.
            ///
            /// Returns the ABI-encoded result of the resolver call and the resolver address.
            /// Reverts with `OffchainLookup` when CCIP Read (ERC-3668) is required.
            function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory result, address resolver);

            /// Reverse-resolves an address to its primary ENS name.
            ///
            /// `reverse_name` is the DNS wire-format encoding of `<addr>.addr.reverse`.
            function reverse(bytes calldata reverse_name) external view returns (string memory name, address resolver, address reverse_resolver, address addr);
        }
    }

    /// Error type for ENS resolution.
    #[derive(Debug, thiserror::Error)]
    pub enum EnsError {
        /// Failed to get the resolver for this name.
        #[error("Failed to get ENS resolver: {0}")]
        Resolver(alloy_contract::Error),
        /// No resolver found for the given name.
        #[error("ENS resolver not found for name {0:?}")]
        ResolverNotFound(String),
        /// Failed to perform a reverse lookup.
        #[error("Failed to lookup ENS name from an address: {0}")]
        Lookup(alloy_contract::Error),
        /// Failed to resolve ENS name to an address.
        #[error("Failed to resolve ENS name to an address: {0}")]
        Resolve(alloy_contract::Error),
        /// Failed to get txt records of ENS name.
        #[error("Failed to resolve txt record: {0}")]
        ResolveTxtRecord(alloy_contract::Error),
        /// Failed to DNS-encode the ENS name for the Universal Resolver.
        #[error("Failed to DNS-encode ENS name: {0}")]
        DnsEncode(#[from] crate::DnsEncodeError),
        /// Failed to decode the Universal Resolver response.
        #[error("Failed to decode Universal Resolver response")]
        InvalidResponse,
    }
}

#[cfg(feature = "provider")]
mod provider {
    use crate::{
        dns_encode, namehash, reverse_address, EnsError, EnsMulticoinResolver, EnsResolver,
        EnsResolver::EnsResolverInstance, UniversalResolver, ENS_UNIVERSAL_RESOLVER_ADDRESS,
    };
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_provider::{Network, Provider};
    use alloy_sol_types::{SolCall, SolValue};

    /// Extension trait for ENS contract calls.
    #[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
    pub trait ProviderEnsExt<N: alloy_provider::Network, P: Provider<N>> {
        /// Returns the resolver contract instance for the given ENS name.
        ///
        /// Determines the resolver address via the Universal Resolver.
        async fn get_resolver(&self, name: &str) -> Result<EnsResolverInstance<&P, N>, EnsError>;

        /// Performs a forward lookup of an ENS name to an Ethereum address.
        ///
        /// Routes through the [Universal Resolver], which handles wildcard resolvers
        /// and CCIP Read (ERC-3668) for L2 and offchain names.
        ///
        /// [Universal Resolver]: https://docs.ens.domains/web/ensv2-readiness
        async fn resolve_name(&self, name: &str) -> Result<Address, EnsError> {
            let node = namehash(name);
            let dns = dns_encode(name)?;
            let calldata = EnsResolver::addrCall { node }.abi_encode();

            let ur = UniversalResolver::new(ENS_UNIVERSAL_RESOLVER_ADDRESS, self);
            let ret = ur
                .resolve(dns.into(), calldata.into())
                .call()
                .await
                .map_err(EnsError::Resolve)?;

            Address::abi_decode(ret.result.as_ref()).map_err(|_| EnsError::InvalidResponse)
        }

        /// Resolves an ENS name to a multichain address for the given coin type (ENSIP-11).
        ///
        /// Returns the raw address bytes as stored in the resolver. The encoding varies
        /// by coin type: 20-byte ABI-encoded address for EVM chains, script bytes for
        /// Bitcoin, etc. Use constants in [`coin_type`][crate::coin_type] or
        /// [`coin_type::evm_chain`][crate::coin_type::evm_chain] for common coin types.
        async fn resolve_name_for_coin_type(
            &self,
            name: &str,
            coin_type: u64,
        ) -> Result<Bytes, EnsError> {
            let node = namehash(name);
            let dns = dns_encode(name)?;
            let calldata = EnsMulticoinResolver::addrCall {
                node,
                coin_type: U256::from(coin_type),
            }
            .abi_encode();

            let ur = UniversalResolver::new(ENS_UNIVERSAL_RESOLVER_ADDRESS, self);
            let ret = ur
                .resolve(dns.into(), calldata.into())
                .call()
                .await
                .map_err(EnsError::Resolve)?;

            Bytes::abi_decode(ret.result.as_ref()).map_err(|_| EnsError::InvalidResponse)
        }

        /// Performs a reverse lookup of an address to its primary ENS name.
        async fn lookup_address(&self, address: &Address) -> Result<String, EnsError> {
            let reverse_name = reverse_address(address);
            let dns = dns_encode(&reverse_name)?;

            let ur = UniversalResolver::new(ENS_UNIVERSAL_RESOLVER_ADDRESS, self);
            let ret = ur
                .reverse(dns.into())
                .call()
                .await
                .map_err(EnsError::Lookup)?;

            Ok(ret.name)
        }

        /// Looks up a text record for an ENS name.
        async fn lookup_txt(&self, name: &str, key: &str) -> Result<String, EnsError> {
            let node = namehash(name);
            let dns = dns_encode(name)?;
            let calldata =
                EnsResolver::textCall { node, key: key.to_string() }.abi_encode();

            let ur = UniversalResolver::new(ENS_UNIVERSAL_RESOLVER_ADDRESS, self);
            let ret = ur
                .resolve(dns.into(), calldata.into())
                .call()
                .await
                .map_err(EnsError::ResolveTxtRecord)?;

            String::abi_decode(ret.result.as_ref()).map_err(|_| EnsError::InvalidResponse)
        }
    }

    #[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
    impl<N, P> ProviderEnsExt<N, P> for P
    where
        P: Provider<N>,
        N: Network,
    {
        async fn get_resolver(&self, name: &str) -> Result<EnsResolverInstance<&P, N>, EnsError> {
            let node = namehash(name);
            let dns = dns_encode(name)?;
            let calldata = EnsResolver::addrCall { node }.abi_encode();

            let ur = UniversalResolver::new(ENS_UNIVERSAL_RESOLVER_ADDRESS, self);
            let ret = ur
                .resolve(dns.into(), calldata.into())
                .call()
                .await
                .map_err(EnsError::Resolver)?;

            if ret.resolver == Address::ZERO {
                return Err(EnsError::ResolverNotFound(name.to_string()));
            }
            Ok(EnsResolverInstance::new(ret.resolver, self))
        }
    }
}

/// Returns the ENS namehash as specified in [EIP-137](https://eips.ethereum.org/EIPS/eip-137)
pub fn namehash(name: &str) -> B256 {
    if name.is_empty() {
        return B256::ZERO;
    }

    // Remove the variation selector `U+FE0F` if present.
    const VARIATION_SELECTOR: char = '\u{fe0f}';
    let name = if name.contains(VARIATION_SELECTOR) {
        Cow::Owned(name.replace(VARIATION_SELECTOR, ""))
    } else {
        Cow::Borrowed(name)
    };

    // Generate the node starting from the right.
    // This buffer is `[node @ [u8; 32], label_hash @ [u8; 32]]`.
    let mut buffer = [0u8; 64];
    for label in name.rsplit('.') {
        // node = keccak256([node, keccak256(label)])

        // Hash the label.
        let mut label_hasher = Keccak256::new();
        label_hasher.update(label.as_bytes());
        label_hasher.finalize_into(&mut buffer[32..]);

        // Hash both the node and the label hash, writing into the node.
        let mut buffer_hasher = Keccak256::new();
        buffer_hasher.update(buffer.as_slice());
        buffer_hasher.finalize_into(&mut buffer[..32]);
    }
    buffer[..32].try_into().unwrap()
}

/// Returns the reverse-registrar name of an address.
pub fn reverse_address(addr: &Address) -> String {
    format!("{addr:x}.addr.reverse")
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::hex;

    fn assert_hex(hash: B256, val: &str) {
        assert_eq!(hash.0[..], hex::decode(val).unwrap()[..]);
    }

    #[test]
    fn test_namehash() {
        for (name, expected) in &[
            ("", "0x0000000000000000000000000000000000000000000000000000000000000000"),
            ("eth", "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"),
            ("foo.eth", "0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"),
            ("alice.eth", "0x787192fc5378cc32aa956ddfdedbf26b24e8d78e40109add0eea2c1a012c3dec"),
            ("ret↩️rn.eth", "0x3de5f4c02db61b221e7de7f1c40e29b6e2f07eb48d65bf7e304715cd9ed33b24"),
        ] {
            assert_hex(namehash(name), expected);
        }
    }

    #[test]
    fn test_reverse_address() {
        for (addr, expected) in [
            (
                "0x314159265dd8dbb310642f98f50c066173c1259b",
                "314159265dd8dbb310642f98f50c066173c1259b.addr.reverse",
            ),
            (
                "0x28679A1a632125fbBf7A68d850E50623194A709E",
                "28679a1a632125fbbf7a68d850e50623194a709e.addr.reverse",
            ),
        ] {
            assert_eq!(reverse_address(&addr.parse().unwrap()), expected, "{addr}");
        }
    }

    #[test]
    fn test_invalid_address() {
        for addr in [
            "0x314618",
            "0x000000000000000000000000000000000000000", // 41
            "0x00000000000000000000000000000000000000000", // 43
            "0x28679A1a632125fbBf7A68d850E50623194A709E123", // 44
        ] {
            assert!(NameOrAddress::from_str(addr).is_err());
        }
    }

    #[test]
    fn test_dns_encode() {
        assert_eq!(dns_encode("").unwrap(), vec![0]);
        assert_eq!(
            dns_encode("foo.eth").unwrap(),
            vec![3, b'f', b'o', b'o', 3, b'e', b't', b'h', 0]
        );
        assert_eq!(
            dns_encode("alice.eth").unwrap(),
            vec![5, b'a', b'l', b'i', b'c', b'e', 3, b'e', b't', b'h', 0]
        );
        // Empty label errors
        assert_eq!(dns_encode(".eth").unwrap_err(), DnsEncodeError::EmptyLabel);
        assert_eq!(dns_encode("foo..eth").unwrap_err(), DnsEncodeError::EmptyLabel);
        // Label too long
        let long_label = "a".repeat(64) + ".eth";
        assert_eq!(dns_encode(&long_label).unwrap_err(), DnsEncodeError::LabelTooLong);
    }

    #[test]
    fn test_name_or_address_dns_detection() {
        // Standard ENS names
        assert!(matches!(NameOrAddress::from_str("foo.eth"), Ok(NameOrAddress::Name(_))));
        // Imported DNS names (ENSv2 requirement)
        assert!(matches!(
            NameOrAddress::from_str("ensfairy.xyz"),
            Ok(NameOrAddress::Name(_))
        ));
        // Too short to be a valid ENS name (len <= 2)
        assert!(NameOrAddress::from_str(".").is_err());
        // Valid subdomains
        assert!(matches!(
            NameOrAddress::from_str("sub.foo.eth"),
            Ok(NameOrAddress::Name(_))
        ));
    }

    #[test]
    fn test_coin_type_evm_chain() {
        use crate::coin_type;
        assert_eq!(coin_type::evm_chain(1), 0x8000_0001);
        assert_eq!(coin_type::evm_chain(8453), 0x8000_2105); // Base
        assert_eq!(coin_type::evm_chain(10), 0x8000_000A); // Optimism
        assert_eq!(coin_type::evm_chain(42161), 0x8000_A4B1); // Arbitrum One
    }
}

#[cfg(all(test, feature = "provider"))]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use alloy_provider::ProviderBuilder;

    #[tokio::test]
    async fn test_pub_resolver_fetching_mainnet() {
        let provider = ProviderBuilder::new()
            .connect_http("https://reth-ethereum.ithaca.xyz/rpc".parse().unwrap());

        let res = provider.get_resolver("vitalik.eth").await;
        assert_eq!(*res.unwrap().address(), address!("0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63"));
    }

    #[tokio::test]
    async fn test_pub_resolver_text() {
        let provider = ProviderBuilder::new()
            .connect_http("http://reth-ethereum.ithaca.xyz/rpc".parse().unwrap());

        let name = "vitalik.eth";
        let node = namehash(name);
        let res = provider.get_resolver(name).await.unwrap();
        let txt = res.text(node, "avatar".to_string()).call().await.unwrap();
        assert_eq!(txt, "https://euc.li/vitalik.eth")
    }

    #[tokio::test]
    async fn test_pub_resolver_fetching_txt() {
        let provider = ProviderBuilder::new()
            .connect_http("http://reth-ethereum.ithaca.xyz/rpc".parse().unwrap());

        let name = "vitalik.eth";
        let res = provider.lookup_txt(name, "avatar").await.unwrap();
        assert_eq!(res, "https://euc.li/vitalik.eth")
    }

    /// ENSv2 readiness test: the Universal Resolver integration test name should resolve
    /// to a well-known address. See https://docs.ens.domains/web/ensv2-readiness
    #[tokio::test]
    async fn test_universal_resolver_integration() {
        let provider = ProviderBuilder::new()
            .connect_http("https://reth-ethereum.ithaca.xyz/rpc".parse().unwrap());

        let res = provider.resolve_name("ur.integration-tests.eth").await.unwrap();
        assert_eq!(res, address!("0x2222222222222222222222222222222222222222"));
    }
}
