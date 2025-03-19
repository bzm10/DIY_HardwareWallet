#include <Arduino.h>
#include <Crypto.h>  // For Ed25519 (Solana)
#include <Ed25519.h> // For Ed25519 key derivation
#include <uECC.h>    // For Ethereum (secp256k1)
#include "keccak256.h"
#include <tuple>
#include <Preferences.h>

Preferences prefs;

// --------------------------------------------
// Base58 Encoding Function
// --------------------------------------------
String base58Encode(const uint8_t *input, size_t len)
{
  const char *ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  // Count leading zeroes.
  size_t zeroes = 0;
  while (zeroes < len && input[zeroes] == 0)
    zeroes++;

  // Allocate enough space in big-endian base58 representation.
  size_t size = len * 138 / 100 + 1; // log(256)/log(58), rounded up.
  uint8_t buf[size];
  memset(buf, 0, size);

  // Process the bytes.
  for (size_t i = 0; i < len; i++)
  {
    int carry = input[i];
    for (ssize_t j = size - 1; j >= 0; j--)
    {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
    }
  }

  // Skip leading zeroes in the buf.
  size_t i = 0;
  while (i < size && buf[i] == 0)
    i++;

  // Translate the digits into the Base58 string.
  String result = "";
  // Add as many '1' as there were leading zeros.
  for (size_t j = 0; j < zeroes; j++)
  {
    result += '1';
  }
  for (; i < size; i++)
  {
    result += ALPHABET[buf[i]];
  }

  return result;
}

// -------------------------------------------------------------------------
// Solana (Ed25519): Generate a 32-byte seed and its corresponding public key
// -------------------------------------------------------------------------
std::tuple<String, String, String> generateSolanaKeys()
{
  // Generate a 32-byte random seed (private key)
  uint8_t solPrivateKey[32];
  for (int i = 0; i < 32; i++)
  {
    solPrivateKey[i] = (uint8_t)random(0, 256);
  }

  // Derive the 32-byte public key using Ed25519
  uint8_t solPublicKey[32];
  Ed25519::derivePublicKey(solPublicKey, solPrivateKey);

  // Optionally combine private & public key (64 bytes total)
  uint8_t solanaCombinedKey[64];
  memcpy(solanaCombinedKey, solPrivateKey, 32);
  memcpy(solanaCombinedKey + 32, solPublicKey, 32);

  // Print keys using Base58 encoding
  String solPrivBase58 = base58Encode(solPrivateKey, 32);
  String solPubBase58 = base58Encode(solPublicKey, 32);
  String solCombinedBase58 = base58Encode(solanaCombinedKey, 64);

  return std::make_tuple(solPrivBase58, solPubBase58, solCombinedBase58);
}

// -------------------------------------------------------------------------
// Ethereum (secp256k1): Generate a 32-byte private key and its 64-byte public key
// -------------------------------------------------------------------------
int my_rng(uint8_t *dest, unsigned size)
{
  for (unsigned i = 0; i < size; i += 4)
  {
    uint32_t rnd = esp_random();
    for (unsigned j = 0; j < 4 && (i + j) < size; j++)
    {
      dest[i + j] = (rnd >> (8 * (3 - j))) & 0xFF;
    }
  }
  return 1;
}

std::tuple<String, String, String> generateEthereumKeys()
{
  // Define variables to store keys and address
  uint8_t ethPrivateKey[32];
  uint8_t ethPublicKey[64];
  uint8_t ethAddress[20];

  // Select secp256k1 curve and set RNG
  const struct uECC_Curve_t *curve = uECC_secp256k1();
  uECC_set_rng(&my_rng);

  // Generate 32-byte Private Key
  for (int i = 0; i < 32; i += 4)
  {
    uint32_t rnd = esp_random();
    ethPrivateKey[i + 0] = (rnd >> 24) & 0xFF;
    ethPrivateKey[i + 1] = (rnd >> 16) & 0xFF;
    ethPrivateKey[i + 2] = (rnd >> 8) & 0xFF;
    ethPrivateKey[i + 3] = (rnd) & 0xFF;
  }
  // Compute the 64-byte Public Key
  if (!uECC_compute_public_key(ethPrivateKey, ethPublicKey, curve))
  {
    Serial.println("ERROR: Public key generation failed!");
    return std::make_tuple("", "", "");
  }

  // Derive Ethereum Address
  uint8_t keccakHash[32];
  SHA3_CTX ctx;
  keccak_init(&ctx);
  keccak_update(&ctx, ethPublicKey, 64);
  keccak_final(&ctx, keccakHash);

  // Store the last 20 bytes as the Ethereum address
  memcpy(ethAddress, keccakHash + 12, 20);

  // Convert byte arrays to hex strings
  String privKeyStr = "0x";
  String pubKeyStr = "0x04";
  String addrStr = "0x";
  
  for (int i = 0; i < 32; i++) {
    if (ethPrivateKey[i] < 0x10) privKeyStr += '0';
    privKeyStr += String(ethPrivateKey[i], HEX);
  }
  for (int i = 0; i < 64; i++) {
    if (ethPublicKey[i] < 0x10) pubKeyStr += '0';
    pubKeyStr += String(ethPublicKey[i], HEX);
  }
  for (int i = 0; i < 20; i++) {
    if (ethAddress[i] < 0x10) addrStr += '0';
    addrStr += String(ethAddress[i], HEX);
  }

  return std::make_tuple(privKeyStr, pubKeyStr, addrStr);
}


void setup()
{
  Serial.begin(115200);
  delay(1000);

  // Storage of keys
  prefs.begin("storage", false);
  String SolPriv = prefs.getString("SolPriv", "");
  String EthPriv = prefs.getString("EthPriv", "");


  prefs.end();

  if (SolPriv.length() > 0 && EthPriv.length() > 0)
  {
    Serial.print("Data found in NVS already: ");
    Serial.println(SolPriv);
    Serial.println(EthPriv);
  }
  else
  {
    // Variables to store keys
    String solPrivBase58, solPubBase58, solCombinedBase58;
    String ethPrivateKey, ethPublicKey, ethAddress;

    std::tie(solPrivBase58, solPubBase58, solCombinedBase58) = generateSolanaKeys();
    std::tie(ethPrivateKey, ethPublicKey, ethAddress) = generateEthereumKeys();

    // write the keys to NVS
    prefs.putString("SolPriv", solPrivBase58);
    prefs.putString("SolPub", solPubBase58);
    prefs.putString("SolCombined", solCombinedBase58);

    prefs.putString("EthPriv", ethPrivateKey);
    prefs.putString("EthPub", ethPublicKey);  
    prefs.putString("EthAddr", ethAddress);

    Serial.println("Keys generated and stored in NVS");
  }

  prefs.end();
}

void loop()
{
  // Nothing to do here.
}