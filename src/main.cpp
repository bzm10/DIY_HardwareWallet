#include <Arduino.h>
#include <Crypto.h>  // For Ed25519 (Solana)
#include <Ed25519.h> // For Ed25519 key derivation
#include <uECC.h>    // For Ethereum (secp256k1)
#include "keccak256.h"
#include <tuple>
#include <Preferences.h>
#include <AES.h>
#include <CBC.h>
#include <SHA256.h>


Preferences prefs;

static const size_t SALT_LEN = 8;
static const size_t IV_LEN = 16;  
static const size_t KEY_LEN = 32;

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
// --------------------------------------------
// Base58 Decoding Function
// --------------------------------------------
size_t base58Decode(const String &input, uint8_t *output, size_t outputLen)
{
  const char *ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  int8_t INDEXES[128];
  memset(INDEXES, -1, sizeof(INDEXES));
  for (int i = 0; i < 58; i++)
  {
    INDEXES[(uint8_t)ALPHABET[i]] = i;
  }

  // Convert the Base58 string to a big-endian integer
  size_t zeroes = 0;
  for (size_t i = 0; i < input.length(); i++)
  {
    if (input[i] >= 128 || INDEXES[(uint8_t)input[i]] == -1)
    {
      return 0; // Invalid character
    }
    if (input[i] == '1')
    {
      zeroes++;
    }
    else
    {
      break;
    }
  }

  size_t size = input.length() * 733 / 1000 + 1; // log(58)/log(256), rounded up
  uint8_t buf[size];
  memset(buf, 0, size);

  for (size_t i = 0; i < input.length(); i++)
  {
    int carry = INDEXES[(uint8_t)input[i]];
    for (ssize_t j = size - 1; j >= 0; j--)
    {
      carry += 58 * buf[j];
      buf[j] = carry % 256;
      carry /= 256;
    }
  }

  // Skip leading zeroes in the buffer
  size_t i = 0;
  while (i < size && buf[i] == 0)
  {
    i++;
  }

  // Copy the result into the output buffer
  size_t decodedLen = size - i + zeroes;
  if (decodedLen > outputLen)
  {
    return 0; // Output buffer too small
  }

  memset(output, 0, outputLen);
  memcpy(output + zeroes, buf + i, size - i);

  return decodedLen; // Return the number of bytes written to the output
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


// -------------------------------------------------------------------------
// Encrypt the private keys and store them in NVS
// -------------------------------------------------------------------------
String bytesToHex(const uint8_t *data, size_t length)
{
  String hexStr = "";
  for (size_t i = 0; i < length; i++)
  {
    if (data[i] < 16)
      hexStr += "0";
    hexStr += String(data[i], HEX);
  }
  return hexStr;
}

void hexToBytes(const String &hex, uint8_t *buffer, size_t bufferLen)
{
  for (size_t i = 0; i < bufferLen; i++)
  {
    String byteString = hex.substring(i * 2, i * 2 + 2);
    buffer[i] = (uint8_t)strtol(byteString.c_str(), NULL, 16);
  }
}

uint8_t *pkcs7Pad(const uint8_t *input, size_t inputLen, size_t blockSize, size_t &paddedLen)
{
  uint8_t padVal = blockSize - (inputLen % blockSize);
  if (padVal == 0)
    padVal = blockSize;
  paddedLen = inputLen + padVal;
  uint8_t *output = (uint8_t *)malloc(paddedLen);
  memcpy(output, input, inputLen);
  for (size_t i = inputLen; i < paddedLen; i++)
  {
    output[i] = padVal;
  }
  return output;
}

size_t pkcs7Unpad(uint8_t *buffer, size_t totalLen, size_t blockSize)
{
  if (totalLen == 0 || (totalLen % blockSize) != 0)
  {
    return 0; // malformed data
  }
  uint8_t padVal = buffer[totalLen - 1];
  if (padVal < 1 || padVal > blockSize)
    return 0;
  for (size_t i = totalLen - padVal; i < totalLen; i++)
  {
    if (buffer[i] != padVal)
      return 0;
  }
  return totalLen - padVal;
}

String encryptData(const String &plaintext, const char *password)
{
  size_t infoLen = plaintext.length();
  const uint8_t *plainData = (const uint8_t *)plaintext.c_str();

  // Generate random salt and IV
  uint8_t salt[SALT_LEN], iv[IV_LEN];
  for (size_t i = 0; i < SALT_LEN; i++)
  {
    salt[i] = (uint8_t)random(0, 256);
  }
  for (size_t i = 0; i < IV_LEN; i++)
  {
    iv[i] = (uint8_t)random(0, 256);
  }

  // Derive 32-byte key from (password + salt) using SHA-256
  uint8_t derivedKey[KEY_LEN];
  {
    SHA256 sha256;
    sha256.reset();
    sha256.update((const uint8_t *)password, strlen(password));
    sha256.update(salt, SALT_LEN);
    sha256.finalize(derivedKey, KEY_LEN);
  }

  // PKCS#7 pad the plaintext (block size 16)
  size_t paddedLen;
  uint8_t *paddedPlaintext = pkcs7Pad(plainData, infoLen, 16, paddedLen);

  // Encrypt using AES-256-CBC
  CBC<AES256> cbcEncrypt;
  cbcEncrypt.setKey(derivedKey, KEY_LEN);
  cbcEncrypt.setIV(iv, IV_LEN);

  uint8_t *ciphertext = (uint8_t *)malloc(paddedLen);
  cbcEncrypt.encrypt(ciphertext, paddedPlaintext, paddedLen);

  // Combine salt, IV, and ciphertext
  size_t totalLen = SALT_LEN + IV_LEN + paddedLen;
  uint8_t *combined = (uint8_t *)malloc(totalLen);
  memcpy(combined, salt, SALT_LEN);
  memcpy(combined + SALT_LEN, iv, IV_LEN);
  memcpy(combined + SALT_LEN + IV_LEN, ciphertext, paddedLen);

  String outHex = bytesToHex(combined, totalLen);

  free(paddedPlaintext);
  free(ciphertext);
  free(combined);

  return outHex;
}

String decryptData(const String &encryptedHex, const char *password)
{
  size_t totalLen = encryptedHex.length() / 2;
  uint8_t *combined = (uint8_t *)malloc(totalLen);
  hexToBytes(encryptedHex, combined, totalLen);

  // Extract salt, IV and ciphertext
  uint8_t salt[SALT_LEN], iv[IV_LEN];
  memcpy(salt, combined, SALT_LEN);
  memcpy(iv, combined + SALT_LEN, IV_LEN);
  size_t cipherLen = totalLen - SALT_LEN - IV_LEN;
  uint8_t *ciphertext = (uint8_t *)malloc(cipherLen);
  memcpy(ciphertext, combined + SALT_LEN + IV_LEN, cipherLen);
  free(combined);

  // Derive key
  uint8_t derivedKey[KEY_LEN];
  {
    SHA256 sha256;
    sha256.reset();
    sha256.update((const uint8_t *)password, strlen(password));
    sha256.update(salt, SALT_LEN);
    sha256.finalize(derivedKey, KEY_LEN);
  }

  // Decrypt using AES-256-CBC
  CBC<AES256> cbcDecrypt;
  cbcDecrypt.setKey(derivedKey, KEY_LEN);
  cbcDecrypt.setIV(iv, IV_LEN);
  uint8_t *decrypted = (uint8_t *)malloc(cipherLen);
  cbcDecrypt.decrypt(decrypted, ciphertext, cipherLen);
  free(ciphertext);

  // Remove PKCS#7 padding
  size_t unpaddedLen = pkcs7Unpad(decrypted, cipherLen, 16);

  String out = "";
  for (size_t i = 0; i < unpaddedLen; i++)
  {
    out += (char)decrypted[i];
  }
  free(decrypted);
  return out;
}

// Funcion to sign a unsigned solana transaction
std::tuple<String, String> signSolanaTransaction(const uint8_t *unsignedTx, size_t txLen,
                         const uint8_t *privateKey, const uint8_t *publicKey)
{
  // Generate a 64-byte Ed25519 signature
  uint8_t signature[64];
  Ed25519::sign(signature, unsignedTx, publicKey, privateKey, txLen);

  // Convert signature and public key to Base58 for return
  String signatureBase58 = base58Encode(signature, 64);
  String publicKeyBase58 = base58Encode(publicKey, 32);

  return std::make_tuple(signatureBase58, publicKeyBase58);
}

void setup()
{
  Serial.begin(115200);
  delay(500);
  Serial.println("Starting...");

  const char *passcode = "mySecretPassword";

  // Storage of keys
  prefs.begin("storage", false);
  String encSolPriv = prefs.getString("SolPriv", "");
  String encEthPriv = prefs.getString("EthPriv", "");
  String encSolPub = prefs.getString("SolPub", "");
  String encEthPub = prefs.getString("EthPub", "");
  String encSolCombined = prefs.getString("SolCombined", "");
  String encEthAddr = prefs.getString("EthAddr", "");
  
  String SolPriv = encSolPriv.length() > 0 ? decryptData(encSolPriv, passcode) : "";
  String EthPriv = encEthPriv.length() > 0 ? decryptData(encEthPriv, passcode) : "";
  String SolPub = encSolPub.length() > 0 ? decryptData(encSolPub, passcode) : "";
  String EthPub = encEthPub.length() > 0 ? decryptData(encEthPub, passcode) : "";
  String SolCombined = encSolCombined.length() > 0 ? decryptData(encSolCombined, passcode) : "";
  String EthAddr = encEthAddr.length() > 0 ? decryptData(encEthAddr, passcode) : "";

  if (SolPriv.length() > 0 && EthPriv.length() > 0)
  {
    Serial.print("Data found in NVS already: ");
    Serial.println(SolPriv);
    Serial.println(EthPriv);
    Serial.println(SolPub);
    Serial.println(EthPub);
    Serial.println(SolCombined);
    Serial.println(EthAddr);
  }
  else
  {

    // Variables to store keys
    String solPrivBase58, solPubBase58, solCombinedBase58;
    String ethPrivateKey, ethPublicKey, ethAddress;

    std::tie(solPrivBase58, solPubBase58, solCombinedBase58) = generateSolanaKeys();
    std::tie(ethPrivateKey, ethPublicKey, ethAddress) = generateEthereumKeys();

    // write the keys to NVS
    // Encrypt before storing
    String encryptedSolPriv = encryptData(solPrivBase58, passcode);
    String encryptedSolPub = encryptData(solPubBase58, passcode);
    String encryptedSolCombined = encryptData(solCombinedBase58, passcode);
    String encryptedEthPriv = encryptData(ethPrivateKey, passcode);
    String encryptedEthPub = encryptData(ethPublicKey, passcode);
    String encryptedEthAddr = encryptData(ethAddress, passcode);

    // Store encrypted values
    prefs.putString("SolPriv", encryptedSolPriv);
    prefs.putString("SolPub", encryptedSolPub);
    prefs.putString("SolCombined", encryptedSolCombined);
    prefs.putString("EthPriv", encryptedEthPriv); 
    prefs.putString("EthPub", encryptedEthPub);
    prefs.putString("EthAddr", encryptedEthAddr);

    Serial.println("Keys generated and stored in NVS");
  }
  prefs.end();
}

void loop()
{
  // // Command list codes
  // String sendSol = "1";
  // String sendEth = "2";
  // String ViewSolPub = "3";
  // String ViewEthPub = "4";

  // // Read command from Serial
  // String command = Serial.readStringUntil('\n');
  // command.trim();

  // // Check if the command is any of the above

  // if (command == sendSol) {
  //   // Send Solana keys
  // } else if (command == sendEth) {
  //   // Send Ethereum keys
  // } else if (command == ViewSolPub) {
  //   // View Solana public key
  // } else if (command == ViewEthPub) {
  //   // View Ethereum public key
  // } else {
  //   Serial.println("Invalid command");
  // }

  // read serial input
  if (Serial.available())
  {
    // Take the serial input and sign it with the solana private key
    char input = Serial.read();

    if (input == '1') {
      String tx = Serial.readStringUntil('\n');
      tx.trim();

      // Convert input from hex to bytes
      size_t inputLen = tx.length() / 2;
      uint8_t inputBytes[inputLen];
      hexToBytes(tx, inputBytes, inputLen);

      // Retrieve the Solana private key from NVS
      prefs.begin("storage", false);
      String encSolPriv = prefs.getString("SolPriv", "");
      String encSolPub = prefs.getString("SolPub", "");
      prefs.end();

      if (encSolPriv.length() == 0)
      {
        Serial.println("No Solana private key found in NVS.");
        return;
      }

      const char *passcode = "mySecretPassword";
      String solPrivBase58 = decryptData(encSolPriv, passcode);

      // Decode the Base58 private key back to bytes
      uint8_t solPrivateKey[32];
      base58Decode(solPrivBase58, solPrivateKey, 32);

      // Generate the corresponding public key
      String solPublicKey = decryptData(encSolPub, passcode);
      uint8_t solPubKey[32];
      base58Decode(solPublicKey, solPubKey, 32);

      Serial.println("Public Key (Base58): " + solPublicKey);

      // Sign the input data
      uint8_t signature[64];
      Ed25519::sign(signature, solPrivateKey, solPubKey, inputBytes, inputLen);

      // Convert the signature to Base58
      String signatureBase58 = base58Encode(signature, 64);

      // Output the signature
      Serial.println("Signature (Base58):" + signatureBase58);
    }
  }
}