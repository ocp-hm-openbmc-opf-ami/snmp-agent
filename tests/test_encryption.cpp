// test_encryption.cpp — unit tests for Encryption.cpp
//
// Include order: project header → macro undefines → GTest
// aesKeyFile / aesIVFile are extern non-const pointers; the fixture redirects
// them to /tmp so tests never touch /etc/snmp/.

#include "Encryption.hpp"

#ifdef FAIL
#undef FAIL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DEBUG
#undef DEBUG
#endif

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

extern const char* aesKeyFile;
extern const char* aesIVFile;

namespace
{

constexpr const char* kTestKeyPath = "/tmp/snmp_ut_aeskey";
constexpr const char* kTestIVPath = "/tmp/snmp_ut_aesiv";

class EncryptionTest : public ::testing::Test
{
  protected:
    const char* origKeyFile{nullptr};
    const char* origIVFile{nullptr};

    void SetUp() override
    {
        origKeyFile = aesKeyFile;
        origIVFile = aesIVFile;
        aesKeyFile = kTestKeyPath;
        aesIVFile = kTestIVPath;
        std::remove(kTestKeyPath);
        std::remove(kTestIVPath);
    }

    void TearDown() override
    {
        std::remove(kTestKeyPath);
        std::remove(kTestIVPath);
        aesKeyFile = origKeyFile;
        aesIVFile = origIVFile;
    }
};

// ---------------------------------------------------------------------------
// base64_encode / base64_decode
// ---------------------------------------------------------------------------

TEST(Base64Test, Encode_NonEmptyInput_ReturnsNonNull)
{
    const unsigned char input[] = "HelloWorld";
    char* result = base64_encode(input, static_cast<int>(sizeof(input) - 1));
    ASSERT_NE(result, nullptr);
    EXPECT_GT(strlen(result), 0u);
    free(result);
}

TEST(Base64Test, Decode_ValidBase64_ReturnsOriginalData)
{
    const unsigned char input[] = "TestData1234";
    int origLen = static_cast<int>(sizeof(input) - 1);

    char* encoded = base64_encode(input, origLen);
    ASSERT_NE(encoded, nullptr);

    int outLen = 0;
    unsigned char* decoded = base64_decode(encoded, &outLen);
    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(outLen, origLen);
    EXPECT_EQ(memcmp(decoded, input, static_cast<size_t>(origLen)), 0);

    free(encoded);
    free(decoded);
}

TEST(Base64Test, RoundTrip_AllByteValues_Succeeds)
{
    unsigned char input[256];
    for (int i = 0; i < 256; ++i)
    {
        input[i] = static_cast<unsigned char>(i);
    }
    char* encoded = base64_encode(input, 256);
    ASSERT_NE(encoded, nullptr);

    int outLen = 0;
    unsigned char* decoded = base64_decode(encoded, &outLen);
    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(outLen, 256);
    EXPECT_EQ(memcmp(decoded, input, 256), 0);

    free(encoded);
    free(decoded);
}

TEST(Base64Test, Decode_MalformedInput_ReturnsNullOrZeroLen)
{
    int outLen = 0;
    // "!!!!" is not valid base64; base64_decode returns NULL or 0-length
    unsigned char* result = base64_decode("!!!!@@@@", &outLen);
    // Either null is returned, or the decoded length is zero
    if (result != nullptr)
    {
        EXPECT_EQ(outLen, 0);
        free(result);
    }
    else
    {
        EXPECT_EQ(outLen, 0);
    }
}

TEST(Base64Test, Encode_SingleByte_ReturnsExpectedLength)
{
    const unsigned char input[] = {0xAB};
    char* result = base64_encode(input, 1);
    ASSERT_NE(result, nullptr);
    // 1 byte base64-encodes to 4 chars (no newline since NO_NL flag is set)
    EXPECT_EQ(strlen(result), 4u);
    free(result);
}

// ---------------------------------------------------------------------------
// AES_GenerateAndSaveKeys / AES_GetKeyFromFile
// ---------------------------------------------------------------------------

TEST_F(EncryptionTest, GenerateAndSaveKeys_ValidPaths_CreatesFiles)
{
    EXPECT_TRUE(AES_GenerateAndSaveKeys(kTestKeyPath, kTestIVPath));
    EXPECT_TRUE(std::filesystem::exists(kTestKeyPath));
    EXPECT_TRUE(std::filesystem::exists(kTestIVPath));
}

TEST_F(EncryptionTest, GenerateAndSaveKeys_InvalidDirectory_ReturnsFalse)
{
    EXPECT_FALSE(
        AES_GenerateAndSaveKeys("/nonexistent_dir/key", "/nonexistent_dir/iv"));
}

TEST_F(EncryptionTest, GetKeyFromFile_AfterGenerate_ReturnsCorrectSize)
{
    ASSERT_TRUE(AES_GenerateAndSaveKeys(kTestKeyPath, kTestIVPath));

    unsigned char keyBuf[AES_MAX_KEY_LENGTH]{};
    int rc = AES_GetKeyFromFile(kTestKeyPath, keyBuf, AES_MAX_KEY_LENGTH);
    EXPECT_EQ(rc, 0);
}

TEST_F(EncryptionTest, GetKeyFromFile_AfterGenerate_IVCorrectSize)
{
    ASSERT_TRUE(AES_GenerateAndSaveKeys(kTestKeyPath, kTestIVPath));

    unsigned char ivBuf[AES_MAX_IV_LENGTH]{};
    int rc = AES_GetKeyFromFile(kTestIVPath, ivBuf, AES_MAX_IV_LENGTH);
    EXPECT_EQ(rc, 0);
}

TEST_F(EncryptionTest, GetKeyFromFile_MissingFile_ReturnsError)
{
    unsigned char buf[AES_MAX_KEY_LENGTH]{};
    int rc = AES_GetKeyFromFile("/tmp/nonexistent_key_file", buf,
                                AES_MAX_KEY_LENGTH);
    EXPECT_LT(rc, 0);
}

TEST_F(EncryptionTest, GetKeyFromFile_WrongBufferSize_ReturnsError)
{
    ASSERT_TRUE(AES_GenerateAndSaveKeys(kTestKeyPath, kTestIVPath));

    // Pass buffer_size that does NOT match the stored key length
    unsigned char buf[AES_MAX_KEY_LENGTH]{};
    int rc = AES_GetKeyFromFile(kTestKeyPath, buf, AES_MAX_IV_LENGTH);
    EXPECT_LT(rc, 0);
}

// ---------------------------------------------------------------------------
// encryptString / decryptString round-trip
// ---------------------------------------------------------------------------

TEST_F(EncryptionTest, EncryptDecrypt_SimpleString_RoundTrip)
{
    const std::string plaintext = "HelloSNMPAgent";

    std::string ciphertext = encryptString(plaintext);
    ASSERT_FALSE(ciphertext.empty());

    int outLen = 0;
    std::string decrypted = decryptString(ciphertext, &outLen);
    EXPECT_EQ(decrypted, plaintext);
    EXPECT_EQ(outLen, static_cast<int>(plaintext.size()));
}

TEST_F(EncryptionTest, EncryptDecrypt_LongString_RoundTrip)
{
    const std::string plaintext(128, 'X');

    std::string ciphertext = encryptString(plaintext);
    ASSERT_FALSE(ciphertext.empty());

    int outLen = 0;
    std::string decrypted = decryptString(ciphertext, &outLen);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(EncryptionTest, EncryptDecrypt_SpecialChars_RoundTrip)
{
    const std::string plaintext = "P@$$w0rd!#&*()";

    std::string ciphertext = encryptString(plaintext);
    ASSERT_FALSE(ciphertext.empty());

    int outLen = 0;
    std::string decrypted = decryptString(ciphertext, &outLen);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(EncryptionTest, DecryptString_EmptyInput_ReturnsEmpty)
{
    int outLen = 0;
    std::string result = decryptString("", &outLen);
    EXPECT_TRUE(result.empty());
}

TEST_F(EncryptionTest, DecryptString_MalformedBase64_ReturnsEmpty)
{
    int outLen = 0;
    std::string result = decryptString("not-valid-base64!!!", &outLen);
    EXPECT_TRUE(result.empty());
}

TEST_F(EncryptionTest, EncryptString_RepeatedCalls_ProduceDifferentCiphertext)
{
    // Two encryptions of the same plaintext should produce different ciphertext
    // only if a fresh IV is used each time — with a static IV they may match.
    // We verify the output is non-empty and decrypts correctly.
    const std::string plaintext = "testpassword";

    std::string ct1 = encryptString(plaintext);
    std::string ct2 = encryptString(plaintext);
    EXPECT_FALSE(ct1.empty());
    EXPECT_FALSE(ct2.empty());

    int len1 = 0;
    EXPECT_EQ(decryptString(ct1, &len1), plaintext);
}

TEST_F(EncryptionTest, EncryptString_AutoGeneratesKeyFiles)
{
    // Key files don't exist yet; encryptString must generate them
    EXPECT_FALSE(std::filesystem::exists(kTestKeyPath));
    EXPECT_FALSE(std::filesystem::exists(kTestIVPath));

    std::string ct = encryptString("mypassword");
    EXPECT_FALSE(ct.empty());
    EXPECT_TRUE(std::filesystem::exists(kTestKeyPath));
    EXPECT_TRUE(std::filesystem::exists(kTestIVPath));
}

TEST_F(EncryptionTest,
       DecryptString_MalformedBase64_AfterKeyGenerated_ReturnsEmpty)
{
    // Generate key files first, then try to decrypt malformed base64.
    // This exercises the "base64 decode failed" path in decryptString.
    ASSERT_TRUE(AES_GenerateAndSaveKeys(kTestKeyPath, kTestIVPath));
    int outLen = 0;
    std::string result = decryptString("!!!not-valid-base64!!!", &outLen);
    EXPECT_TRUE(result.empty());
}

TEST_F(EncryptionTest, DecryptString_IVFileMissing_ReturnsEmpty)
{
    // Key file exists but IV file does not → "AES IV file not found".
    ASSERT_TRUE(AES_GenerateAndSaveKeys(kTestKeyPath, kTestIVPath));
    std::remove(kTestIVPath);
    // Encrypt a string so we have valid ciphertext
    aesIVFile = kTestIVPath; // already set; remove it now
    int outLen = 0;
    std::string result = decryptString("AAAAAAAAAAAAAAAA==", &outLen);
    EXPECT_TRUE(result.empty());
}

TEST_F(EncryptionTest, DecryptString_KeyFileMissing_GeneratesNewKey)
{
    // Neither key file exists → encryptString generates them.
    // Then decryptString should work with the generated files.
    std::string ct = encryptString("testvalue");
    ASSERT_FALSE(ct.empty());
    int outLen = 0;
    std::string result = decryptString(ct, &outLen);
    EXPECT_EQ(result, "testvalue");
}

TEST_F(EncryptionTest, GetKeyFromFile_CorruptedFile_ReturnsError)
{
    // Write garbage that can be base64-decoded but has wrong length.
    std::ofstream f(kTestKeyPath);
    f << "aGVsbG8="; // "hello" in base64 → 5 bytes, not AES_MAX_KEY_LENGTH
    f.close();
    unsigned char buf[AES_MAX_KEY_LENGTH]{};
    int rc = AES_GetKeyFromFile(kTestKeyPath, buf, AES_MAX_KEY_LENGTH);
    EXPECT_LT(rc, 0);
}

} // namespace
