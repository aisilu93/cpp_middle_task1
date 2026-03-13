#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

TEST(CryptoGuardCtx,ChecksumQwerty) {
    std::stringstream input("qwerty");
    std::string result;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(result=ctx.CalculateChecksum(input));
    EXPECT_EQ(result,"65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5");
}

TEST(CryptoGuardCtx,ChecksumBadInput) {
    std::stringstream input;
    input.setstate(std::ios::badbit);
    std::string result;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(result=ctx.CalculateChecksum(input));
    EXPECT_EQ(result,"");
}

TEST(CryptoGuardCtx,ChecksumNumbers) {
    std::stringstream input("1234567890");
    std::string result;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(result=ctx.CalculateChecksum(input));
    EXPECT_EQ(result,"c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646");
}

TEST(CryptoGuardCtx,EncryptNoPassDecryptPass) {
    std::stringstream input("qwerty");
    std::stringstream inoutput;
    std::stringstream output;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(ctx.EncryptFile(input,inoutput,""));
    EXPECT_NO_THROW(ctx.DecryptFile(inoutput,output,"123"));
    input.clear();
    input.seekg(0);
    EXPECT_NE(input.str(),output.str());
}
    
TEST(CryptoGuardCtx,EncryptPassDecryptNoPass) {
    std::stringstream input("qwerty");
    std::stringstream inoutput;
    std::stringstream output;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(ctx.EncryptFile(input,inoutput,"123"));
    EXPECT_NO_THROW(ctx.DecryptFile(inoutput,output,""));
    input.clear();
    input.seekg(0);
    EXPECT_NE(input.str(),output.str());
}

TEST(CryptoGuardCtx,EncryptDecrypt) {
    std::stringstream input("qwerty");
    std::stringstream inoutput;
    std::stringstream output;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(ctx.EncryptFile(input,inoutput,"123"));
    EXPECT_NO_THROW(ctx.DecryptFile(inoutput,output,"123"));
    input.clear();
    input.seekg(0);
    EXPECT_EQ(ctx.CalculateChecksum(input),ctx.CalculateChecksum(output));
}

