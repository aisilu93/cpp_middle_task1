#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

TEST(CryptoGuardCtx,ChecksumQwerty) {
    std::stringstream input("qwerty");
    std::string result;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(result=ctx.CalculateChecksum(input));
    EXPECT_NE(result.find("65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5"),std::string::npos);
}

TEST(CryptoGuardCtx,ChecksumEmptyStr) {
    std::stringstream input("");
    std::string result;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(result=ctx.CalculateChecksum(input));
    EXPECT_NE(result.find(""),std::string::npos);
}

TEST(CryptoGuardCtx,ChecksumNumbers) {
    std::stringstream input("1234567890");
    std::string result;
    CryptoGuard::CryptoGuardCtx ctx;
    EXPECT_NO_THROW(result=ctx.CalculateChecksum(input));
    EXPECT_NE(result.find("c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646"),std::string::npos);
}
