#include "crypto_guard_ctx.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <array>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <print>
#include <sstream>
#include <iomanip>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl final {
public:
    Impl()  { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }
    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        if(!inStream || !outStream) return;
        DoCrypt(true,inStream,outStream,password); 
    }

    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        if(!inStream || !outStream) return;
        DoCrypt(false,inStream,outStream,password);    
    }

    std::string CalculateChecksum(std::istream &inStream) {
        if(!inStream) return "";
        std::stringstream res;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len,i;
        auto d=[](EVP_MD_CTX *ptr){ EVP_MD_CTX_free(ptr); };
        try {
            std::unique_ptr<EVP_MD_CTX,decltype(d)> ctx(EVP_MD_CTX_new(),d);
            if(!ctx.get()) {
                throw std::runtime_error("Message digest create failed.\n");
            }
            const EVP_MD *md=EVP_get_digestbyname("SHA256");
            if(!md) {
                throw std::runtime_error("Unknown message digest.\n");
            }
            if(!EVP_DigestInit_ex2(ctx.get(),md,NULL)) {
                throw std::runtime_error("Message digest initialization failed.\n");
            }
            std::vector<unsigned char> inBuf(16);
            std::vector<char> input(16);
            int len=0;
            for(;;) {
                inStream.read(&input[0],16);
                len=static_cast<int>(inStream.gcount());
                if(len<=0) break;
                std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
                if(!EVP_DigestUpdate(ctx.get(),&input[0],len)) {
                    throw std::runtime_error("Message digest update failed.\n");
                }
            }
            if(!EVP_DigestFinal_ex(ctx.get(),md_value,&md_len)) {
                throw std::runtime_error("Message digest finalization failed.\n");
            }
            for(i=0;i<md_len;i++) {
                res<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<int>(md_value[i]);
            }
        }
        catch(std::runtime_error e) {
            PrintRuntimeErrors(e);
        }
        return(res.str());
    }

    void DoCrypt(bool encrypt,std::istream &inStream, std::ostream &outStream, std::string_view password){
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = encrypt?1:0;
        auto d=[](EVP_CIPHER_CTX *ptr){EVP_CIPHER_CTX_free(ptr);};
        try {
            std::unique_ptr<EVP_CIPHER_CTX,decltype(d)> ctx(EVP_CIPHER_CTX_new(),d);
            if(!ctx.get()) {
                throw std::runtime_error("Cipher context create failed.\n");
            }
            // Инициализируем cipher
            if(EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr,
                            params.key.data(), params.iv.data(), params.encrypt)!=1) {
                throw std::runtime_error("Cipher init failed.\n");
            }

            std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
            std::vector<unsigned char> inBuf(16);
            std::vector<char> input(16);
            std::string output;
            int outLen=0;

            for(;;) {
                inStream.read(&input[0],16);
                outLen=static_cast<int>(inStream.gcount());
                if(outLen<=0) break;
                std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
                if(EVP_CipherUpdate(ctx.get(),outBuf.data(), &outLen, 
                                inBuf.data(), static_cast<int>(16))!=1) {
                    throw std::runtime_error("Cipher update failed.\n");
                }
                for (int i = 0; i < outLen; ++i) {
                    output.push_back(outBuf[i]);
                }
            }

            // Заканчиваем работу с cipher
            if(EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)!=1) {
                throw std::runtime_error("Cipher finalize filed.\n");
            }
            for (int i = 0; i < outLen; ++i) {
                output.push_back(outBuf[i]);
            }
            std::print("String {} successfully. Result: '{}'\n\n", params.encrypt==1?"encrypted":"decrypted",output);
            outStream.write(&output[0],output.size());
        }
        catch(std::runtime_error &e) {
            PrintRuntimeErrors(e);
        }
    }

    void PrintRuntimeErrors(std::runtime_error &e) {
        std::print("{}",e.what());
        int errcode=ERR_get_error();
        char errstr[256]={0};
        while(errcode!=0) {
            std::print("OpenSSL error: {}",ERR_error_string(errcode, errstr));
            errcode=ERR_get_error();
        }
    }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx(): pImpl_(std::make_unique<Impl>()) {
}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password){
    pImpl_->EncryptFile(inStream,outStream,password);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password){
    pImpl_->DecryptFile(inStream,outStream,password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream){
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard

