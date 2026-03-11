#include "../include/cmd_options.h"
#include "crypto_guard_ctx.h"
#include <iostream>
#include <fstream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    CryptoGuard::ProgramOptions config;
    config.Parse(argc,argv);
    try {
        std::ifstream input(config.GetInputFile());
        std::ofstream output(config.GetOutputFile());

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (config.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            cryptoCtx.EncryptFile(input, output, config.GetPassword());
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            cryptoCtx.DecryptFile(input, output, config.GetPassword());
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}