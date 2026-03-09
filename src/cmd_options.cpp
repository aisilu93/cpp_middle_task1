#include "cmd_options.h"
#include <boost/program_options/errors.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <print>

namespace po=boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help", "print options list")
        ("command", po::value<std::string>(),"Select command: encrypt, decrypt, checksum")
        ("input", po::value<std::string>())
        ("output", po::value<std::string>())
        ("password", po::value<std::string>());
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc,argv,desc_),vm);
        po::notify(vm);
        std::string error;
        if(vm.count("help")) {
            desc_.print(std::cout);
            return;
        }
        if(vm.count("command")) {
            std::string_view cmd=vm["command"].as<std::string>();
            if(cmd=="encrypt")      command_=COMMAND_TYPE::ENCRYPT;
            else if(cmd=="decrypt") command_=COMMAND_TYPE::DECRYPT;
            else if(cmd=="checksum")command_=COMMAND_TYPE::CHECKSUM;
            else error+="Unknown command\n";
        }
        else error+="No command detected\n";
        if(vm.count("input")) {
            inputFile_=std::move(vm["input"].as<std::string>());
            if(inputFile_.empty()) error+="Input path is empty\n";
        }
        else error+="Input is empty\n";
        if(vm.count("output")) {
            outputFile_=std::move(vm["output"].as<std::string>());
            if(outputFile_.empty()) error+="Output path is empty\n";
        }
        else error+="Output is empty\n";
        if(vm.count("password")) {
            password_=std::move(vm["password"].as<std::string>());
        }
        else {
            if(command_!=COMMAND_TYPE::CHECKSUM)
                error+="Password is required\n";
        }
        if(!error.empty()) throw po::error(error);
    }
    catch(po::error const &e) {
        std::print("{}",e.what());
    }
}

}  // namespace CryptoGuard
