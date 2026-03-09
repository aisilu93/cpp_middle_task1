#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include "../include/cmd_options.h"

TEST(ProgramOptions,HelpPrintOptions){
    CryptoGuard::ProgramOptions options;
    char* my_argv[] = {"app","--help"};
    int my_argc=2;
    std::ostringstream output;
    auto *old_cout=std::cout.rdbuf(output.rdbuf());
    EXPECT_NO_THROW(options.Parse(my_argc,my_argv));
    std::cout.rdbuf(old_cout);
    std::string help_str(output.str().c_str());
    EXPECT_NE(help_str.find("print options list"),std::string::npos);
}

TEST(ProgramOptions,ParseUnknownCmdError){
    CryptoGuard::ProgramOptions options;
    char* my_argv[] = {"app","--command","unknown"};
    int my_argc=3;
    std::ostringstream output;
    auto *old_cout=std::cout.rdbuf(output.rdbuf());
    EXPECT_NO_THROW(options.Parse(my_argc,my_argv));
    std::cout.rdbuf(old_cout);
    std::string error_str(output.str().c_str());
    EXPECT_NE(error_str.find("Unknown command"),std::string::npos);
}

TEST(ProgramOptions,ParseNotAllParamsError){
    CryptoGuard::ProgramOptions options;
    char* my_argv[] = {"app"};
    int my_argc=1;
    std::ostringstream output;
    auto *old_cout=std::cout.rdbuf(output.rdbuf());
    EXPECT_NO_THROW(options.Parse(my_argc,my_argv));
    std::cout.rdbuf(old_cout);
    std::string error_str(output.str().c_str());
    EXPECT_NE(error_str.find("No command detected"),std::string::npos);
    EXPECT_NE(error_str.find("Input is empty"),std::string::npos);
    EXPECT_NE(error_str.find("Output is empty"),std::string::npos);
    EXPECT_NE(error_str.find("Password is required"),std::string::npos);
}

TEST(ProgramOptions,ParseChecksumNotRequirePass){
    CryptoGuard::ProgramOptions options;
    char* my_argv[] = {"app", "--command","checksum"};
    int my_argc=3;
    std::ostringstream output;
    auto *old_cout=std::cout.rdbuf(output.rdbuf());
    EXPECT_NO_THROW(options.Parse(my_argc,my_argv));
    std::cout.rdbuf(old_cout);
    std::string error_str(output.str().c_str());
    EXPECT_TRUE(error_str.find("Password is required")==std::string::npos);
}

TEST(ProgramOptions,ParseEmptyInputError){
    CryptoGuard::ProgramOptions options;
    char* my_argv[] = {"app", "--command","encrypt","--input","--output","test","--password","test"};
    int my_argc=7;
    std::ostringstream output;
    auto *old_cout=std::cout.rdbuf(output.rdbuf());
    EXPECT_NO_THROW(options.Parse(my_argc,my_argv));
    std::cout.rdbuf(old_cout);
    std::string error_str(output.str().c_str());
    EXPECT_TRUE(error_str.find("Input path is empty")==std::string::npos);
}

TEST(ProgramOptions,ParseEmptyOutputError){
    CryptoGuard::ProgramOptions options;
    char* my_argv[] = {"app", "--command","encrypt","--input","test","--output","--password","test"};
    int my_argc=7;
    std::ostringstream output;
    auto *old_cout=std::cout.rdbuf(output.rdbuf());
    EXPECT_NO_THROW(options.Parse(my_argc,my_argv));
    std::cout.rdbuf(old_cout);
    std::string error_str(output.str().c_str());
    EXPECT_TRUE(error_str.find("Output path is empty")==std::string::npos);
}