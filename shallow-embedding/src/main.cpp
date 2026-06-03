#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "translator.hpp"

namespace fs = std::filesystem;

// ============================================================
// File I/O helpers
// ============================================================

static std::string trim(const std::string& s) {
    std::size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])))
        ++start;
    std::size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
        --end;
    return s.substr(start, end - start);
}

static bool is_comment_or_empty(const std::string& line) {
    const std::string t = trim(line);
    return t.empty() || t.rfind("//", 0) == 0 || t.rfind("#", 0) == 0;
}

static uint8_t parse_hex_byte(const std::string& token) {
    std::string t = token;
    if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
        t = t.substr(2);
    if (t.empty() || t.size() > 2)
        throw std::runtime_error("Invalid byte token: " + token);
    unsigned int value = 0;
    std::stringstream ss;
    ss << std::hex << t;
    ss >> value;
    if (ss.fail() || value > 0xFF)
        throw std::runtime_error("Invalid hex byte: " + token);
    return static_cast<uint8_t>(value);
}

static bpf_insn decode_insn_from_bytes(const std::array<uint8_t, 8>& bytes) {
    bpf_insn insn{};
    insn.code    = bytes[0];
    insn.dst_reg = bytes[1] & 0x0F;
    insn.src_reg = (bytes[1] >> 4) & 0x0F;
    insn.off     = static_cast<int16_t>(
        static_cast<uint16_t>(bytes[2]) |
        (static_cast<uint16_t>(bytes[3]) << 8));
    insn.imm     = static_cast<int32_t>(
        static_cast<uint32_t>(bytes[4]) |
        (static_cast<uint32_t>(bytes[5]) << 8) |
        (static_cast<uint32_t>(bytes[6]) << 16) |
        (static_cast<uint32_t>(bytes[7]) << 24));
    return insn;
}

static std::vector<bpf_insn> read_txt_bytecode(const std::string& path) {
    std::ifstream in(path);
    if (!in)
        throw std::runtime_error("Cannot open input file: " + path);
    std::vector<bpf_insn> program;
    std::string line;
    int line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        if (is_comment_or_empty(line)) continue;
        std::stringstream ss(line);
        std::vector<std::string> tokens;
        std::string tok;
        while (ss >> tok) tokens.push_back(tok);
        if (tokens.size() != 8)
            throw std::runtime_error(
                "Line " + std::to_string(line_no) +
                ": expected 8 hex bytes, got " + std::to_string(tokens.size()));
        std::array<uint8_t, 8> bytes{};
        for (std::size_t i = 0; i < 8; ++i)
            bytes[i] = parse_hex_byte(tokens[i]);
        program.push_back(decode_insn_from_bytes(bytes));
    }
    return program;
}

// ============================================================
// main()
// ============================================================

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <bytecode-file> [method-name]\n";
            return 1;
        }

        const fs::path input_path   = argv[1];
        const std::string method_name = (argc >= 3) ? argv[2] : "test";

        const auto program = read_txt_bytecode(input_path.string());

        // Delegate to the library function — no duplication of the
        // header/footer logic here.
        const std::string dafny = build_dafny_string(
            program.data(),
            static_cast<int>(program.size()),
            method_name, 0, 0 /*prog_type, attach_type*/);

        // Write to eBPF-spec/tests/<method_name>.dfy
        const fs::path output_dir  = fs::path("../tests");
        fs::create_directories(output_dir);
        const fs::path output_path = output_dir / (method_name + ".dfy");

        std::ofstream out(output_path);
        if (!out)
            throw std::runtime_error("Cannot open output file: " + output_path.string());
        out << dafny;
        std::cerr << "Generated " << output_path << "\n";

        std::cout << dafny;
        return 0;

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}