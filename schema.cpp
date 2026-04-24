
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
// Header Files
//----------------------------------------------------------------------------------

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <deque>
#include <string>
#include <utility>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <cctype>
#include <bitset>
#include <fstream>
#include <limits>

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
// Global Constants
//----------------------------------------------------------------------------------

std::string fileName = "XORedCompressedData.txt";

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SystemClock {
  public:
    inline long long getNanoseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    }
};

// Global Instance
inline SystemClock systemClock;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Functions {
  public:
    // ----------------------------
    // UNUSED (KEEP IF NEEDED)
    // ----------------------------
    std::string stringToBinaryASCII(const std::string &input) {
        std::string binary;
        binary.reserve(input.size() * 8);

        for (char c : input) {
            std::bitset<8> bits(static_cast<unsigned char>(c));
            binary += bits.to_string();
        }

        while ((binary.size() & (binary.size() - 1)) != 0) {
            binary.push_back('0');
        }

        return binary;
    }

    std::string binaryASCIIToString(const std::string &binary) {
        if (binary.size() % 8 != 0) {
            throw std::runtime_error("Binary length must be multiple of 8");
        }

        std::string output;
        output.reserve(binary.size() / 8);

        for (size_t i = 0; i < binary.size(); i += 8) {
            std::bitset<8> bits(binary.substr(i, 8));
            output.push_back(static_cast<char>(bits.to_ulong()));
        }

        return output;
    }
};

inline Functions functions;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace CRYPTO {
class SHA256 {
  public:
    SHA256() { reset(); }

    void update(const uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[bufferLen++] = data[i];
            if (bufferLen == 64) {
                transform(buffer);
                bitlen += 512;
                bufferLen = 0;
            }
        }
    }

    void update(const std::string &data) { update(reinterpret_cast<const uint8_t *>(data.c_str()), data.size()); }

    std::string digest() {
        uint64_t totalBits = bitlen + bufferLen * 8;

        buffer[bufferLen++] = 0x80;
        if (bufferLen > 56) {
            while (bufferLen < 64)
                buffer[bufferLen++] = 0x00;
            transform(buffer);
            bufferLen = 0;
        }

        while (bufferLen < 56)
            buffer[bufferLen++] = 0x00;

        for (int i = 7; i >= 0; --i)
            buffer[bufferLen++] = (totalBits >> (i * 8)) & 0xFF;

        transform(buffer);

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i)
            oss << std::hex << std::setw(8) << std::setfill('0') << h[i];

        reset(); // reset internal state after digest
        return oss.str();
    }

    std::string digestBinary() {
        std::string hex = digest();
        std::string binary;
        for (char c : hex) {
            uint8_t val = (c <= '9') ? c - '0' : 10 + (std::tolower(c) - 'a');
            for (int i = 3; i >= 0; --i)
                binary += ((val >> i) & 1) ? '1' : '0';
        }
        return binary;
    }

    void reset() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        bitlen = 0;
        bufferLen = 0;
    }

  private:
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferLen;

    void transform(const uint8_t block[64]) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_val = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h_val + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t temp2 = sig0(a) + majority(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    const uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                            0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                            0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
};
} // namespace CRYPTO

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class RandomNumberGenerator {
  public:
    inline std::string run() {
        std::string result;
        result.reserve((totalIterations - localBufferSize) * 256);

        for (int i = 0; i < totalIterations; ++i) {

            long long duration = countdown();
            ++count;
            globalSum += duration;
            globalAvg = globalSum / count;

            int bit = duration < globalAvg ? 0 : 1;

            if (localBits.size() >= localBufferSize)
                localBits.pop_front();

            localBits.push_back(bit);

            if (localBits.size() == localBufferSize) {
                // 32 raw bytes → 256 bit string
                std::string hashBits = hashLocalBits();
                result += hashBits;
            }
        }

        return result;
    }

  private:
    CRYPTO::SHA256 sha;
    std::deque<int> localBits;
    const int totalIterations = 1000;
    const size_t localBufferSize = 512;
    long long globalSum = 0;
    long long globalAvg = 0;
    int count = 0;

    inline long long countdown() {
        int x = 10;
        auto start = systemClock.getNanoseconds();
        while (x > 0)
            x--;
        auto end = systemClock.getNanoseconds();
        return end - start;
    }

    inline std::string hashLocalBits() {
        // Build 64-byte block
        uint8_t bytes[64] = {0};
        for (size_t i = 0; i < localBits.size(); ++i) {
            if (localBits[i]) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        sha.update(bytes, 64);

        // Return 256-bit binary string using fast helper
        return sha.digestBinary();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BinaryEntropyPool {
  public:
    inline std::string get(size_t bitsNeeded) {
        std::lock_guard<std::mutex> lock(poolMutex);

        // Refill the pool until we have enough bits
        while (bitPool.size() < bitsNeeded) {
            bitPool += rng.run(); // rng.run() now returns a bit string
        }

        // Extract exactly the number of bits requested
        std::string result = bitPool.substr(0, bitsNeeded);
        bitPool.erase(0, bitsNeeded); // remove consumed bits

        return result;
    }

  private:
    std::string bitPool; // bit string directly
    RandomNumberGenerator rng;
    mutable std::mutex poolMutex;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class XORCompress {
  public:
    struct Result {
        std::string final;
        std::vector<std::string> keys;
        std::vector<std::string> xoredLayers;
        std::size_t layers;
    };

    inline Result compress(std::string data) {
        if (data.empty() || (data.size() & (data.size() - 1)) != 0) {
            throw std::runtime_error("Size must be a power of 2");
        }

        std::vector<std::string> keys;
        std::vector<std::string> xoredLayers;

        std::size_t layers = 0;

        while (data.size() > 1) {
            std::string xored;
            std::string key;

            xored.reserve(data.size() / 2);
            key.reserve(data.size() / 2);

            for (std::size_t i = 0; i < data.size(); i += 2) {
                char A = data[i];
                char B = data[i + 1];

                if ((A != '0' && A != '1') || (B != '0' && B != '1')) {
                    throw std::runtime_error("Invalid bit");
                }

                xored.push_back(A == B ? '0' : '1');
                key.push_back(A);
            }

            xoredLayers.push_back(xored);
            keys.push_back(key);

            // IMPORTANT: you chose key-as-next-state
            data = key;

            ++layers;
        }

        return {data, keys, xoredLayers, layers};
    }

    inline std::string decompress(const Result &result) {
        if (result.keys.size() != result.xoredLayers.size()) {
            throw std::runtime_error("Invalid structure");
        }

        std::string data = result.final;

        // rebuild backwards
        for (int level = (int)result.layers - 1; level >= 0; --level) {
            const std::string &key = result.keys[level];
            const std::string &xored = result.xoredLayers[level];

            std::string prev;
            prev.reserve(key.size() * 2);

            for (std::size_t i = 0; i < key.size(); ++i) {
                char K = key[i];
                char R = xored[i];

                if ((K != '0' && K != '1') || (R != '0' && R != '1')) {
                    throw std::runtime_error("Invalid bit");
                }

                char A = K;
                char B = (K == R ? '0' : '1');

                prev.push_back(A);
                prev.push_back(B);
            }

            data = prev;
        }

        return data;
    }

    std::string decompressFromFile(std::size_t layers, const std::string &final, const std::string &lastKey) {
        std::string data = final;

        for (int level = (int)layers - 1; level >= 0; --level) {

            std::string prev;
            prev.reserve(lastKey.size() * 2);

            for (char K : lastKey) {
                char A = K;
                char B = (K == '0') ? '1' : '0'; // deterministic guess

                prev.push_back(A);
                prev.push_back(B);
            }

            data = prev;
        }

        return data;
    }

    inline void writeToFile(const std::string &filename, const XORCompress::Result &r) {
        std::ofstream out(filename);
        if (!out)
            throw std::runtime_error("Failed to open file");

        out << "-----\nFINAL\n" << r.final << "\n";
        out << "-----\nLAYERS\n" << r.layers << "\n";

        out << "-----\nKEYS\n";
        for (const auto &k : r.keys)
            out << k << "\n";

        out << "-----\nXOR\n";
        for (const auto &x : r.xoredLayers)
            out << x << "\n";

        out << "-----\n";
    }

    inline XORCompress::Result readFromFile(const std::string &filename) {
        std::ifstream in(filename);
        if (!in)
            throw std::runtime_error("Failed to open file");

        XORCompress::Result r;

        std::string line;

        auto nextNonDash = [&]() {
            while (std::getline(in, line)) {
                if (line.find("-----") == std::string::npos)
                    return true;
            }
            return false;
        };

        // ---------------- FINAL ----------------
        nextNonDash(); // FINAL
        std::getline(in, r.final);

        // ---------------- LAYERS ----------------
        nextNonDash(); // LAYERS
        std::getline(in, line);
        r.layers = std::stoull(line);

        // ---------------- KEYS ----------------
        nextNonDash(); // KEYS
        while (std::getline(in, line) && line.find("-----") == std::string::npos) {
            if (!line.empty())
                r.keys.push_back(line);
        }

        // ---------------- XOR ----------------
        nextNonDash(); // XOR
        while (std::getline(in, line) && line.find("-----") == std::string::npos) {
            if (!line.empty())
                r.xoredLayers.push_back(line);
        }

        // ---------------- VALIDATION ----------------
        if (r.final.empty())
            throw std::runtime_error("Missing final");

        if (r.layers == 0)
            throw std::runtime_error("Missing layers");

        if (r.keys.size() != r.xoredLayers.size())
            throw std::runtime_error("Corrupt file");

        return r;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class UserInterface {
  public:
    void run() {
        std::cout << "Welcome to the Program...\n";
        std::cout << "\nPress Enter to continue...\n";
        std::cin.get();

        try {
            std::string input = bep.get(64);
            std::cout << "bitstream: " << input << "\n\n";

            if (!askYesNo("Do you want to compress the data? (y/n): ")) {
                std::cout << "Compression skipped.\n";
                return;
            }

            std::cout << "Compressing...\n";

            result = compressor.compress(input);

            compress(result);
            output(result);

            if (!askYesNo("\nDo you want to decompress the data? (y/n): ")) {
                std::cout << "Decompression skipped.\n";
                return;
            }

            decompress(input);

        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << "\n";
        }

        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }

  private:
    XORCompress compressor;
    BinaryEntropyPool bep;

    XORCompress::Result result;
    std::string fileName = "XORedCompressedData.txt";

    bool askYesNo(const std::string &msg) {
        std::cout << msg;

        char choice{};
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        return (choice == 'y' || choice == 'Y');
    }

    // ----------------------------
    void compress(const XORCompress::Result &result) {
        std::cout << "\nWriting compressed data to file...\n";

        if (result.final.size() != 1) {
            throw std::runtime_error("Final is not 1 bit!");
        }

        compressor.writeToFile(fileName, result);

        std::cout << "File written: " << fileName << "\n";
    }

    // ----------------------------
    void decompress(const std::string &input) {
        std::cout << "\nReading compressed file...\n";

        XORCompress::Result result = compressor.readFromFile(fileName);

        std::cout << "Read Layers: " << result.layers << "\n";
        std::cout << "Read Final: " << result.final << "\n";

        std::cout << "\nReconstructing from file...\n";

        std::string restored = compressor.decompress(result);

        std::cout << "Restored: " << restored << "\n";

        if (restored == input) {
            std::cout << "SUCCESS\n";
        } else {
            std::cout << "FAIL\n";
        }
    }

    void output(const XORCompress::Result &result) {
        std::cout << "Final bit: " << result.final << "\n";
        std::cout << "Layers: " << result.layers << "\n";

        std::cout << "\nKeys:\n";
        for (size_t i = 0; i < result.keys.size(); ++i) {
            std::cout << "Layer " << i << ": " << result.keys[i] << "\n";
        }

        std::cout << "\nXored layers:\n";
        for (size_t i = 0; i < result.xoredLayers.size(); ++i) {
            std::cout << "Layer " << i << ": " << result.xoredLayers[i] << "\n";
        }
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

int main() {
    UserInterface ui;
    ui.run();

    return 0;
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
