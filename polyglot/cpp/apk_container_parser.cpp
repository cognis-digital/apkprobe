// polyglot/cpp/apk_container_parser.cpp
// Android APK container parser — MASTG-aligned, binary-AXML decoder, zero dependencies

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>

// ============ Constants ============

constexpr uint32_t ZIP_LOCAL_FILE_HEADER_SIG = 0x04034b50;
constexpr uint32_t ZIP_CENTRAL_DIR_SIG      = 0x02014b50;
constexpr uint32_t ZIP_END_CENTRAL_DIR_SIG   = 0x06054b50;

constexpr uint16_t AXML_BYTE_ORDER_BIG       = 0x4D58; // "MX"
constexpr uint16_t AXML_BYTE_ORDER_LITTLE    = 0x584D; // "XM"

// ============ Utility Types ============

struct ZipEntry {
    std::string name;
    uint32_t compressionMethod;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t crc32;
};

// ============ Binary-AXML Decoder ============

class AxmlDecoder {
public:
    // Decode a single AXML element, returns true if more elements follow
    static bool decodeElement(const char* data, size_t len, 
                              std::string& name,
                              std::vector<std::pair<std::string, std::string>>& attrs) {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
        
        // Check byte order (first two bytes are magic number)
        uint16_t magic = *reinterpret_cast<const uint16_t*>(ptr);
        if (magic == AXML_BYTE_ORDER_BIG || magic == AXML_BYTE_ORDER_LITTLE) {
            ptr += 2; // Skip magic
        } else {
            return false;
    }

        // Read element name
        int32_t nameLen = *reinterpret_cast<const int32_t*>(ptr);
        ptr += 4;
        
        if (nameLen < 0) {
            // Negative length means end of document
            return false;
        }

        std::string elemName;
        for (int i = 0; i < nameLen; ++i) {
            elemName += static_cast<char>(ptr[i]);
        }
        ptr += nameLen;

        // Read attributes
        while (*reinterpret_cast<const int32_t*>(ptr) >= 0) {
            int32_t attrLen = *reinterpret_cast<const int32_t*>(ptr);
            ptr += 4;
            
            if (attrLen < 0) break;
            
            std::string attrName, attrValue;
            for (int i = 0; i < static_cast<int>(attrLen); ++i) {
                attrName += static_cast<char>(ptr[i]);
            }
            ptr += attrLen;

            int32_t valLen = *reinterpret_cast<const int32_t*>(ptr);
            ptr += 4;
            
            if (valLen < 0) break;
            
            for (int i = 0; i < static_cast<int>(valLen); ++i) {
                attrValue += static_cast<char>(ptr[i]);
            }
            ptr += valLen;

            attrs.emplace_back(attrName, attrValue);
        }

        name = elemName;
        return true;
    }

    // Decode entire AXML document
    static bool decode(const char* data, size_t len, 
                       std::string& rootName,
                       std::vector<std::pair<std::string, std::string>>& rootAttrs) {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
        
        // Check and skip magic number
        uint16_t magic = *reinterpret_cast<const uint16_t*>(ptr);
        if (magic == AXML_BYTE_ORDER_BIG || magic == AXML_BYTE_ORDER_LITTLE) {
            ptr += 2;
        } else {
            return false;
        }

        // Read root name length and name
        int32_t rootNameLen = *reinterpret_cast<const int32_t*>(ptr);
        ptr += 4;
        
        if (rootNameLen < 0) return false;
        
        std::string rootNameStr;
        for (int i = 0; i < rootNameLen; ++i) {
            rootNameStr += static_cast<char>(ptr[i]);
        }
        ptr += rootNameLen;

        // Read root attributes
        while (*reinterpret_cast<const int32_t*>(ptr) >= 0) {
            int32_t attrLen = *reinterpret_cast<const int32_t*>(ptr);
            ptr += 4;
            
            if (attrLen < 0) break;
            
            std::string attrName, attrValue;
            for (int i = 0; i < static_cast<int>(attrLen); ++i) {
                attrName += static_cast<char>(ptr[i]);
            }
            ptr += attrLen;

            int32_t valLen = *reinterpret_cast<const int32_t*>(ptr);
            ptr += 4;
            
            if (valLen < 0) break;
            
            for (int i = 0; i < static_cast<int>(valLen); ++i) {
                attrValue += static_cast<char>(ptr[i]);
            }
            ptr += valLen;

            rootAttrs.emplace_back(attrName, attrValue);
        }

        return true;
    }
};

// ============ APK Container Parser ============

class ApkContainerParser {
public:
    explicit ApkContainerParser(const std::string& path) : mPath(path), mManifestData() {}

    // Parse the entire APK and extract manifest data
    bool parse() {
        if (!openFile()) return false;

        if (!locateCentralDirectory()) return false;

        if (!readAllEntries()) return false;

        if (!extractAndroidManifest()) return false;

        closeFile();
        return true;
    }

    // Get the parsed manifest data
    const std::string& getRootName() const { return mRootName; }
    
    const std::vector<std::pair<std::string, std::string>>& getRootAttrs() const { 
        return mRootAttrs; 
    }

private:
    std::string mPath;
    FILE* mFile = nullptr;
    std::vector<ZipEntry> mEntries;
    std::string mManifestData;
    std::string mRootName;
    std::vector<std::pair<std::string, std::string>> mRootAttrs;

    bool openFile() {
        if (mFile) fclose(mFile);
        
        mFile = fopen(mPath.c_str(), "rb");
        return mFile != nullptr;
    }

    void closeFile() {
        if (mFile) fclose(mFile);
        mFile = nullptr;
    }

    // Locate the central directory by scanning backwards from EOF
    bool locateCentralDirectory() {
        fseek(mFile, 0, SEEK_END);
        long fileSize = ftell(mFile);
        fseek(mFile, -22, SEEK_END); // ZIP_END_CENTRAL_DIR_SIG is 22 bytes

        uint32_t sig;
        if (fread(&sig, sizeof(sig), 1, mFile) != 1 || 
            sig != ZIP_END_CENTRAL_DIR_SIG) {
            return false;
        }

        // Read the rest of the end central directory record
        uint16_t commentLen = *reinterpret_cast<const uint16_t*>(mFile);
        fseek(mFile, -22 + 42 + commentLen, SEEK_END); // Skip to central dir offset

        uint32_t cdOffset;
        if (fread(&cdOffset, sizeof(cdOffset), 1, mFile) != 1) {
            return false;
        }

        fseek(mFile, cdOffset, SEEK_SET);

        // Read the number of entries in central directory
        uint32_t numEntries = *reinterpret_cast<const uint32_t*>(mFile);
        
        // Calculate offset to first entry (CD header is 46 bytes)
        long cdHeaderOffset = cdOffset - (numEntries * 46);
        fseek(mFile, cdHeaderOffset, SEEK_SET);

        for (uint32_t i = 0; i < numEntries; ++i) {
            uint16_t nameLen = *reinterpret_cast<const uint16_t*>(mFile);
            mFile += 2; // Skip name length
            
            std::string entryName;
            for (int j = 0; j < static_cast<int>(nameLen); ++j) {
                char c;
                if (fread(&c, 1, 1, mFile) == 1) {
                    entryName += c;
                }
            }

            // Skip compression method, flags, etc.
            uint32_t temp;
            for (int j = 0; j < 8; ++j) {
                if (fread(&temp, sizeof(temp), 1, mFile) == 1) {}
            }

            // Read compressed and uncompressed sizes
            if (fread(&mEntries[i].compressedSize, sizeof(mEntries[i].compressedSize), 1, mFile) != 1) break;
            if (fread(&mEntries[i].uncompressedSize, sizeof(mEntries[i].uncompressedSize), 1, mFile) != 1) break;

            // Read CRC32 and name length again for reference
            uint32_t crc;
            if (fread(&crc, sizeof(crc), 1, mFile) == 1) {
                mEntries[i].crc32 = crc;
            }

            // Skip to next entry or end of file
            long remaining = cdOffset + 46 - cdHeaderOffset - 
                            (nameLen + 8 + sizeof(uint32_t) * 2);
            if (remaining > 0) {
                fseek(mFile, remaining, SEEK_CUR);
            }
        }

        return true;
    }

    bool readAllEntries() {
        for (const auto& entry : mEntries) {
            // Skip to the actual data
            long offset = entry.uncompressedSize - 2048; // Approximate, refine below
            
            if (offset < 0 || offset > static_cast<long>(mFile ? ftell(mFile) : 0)) {
                continue;
            }

            fseek(mFile, offset, SEEK_SET);
            
            std::string data;
            char buffer[4096];
            while (true) {
                size_t toRead = std::min(static_cast<size_t>(entry.uncompressedSize - static_cast<uint32_t>(data.size())), 4096);
                
                if (fread(buffer, 1, toRead, mFile) != toRead) break;
                
                data.append(buffer, toRead);

                // Check for AXML magic number
                const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data.c_str());
                uint16_t magic = *ptr;
                if (magic == AXML_BYTE_ORDER_BIG || magic == AXML_BYTE_ORDER_LITTLE) {
                    mManifestData = data;
                    break;
                }

                // If we've read the full entry, assume it's not AndroidManifest.xml
                if (data.size() >= static_cast<size_t>(entry.uncompressedSize)) {
                    break;
                }
            }
        }

        return !mManifestData.empty();
    }

    bool extractAndroidManifest() {
        if (!AxmlDecoder::decode(mManifestData.c_str(), mManifestData.size(), 
                                  mRootName, mRootAttrs)) {
            return false;
        }

        // Verify this is indeed AndroidManifest.xml
        std::string rootNameLower = mRootName;
        std::transform(rootNameLower.begin(), rootNameLower.end(), 
                       rootNameLower.begin(), ::tolower);
        
        if (rootNameLower.find("androidmanifest") == std::string::npos) {
            return false;
        }

        return true;
    }
};

// ============ Demo / Entry Point ============

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: apkprobe [APK_PATH]\n";
        std::cerr << "Example: apkprobe app.apk\n";
        return 1;
    }

    ApkContainerParser parser(argv[1]);

    if (!parser.parse()) {
        std::cerr << "Failed to parse APK: " << argv[1] << "\n";
        return 1;
    }

    const auto& rootName = parser.getRootName();
    const auto& rootAttrs = parser.getRootAttrs();

    std::cout << "APK Container Parser Results\n";
    std::cout << "============================\n\n";

    std::cout << "Root Element: " << rootName << "\n\n";

    std::cout << "Root Attributes:\n";
    for (const auto& attr : rootAttrs) {
        std::cout << "  " << attr.first << " = \"" << attr.second << "\"\n";
    }

    // Extract specific MASTG-relevant fields
    std::cout << "\nMASTG-Relevant Fields:\n";
    
    for (const auto& attr : rootAttrs) {
        if (attr.first == "package" || 
            attr.first == "name" ||
            attr.first == "versionCode" ||
            attr.first == "versionName") {
            std::cout << "  " << attr.first << ": " << attr.second << "\n";
        }
    }

    // Check for dangerous permissions in attributes (recursive would need more code)
    const char* dangerPerms[] = {
        "android.permission.READ_SMS",
        "android.permission.WRITE_SMS",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.FOREGROUND_SERVICE",
        nullptr
    };

    std::cout << "\nPotential Security Concerns:\n";
    for (const auto& attr : rootAttrs) {
        if (attr.first == "permission") {
            const char* perm = attr.second.c_str();
            bool found = false;
            for (int i = 0; dangerPerms[i]; !found; ++i) {
                if (!strcmp(perm, dangerPerms[i])) {
                    std::cout << "  WARNING: Dangerous permission detected!\n";
                    std::cout << "    - " << perm << "\n";
                    found = true;
                }
            }
        }
    }

    return 0;
}