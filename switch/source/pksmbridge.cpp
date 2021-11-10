/*
 *   This file is part of Checkpoint
 *   Copyright (C) 2017-2021 Bernardo Giordano, FlagBrew
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Additional Terms 7.b and 7.c of GPLv3 apply to this file:
 *       * Requiring preservation of specified reasonable legal notices or
 *         author attributions in that material or in the Appropriate Legal
 *         Notices displayed by works containing it.
 *       * Prohibiting misrepresentation of the origin of that material,
 *         or requiring that modified versions of such material be marked in
 *         reasonable ways as different from the original version.
 */

#include "pksmbridge.hpp"
#include "KeyboardManager.hpp"
#include "pksmbridge_api.h"
#include "pksmbridge_tcp.h"
#include "title.hpp"
#include <errno.h>
#include <string.h>

namespace {

    bool isLGPE(u64 id) { return id == 0x0100187003A36000 || id == 0x010003F003A34000; }

    bool isSWSH(u64 id) { return id == 0x0100ABF008968000 || id == 0x01008DB008C2C000; }

    bool validateIpAddress(const std::string& ip)
    {
        struct sockaddr_in sa;
        return inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 0;
    }

    bool verifyPKSMBridgeFileSHA256Checksum(struct pksmBridgeFile file)
    {
        if (file.checksumSize != SHA256_HASH_SIZE) {
            return false;
        }
        unsigned char* checksum = (unsigned char*)malloc(file.checksumSize);
        sha256CalculateHash(checksum, file.contents, file.size);
        int result = memcmp(checksum, file.checksum, file.checksumSize);
        free(checksum);
        return (result == 0) ? true : false;
    }

    std::tuple<bool, Result, std::string> outputTupleFromError(enum pksmBridgeError error)
    {
        switch (error) {
            case PKSM_BRIDGE_ERROR_NONE:
                return std::make_tuple(true, 0, "Data sent correctly.");
            case PKSM_BRIDGE_ERROR_UNSUPPORTED_PROTCOL_VERSION:
                return std::make_tuple(false, errno, "Unsupported PKSM Bridge protocol version.");
            case PKSM_BRIDGE_ERROR_CONNECTION_ERROR:
                return std::make_tuple(false, errno, "Socket connection failed.");
            case PKSM_BRIDGE_DATA_READ_FAILURE:
                return std::make_tuple(false, errno, "Failed to receive data.");
            case PKSM_BRIDGE_DATA_WRITE_FAILURE:
                return std::make_tuple(false, errno, "Failed to send data.");
            case PKSM_BRIDGE_DATA_FILE_CORRUPTED:
                return std::make_tuple(false, errno, "Transfer failed. File data corrupted.");
            case PKSM_BRIDGE_ERROR_UNEXPECTED_MESSAGE:
                return std::make_tuple(false, errno, "Unexpected message received over PKSM Bridge.");
            default:
                char buffer[50];
                sprintf(buffer, "Unhandled PKSM Bridge error occurred: %d", error);
                return std::make_tuple(false, errno, std::string(buffer));
        }
    }

} // namespace

bool isPKSMBridgeTitle(u64 id)
{
    return isLGPE(id) || isSWSH(id);
}

std::tuple<bool, Result, std::string> sendToPKSMBridge(size_t index, AccountUid uid, size_t cellIndex)
{
    auto systemKeyboardAvailable = KeyboardManager::get().isSystemKeyboardAvailable();
    if (!systemKeyboardAvailable.first) {
        return std::make_tuple(false, systemKeyboardAvailable.second, "System keyboard not accessible.");
    }

    Title title;
    getTitle(title, uid, index);
    std::string filename;
    if (isLGPE(title.id())) {
        filename = "/savedata.bin";
    }
    else if (isSWSH(title.id())) {
        // Sword and Shield actually uses the 'backup' file as the canonical one.
        filename = "/backup";
    }
    else {
        return std::make_tuple(false, systemKeyboardAvailable.second, "Invalid title.");
    }
    std::string srcPath = title.fullPath(cellIndex) + filename;
    FILE* save          = fopen(srcPath.c_str(), "rb");
    if (save == NULL) {
        return std::make_tuple(false, systemKeyboardAvailable.second, "Failed to open source file.");
    }
    fseek(save, 0, SEEK_END);
    uint32_t size = ftell(save);
    rewind(save);
    uint8_t* data = new uint8_t[size];
    fread(data, 1, size, save);
    fclose(save);

    auto ipaddress = KeyboardManager::get().keyboard("Input PKSM IP address");
    if (!ipaddress.first || !validateIpAddress(ipaddress.second)) {
        delete[] data;
        return std::make_tuple(false, -1, "Invalid IP address.");
    }

    unsigned char checksum[SHA256_HASH_SIZE];
    sha256CalculateHash(checksum, data, size);
    uint32_t checksumSize      = sizeof(checksum) / sizeof(checksum[0]);
    struct pksmBridgeFile file = {.checksumSize = checksumSize, .checksum = checksum, size = size, .contents = data};
    struct in_addr address     = {.s_addr = inet_addr(ipaddress.second.c_str())};
    enum pksmBridgeError error = sendFileOverPKSMBridgeViaTCP(PKSM_PORT, address, file);
    delete[] data;
    return outputTupleFromError(error);
}

std::tuple<bool, Result, std::string> recvFromPKSMBridge(size_t index, AccountUid uid, size_t cellIndex)
{
    uint8_t* file = nullptr;
    uint32_t fileSize;
    enum pksmBridgeError error = receiveFileOverPKSMBridgeViaTCP(PKSM_PORT, NULL, &file, &fileSize, &verifyPKSMBridgeFileSHA256Checksum);

    std::tuple<bool, Result, std::string> result = outputTupleFromError(error);
    if (error != PKSM_BRIDGE_ERROR_NONE) {
        free(file);
        Logger::getInstance().log(Logger::ERROR, std::get<2>(result));
        return result;
    }

    Title title;
    getTitle(title, uid, index);
    std::string filename;
    if (isLGPE(title.id())) {
        filename = "/savedata.bin";
    }
    else if (isSWSH(title.id())) {
        // Sword and Shield actually uses the 'backup' file as the canonical one.
        filename = "/backup";
    }
    else {
        filename = "DEFAULT";
    }
    std::string srcPath = title.fullPath(cellIndex) + filename;
    FILE* save          = fopen(srcPath.c_str(), "wb");
    if (save == NULL) {
        free(file);
        Logger::getInstance().log(Logger::ERROR, "Failed to open destination file with errno %d.", errno);
        return std::make_tuple(false, errno, "Failed to open destination file.");
    }

    fwrite(file, sizeof(file[0]), fileSize, save);
    fclose(save);
    free(file);
    Logger::getInstance().log(Logger::ERROR, std::get<2>(result));
    return result;
}
