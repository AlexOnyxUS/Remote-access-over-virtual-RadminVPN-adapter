// ============================================================================
// RadminUltraRD.cpp — Ultra-Low Latency Remote Desktop (Host + Client + Files)
// Компиляция (x64 Native Tools Command Prompt for VS):
// cl.exe /O2 /Oi /EHsc /std:c++20 /DUNICODE /D_UNICODE C:\Users\listf\Desktop\RadminUltraRD.cpp /link /SUBSYSTEM:WINDOWS /OUT:C:\Users\listf\Desktop\RadminUltraRD.exe
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <mmsystem.h>
#include <commctrl.h>
#include <bcrypt.h>
#include <dwmapi.h>

#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <d3dcompiler.h>
#include <d2d1.h>
#include <dwrite.h>
#include <wrl/client.h>

#include <initguid.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <codecapi.h>
#include <wmcodecdsp.h>

#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cmath>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "mf.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWA_BORDER_COLOR
#define DWMWA_BORDER_COLOR 34
#endif

using Microsoft::WRL::ComPtr;

static constexpr uint16_t  DISCOVERY_UDP_PORT  = 26999;
static constexpr uint16_t  DEFAULT_STREAM_PORT = 27000;
static constexpr uint32_t  MAGIC_DISCOVERY     = 0x52444D4E; // 'RDMN'
static constexpr uint32_t  MAGIC_VIDEO         = 0x56494430; // 'VID0'
static constexpr uint32_t  MAGIC_CONTROL       = 0x4354524C; // 'CTRL'
static constexpr ULONG_PTR INJECTED_SIGNATURE  = 0x52444D4E;
static constexpr size_t    MAX_UDP_PAYLOAD     = 1340;
static constexpr size_t    MAX_CLIPBOARD_BYTES = 16 * 1024 * 1024;
static constexpr size_t    FILE_CHUNK_SIZE     = 64 * 1024;  // 64 КБ чанки

enum ControlMsgType : uint8_t {
    CTRL_AUTH_CHALLENGE   = 1,
    CTRL_AUTH_RESPONSE    = 2,
    CTRL_AUTH_RESULT      = 3,
    CTRL_MOUSE_EVENT      = 4,
    CTRL_KEY_EVENT        = 5,
    CTRL_CLIPBOARD_DATA   = 6,
    CTRL_REQ_IDR          = 7,
    CTRL_PING             = 8,
    CTRL_PONG             = 9,
    CTRL_RELEASE_ALL_KEYS = 10,
    CTRL_FILE_START       = 11,
    CTRL_FILE_CHUNK       = 12,
    CTRL_FILE_END         = 13
};

enum ClipboardDataType : uint8_t {
    CLIP_FORMAT_TEXT_UTF16 = 1,
    CLIP_FORMAT_IMAGE_DIB  = 2
};

enum MouseButtonFlags : uint32_t {
    MBTN_MOVE       = 0x0001,
    MBTN_LEFT_DOWN  = 0x0002,
    MBTN_LEFT_UP    = 0x0004,
    MBTN_RIGHT_DOWN = 0x0008,
    MBTN_RIGHT_UP   = 0x0010,
    MBTN_MID_DOWN   = 0x0020,
    MBTN_MID_UP     = 0x0040,
    MBTN_WHEEL_V    = 0x0080,
    MBTN_WHEEL_H    = 0x0100,
    MBTN_RELATIVE   = 0x0200
};

#pragma pack(push, 1)
struct DiscoveryPacket {
    uint32_t magic;
    uint8_t  isResponse;
    char     serverName[64];
    char     serverIp[32];
    uint16_t port;
    uint32_t width;
    uint32_t height;
};

struct UdpVideoHeader {
    uint32_t magic;
    uint64_t sessionToken;
    uint32_t frameId;
    uint16_t chunkIdx;
    uint16_t totalChunks;
    uint8_t  flags;
    uint16_t width;
    uint16_t height;
    uint32_t encodeUs;
    uint64_t captureQpcUs;
    uint16_t payloadSize;
};

struct ControlHeader {
    uint32_t magic;
    uint8_t  type;
    uint32_t payloadSize;
};

struct AuthChallengePayload {
    uint8_t  salt[32];
    uint8_t  challenge[32];
    uint32_t screenWidth;
    uint32_t screenHeight;
};

struct AuthResponsePayload {
    uint8_t  hmac[32];
    uint16_t clientUdpPort;
};

struct AuthResultPayload {
    uint8_t  authenticated;
    uint64_t udpSessionToken;
};

struct MouseEventPayload {
    float    normX;
    float    normY;
    int32_t  deltaX;
    int32_t  deltaY;
    int32_t  wheelDelta;
    uint32_t flags;
};

struct KeyEventPayload {
    uint16_t scanCode;
    uint16_t vKey;
    uint8_t  isDown;
    uint8_t  isExtended;
};

struct ClipboardHeaderPayload {
    uint8_t  dataType;
    uint8_t  sha256[32];
    uint32_t dataSize;
};

struct PingPongPayload {
    uint64_t timestampUs;
    uint32_t lastDecodeUs;
};

struct FileStartPayload {
    uint32_t transferId;
    uint64_t totalSize;
    wchar_t  fileName[260];
};

struct FileChunkHeaderPayload {
    uint32_t transferId;
    uint64_t offset;
    uint32_t chunkSize;
};

struct FileEndPayload {
    uint32_t transferId;
    uint8_t  status;
};
#pragma pack(pop)

// ============================================================================
// УТИЛИТЫ ВРЕМЕНИ, КРИПТОГРАФИИ, СТИЛИЗАЦИИ И СЕТИ
// ============================================================================
static inline uint64_t NowMicros() {
    static LARGE_INTEGER freq = {};
    static LARGE_INTEGER start = {};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    LONGLONG delta = counter.QuadPart - start.QuadPart;
    return static_cast<uint64_t>(
        (delta / freq.QuadPart) * 1000000ULL +
        ((delta % freq.QuadPart) * 1000000ULL) / freq.QuadPart
    );
}

static inline void MicroSpinWait(uint64_t delayUs) {
    uint64_t start = NowMicros();
    while (NowMicros() - start < delayUs) YieldProcessor();
}

static void DisableBackgroundPowerThrottling() {
    PROCESS_POWER_THROTTLING_STATE state = {};
    state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED |
                        PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    state.StateMask = 0;
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &state, sizeof(state));
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    timeBeginPeriod(1);
}

static void ApplyWindowDarkChrome(HWND hwnd, bool roundedCorners = false) {
    if (!hwnd) return;
    BOOL dark = TRUE;
    if (FAILED(DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark)))) {
        DwmSetWindowAttribute(hwnd, 19, &dark, sizeof(dark));
    }
    if (roundedCorners) {
        DWORD pref = 2; // DWMWCP_ROUND
        DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &pref, sizeof(pref));
        COLORREF borderCol = RGB(36, 48, 71);
        DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &borderCol, sizeof(borderCol));
    }
}

static void ApplyDarkScrollbarTheme(HWND hwnd) {
    if (!hwnd) return;
    static HMODULE hUxTheme = LoadLibraryExW(L"uxtheme.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hUxTheme) {
        using FnSetWindowTheme = HRESULT(WINAPI*)(HWND, LPCWSTR, LPCWSTR);
        static auto pSetWindowTheme = reinterpret_cast<FnSetWindowTheme>(
            GetProcAddress(hUxTheme, "SetWindowTheme"));
        if (pSetWindowTheme) {
            pSetWindowTheme(hwnd, L"DarkMode_Explorer", nullptr);
        }
    }
}

class CryptoEngine {
public:
    static bool RandomBytes(uint8_t* out, size_t len) {
        return BCryptGenRandom(nullptr, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    static bool ComputeSHA256(const void* data, size_t len, uint8_t outHash[32]) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
                if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0) == 0 &&
                    BCryptFinishHash(hHash, outHash, 32, 0) == 0) ok = true;
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        return ok;
    }

    static bool ComputeHMACSHA256(const uint8_t* key, size_t keyLen,
                                  const void* data, size_t dataLen, uint8_t outMac[32]) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0) {
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, (PUCHAR)key, (ULONG)keyLen, 0) == 0) {
                if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0) == 0 &&
                    BCryptFinishHash(hHash, outMac, 32, 0) == 0) ok = true;
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        return ok;
    }

    static bool ConstantTimeEqual32(const uint8_t a[32], const uint8_t b[32]) {
        uint8_t diff = 0;
        for (int i = 0; i < 32; ++i) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }

    static void StreamCrypt(uint8_t* data, size_t len, const uint8_t sessionKey[32], uint64_t counterNonce) {
        uint8_t blockInput[40];
        memcpy(blockInput, sessionKey, 32);
        uint8_t keystream[32];
        size_t offset = 0;
        uint64_t blockIdx = 0;
        while (offset < len) {
            uint64_t ctr = counterNonce ^ blockIdx++;
            memcpy(blockInput + 32, &ctr, 8);
            ComputeSHA256(blockInput, sizeof(blockInput), keystream);
            size_t chunk = std::min<size_t>(32, len - offset);
            for (size_t i = 0; i < chunk; ++i) data[offset + i] ^= keystream[i];
            offset += chunk;
        }
    }
};

static std::string DetectRadminVpnIP(std::vector<std::string>* outBroadcastAddrs = nullptr) {
    std::string radminIp, fallbackLanIp = "127.0.0.1";
    if (outBroadcastAddrs) {
        outBroadcastAddrs->clear();
        outBroadcastAddrs->push_back("26.255.255.255");
        outBroadcastAddrs->push_back("255.255.255.255");
        outBroadcastAddrs->push_back("127.0.0.1");
    }

    ULONG bufLen = 16384;
    std::vector<uint8_t> buffer(bufLen);
    auto addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    DWORD res = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     nullptr, addresses, &bufLen);
    if (res == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufLen);
        addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        res = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                   nullptr, addresses, &bufLen);
    }

    if (res == NO_ERROR) {
        for (auto curr = addresses; curr != nullptr; curr = curr->Next) {
            if (curr->OperStatus != IfOperStatusUp || curr->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            for (auto ua = curr->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                if (!sin || sin->sin_family != AF_INET) continue;
                char ipStr[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr));
                uint32_t hostIp = ntohl(sin->sin_addr.s_addr);
                if ((hostIp >> 24) == 26) radminIp = ipStr;
                else if (fallbackLanIp == "127.0.0.1") fallbackLanIp = ipStr;

                if (outBroadcastAddrs && ua->OnLinkPrefixLength > 0 && ua->OnLinkPrefixLength < 32) {
                    uint32_t mask = (0xFFFFFFFFu << (32 - ua->OnLinkPrefixLength));
                    in_addr bcastAddr;
                    bcastAddr.s_addr = htonl((hostIp & mask) | (~mask));
                    char bcastStr[INET_ADDRSTRLEN] = {};
                    inet_ntop(AF_INET, &bcastAddr, bcastStr, sizeof(bcastStr));
                    outBroadcastAddrs->push_back(bcastStr);
                }
            }
        }
    }
    return radminIp.empty() ? fallbackLanIp : radminIp;
}

static bool SendAllTcp(SOCKET s, const void* data, size_t len) {
    if (s == INVALID_SOCKET) return false;
    const char* ptr = static_cast<const char*>(data);
    size_t total = 0;
    while (total < len) {
        int sent = send(s, ptr + total, (int)(len - total), 0);
        if (sent <= 0) return false;
        total += sent;
    }
    return true;
}

static bool RecvAllTcp(SOCKET s, void* data, size_t len) {
    if (s == INVALID_SOCKET) return false;
    char* ptr = static_cast<char*>(data);
    size_t total = 0;
    while (total < len) {
        int rcvd = recv(s, ptr + total, (int)(len - total), 0);
        if (rcvd <= 0) return false;
        total += rcvd;
    }
    return true;
}

static void DisableUdpConnReset(SOCKET udpSock) {
    if (udpSock == INVALID_SOCKET) return;
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(udpSock, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior),
             nullptr, 0, &dwBytesReturned, nullptr, nullptr);
}

// ============================================================================
// ПРИЁМНИК ФАЙЛОВ (СОХРАНЕНИЕ НА РАБОЧИЙ СТОЛ С ПРОГРЕССОМ)
// ============================================================================
class FileTransferReceiver {
public:
    ~FileTransferReceiver() { CloseActiveFile(); }

    void CloseActiveFile() {
        if (m_hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hFile);
            m_hFile = INVALID_HANDLE_VALUE;
        }
        m_activeTransferId = 0;
    }

    bool OnFileStart(const FileStartPayload& start, std::wstring& outStatus, float& outPct) {
        CloseActiveFile();
        outPct = 0.0f;
        std::wstring rawName(start.fileName, wcsnlen(start.fileName, 259));
        size_t slashPos = rawName.find_last_of(L"\\/");
        if (slashPos != std::wstring::npos) rawName = rawName.substr(slashPos + 1);
        if (rawName.empty()) rawName = L"Received_File.bin";

        wchar_t desktopDir[MAX_PATH] = {};
        if (FAILED(SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, desktopDir))) {
            GetCurrentDirectoryW(MAX_PATH, desktopDir);
        }

        std::wstring finalPath = BuildUniqueFilePath(desktopDir, rawName);
        m_hFile = CreateFileW(finalPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_hFile == INVALID_HANDLE_VALUE) {
            outStatus = L"Ошибка создания файла: " + rawName;
            return false;
        }

        m_activeTransferId = start.transferId;
        m_totalBytes = start.totalSize;
        m_receivedBytes = 0;
        m_fileName = rawName;
        outStatus = L"Приём файла: " + m_fileName + L" (0%)";
        return true;
    }

    bool OnFileChunk(const FileChunkHeaderPayload& hdr, const uint8_t* data, std::wstring& outStatus, float& outPct, bool& notifyUi) {
        notifyUi = false;
        if (m_hFile == INVALID_HANDLE_VALUE || hdr.transferId != m_activeTransferId) return false;

        DWORD written = 0;
        if (!WriteFile(m_hFile, data, hdr.chunkSize, &written, nullptr) || written != hdr.chunkSize) {
            CloseActiveFile();
            outStatus = L"Ошибка записи файла: " + m_fileName;
            outPct = 0.0f;
            notifyUi = true;
            return false;
        }

        m_receivedBytes += written;
        uint64_t now = NowMicros();
        if (now - m_lastUiUs > 100000ULL || m_receivedBytes == m_totalBytes) {
            m_lastUiUs = now;
            outPct = (m_totalBytes > 0) ? std::clamp((float)m_receivedBytes / (float)m_totalBytes, 0.0f, 1.0f) : 1.0f;
            int pct = (int)(outPct * 100.0f);
            std::wstringstream ss;
            ss << L"Приём: " << m_fileName << L" [" << pct << L"%, "
               << std::fixed << std::setprecision(1) << (m_receivedBytes / 1048576.0)
               << L" / " << (m_totalBytes / 1048576.0) << L" МБ]";
            outStatus = ss.str();
            notifyUi = true;
        }
        return true;
    }

    void OnFileEnd(const FileEndPayload& end, std::wstring& outStatus, float& outPct) {
        if (end.transferId == m_activeTransferId && m_hFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(m_hFile);
            CloseActiveFile();
            outPct = (end.status == 1) ? 1.0f : 0.0f;
            outStatus = (end.status == 1)
                ? (L"Файл сохранён на Рабочий стол: " + m_fileName)
                : (L"Передача файла прервана: " + m_fileName);
        }
    }

private:
    static std::wstring BuildUniqueFilePath(const std::wstring& dir, const std::wstring& fileName) {
        std::wstring base = dir + L"\\" + fileName;
        if (GetFileAttributesW(base.c_str()) == INVALID_FILE_ATTRIBUTES) return base;
        size_t dotPos = fileName.find_last_of(L'.');
        std::wstring stem = (dotPos != std::wstring::npos) ? fileName.substr(0, dotPos) : fileName;
        std::wstring ext  = (dotPos != std::wstring::npos) ? fileName.substr(dotPos) : L"";
        for (int i = 1; i < 1000; ++i) {
            std::wstring candidate = dir + L"\\" + stem + L" (" + std::to_wstring(i) + L")" + ext;
            if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES) return candidate;
        }
        return base;
    }

    HANDLE       m_hFile = INVALID_HANDLE_VALUE;
    uint32_t     m_activeTransferId = 0;
    uint64_t     m_totalBytes = 0;
    uint64_t     m_receivedBytes = 0;
    uint64_t     m_lastUiUs = 0;
    std::wstring m_fileName;
};

// ============================================================================
// ЗАХВАТ ЭКРАНА DXGI DESKTOP DUPLICATION + GPU VIDEO PROCESSOR
// ============================================================================
class DxgiScreenCapturer {
public:
    bool Initialize(uint32_t maxEncodeWidth = 1920, uint32_t maxEncodeHeight = 1080) {
        Shutdown();
        m_maxEncodeW = maxEncodeWidth;
        m_maxEncodeH = maxEncodeHeight;

        ComPtr<IDXGIFactory1> factory;
        if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) return false;

        ComPtr<IDXGIAdapter1> targetAdapter;
        ComPtr<IDXGIOutput> targetOutput;
        for (UINT a = 0; factory->EnumAdapters1(a, &targetAdapter) != DXGI_ERROR_NOT_FOUND; ++a) {
            if (SUCCEEDED(targetAdapter->EnumOutputs(0, &targetOutput))) break;
            targetAdapter.Reset();
        }
        if (!targetAdapter || !targetOutput) return false;

        D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0 };
        D3D_FEATURE_LEVEL achieved;
        UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
        HRESULT hr = D3D11CreateDevice(targetAdapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags,
                                       levels, _countof(levels), D3D11_SDK_VERSION, &m_device, &achieved, &m_context);
        if (FAILED(hr)) {
            hr = D3D11CreateDevice(targetAdapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                                   levels, _countof(levels), D3D11_SDK_VERSION, &m_device, &achieved, &m_context);
            if (FAILED(hr)) return false;
        }

        ComPtr<ID3D10Multithread> mt;
        if (SUCCEEDED(m_device.As(&mt))) mt->SetMultithreadProtected(TRUE);

        if (!InitDuplication()) return false;
        m_vpReady = InitVideoProcessor();
        return true;
    }

    void Shutdown() {
        m_dupl.Reset();
        m_videoProc.Reset();
        m_videoEnum.Reset();
        m_videoContext.Reset();
        m_videoDevice.Reset();
        m_nv12GpuTex.Reset();
        m_nv12StagingTex.Reset();
        m_bgraStagingTex.Reset();
        m_cachedDesktopTex.Reset();
        m_context.Reset();
        m_device.Reset();
        m_hasCachedFrame = false;
        m_vpReady = false;
    }

    bool CaptureToNv12(std::vector<uint8_t>& outNv12, uint32_t& outWidth, uint32_t& outHeight, bool forceEvenOnTimeout) {
        if (!m_device && !Initialize(m_maxEncodeW, m_maxEncodeH)) return false;
        if (!m_dupl) {
            if (!InitDuplication()) return false;
            m_vpReady = InitVideoProcessor();
        }

        DXGI_OUTDUPL_FRAME_INFO frameInfo = {};
        ComPtr<IDXGIResource> desktopRes;
        UINT timeoutMs = (!m_hasCachedFrame) ? 80 : 6;
        HRESULT hr = m_dupl->AcquireNextFrame(timeoutMs, &frameInfo, &desktopRes);

        if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
            if (!m_hasCachedFrame) SeedInitialDesktopTexture();
            else if (!forceEvenOnTimeout) return false;
        } else if (hr == DXGI_ERROR_ACCESS_LOST || hr == DXGI_ERROR_INVALID_CALL) {
            m_dupl.Reset();
            return false;
        } else if (FAILED(hr)) {
            return false;
        } else {
            ComPtr<ID3D11Texture2D> frameTex;
            if (SUCCEEDED(desktopRes.As(&frameTex))) {
                m_context->CopyResource(m_cachedDesktopTex.Get(), frameTex.Get());
                m_hasCachedFrame = true;
            }
            m_dupl->ReleaseFrame();
        }

        if (!m_hasCachedFrame) return false;
        outWidth = m_encodeWidth;
        outHeight = m_encodeHeight;

        if (m_vpReady && ConvertViaGpuVideoProcessor(outNv12)) return true;
        return ConvertViaStagingFallback(outNv12);
    }

private:
    void SeedInitialDesktopTexture() {
        if (!m_cachedDesktopTex) return;
        HDC hScreen = GetDC(nullptr);
        HDC hMem = CreateCompatibleDC(hScreen);
        BITMAPINFO bmi = {};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = (LONG)m_desktopWidth;
        bmi.bmiHeader.biHeight = -(LONG)m_desktopHeight;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        void* bits = nullptr;
        HBITMAP hBmp = CreateDIBSection(hScreen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
        if (hBmp && bits) {
            HGDIOBJ oldObj = SelectObject(hMem, hBmp);
            BitBlt(hMem, 0, 0, m_desktopWidth, m_desktopHeight, hScreen, m_desktopRect.left, m_desktopRect.top, SRCCOPY);
            m_context->UpdateSubresource(m_cachedDesktopTex.Get(), 0, nullptr, bits, m_desktopWidth * 4, 0);
            m_hasCachedFrame = true;
            SelectObject(hMem, oldObj);
        }
        if (hBmp) DeleteObject(hBmp);
        if (hMem) DeleteDC(hMem);
        if (hScreen) ReleaseDC(nullptr, hScreen);
    }

    bool ConvertViaGpuVideoProcessor(std::vector<uint8_t>& outNv12) {
        D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC inViewDesc = {};
        inViewDesc.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
        ComPtr<ID3D11VideoProcessorInputView> inView;
        if (FAILED(m_videoDevice->CreateVideoProcessorInputView(m_cachedDesktopTex.Get(), m_videoEnum.Get(), &inViewDesc, &inView)))
            return false;

        D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC outViewDesc = {};
        outViewDesc.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
        ComPtr<ID3D11VideoProcessorOutputView> outView;
        if (FAILED(m_videoDevice->CreateVideoProcessorOutputView(m_nv12GpuTex.Get(), m_videoEnum.Get(), &outViewDesc, &outView)))
            return false;

        RECT srcRect = { 0, 0, (LONG)m_desktopWidth, (LONG)m_desktopHeight };
        RECT dstRect = { 0, 0, (LONG)m_encodeWidth, (LONG)m_encodeHeight };
        m_videoContext->VideoProcessorSetStreamSourceRect(m_videoProc.Get(), 0, TRUE, &srcRect);
        m_videoContext->VideoProcessorSetStreamDestRect(m_videoProc.Get(), 0, TRUE, &dstRect);
        m_videoContext->VideoProcessorSetOutputTargetRect(m_videoProc.Get(), TRUE, &dstRect);

        D3D11_VIDEO_PROCESSOR_STREAM stream = {};
        stream.Enable = TRUE;
        stream.pInputSurface = inView.Get();
        if (FAILED(m_videoContext->VideoProcessorBlt(m_videoProc.Get(), outView.Get(), 0, 1, &stream)))
            return false;

        m_context->CopyResource(m_nv12StagingTex.Get(), m_nv12GpuTex.Get());

        D3D11_MAPPED_SUBRESOURCE mapped = {};
        if (FAILED(m_context->Map(m_nv12StagingTex.Get(), 0, D3D11_MAP_READ, 0, &mapped)))
            return false;

        size_t ySize = (size_t)m_encodeWidth * m_encodeHeight;
        size_t uvSize = ySize / 2;
        outNv12.resize(ySize + uvSize);

        const uint8_t* srcY = static_cast<const uint8_t*>(mapped.pData);
        const uint8_t* srcUV = srcY + (size_t)mapped.RowPitch * m_encodeHeight;
        uint8_t* dstY = outNv12.data();
        uint8_t* dstUV = dstY + ySize;

        if (mapped.RowPitch == m_encodeWidth) {
            memcpy(dstY, srcY, ySize);
            memcpy(dstUV, srcUV, uvSize);
        } else {
            for (uint32_t y = 0; y < m_encodeHeight; ++y)
                memcpy(dstY + (size_t)y * m_encodeWidth, srcY + (size_t)y * mapped.RowPitch, m_encodeWidth);
            for (uint32_t y = 0; y < m_encodeHeight / 2; ++y)
                memcpy(dstUV + (size_t)y * m_encodeWidth, srcUV + (size_t)y * mapped.RowPitch, m_encodeWidth);
        }

        m_context->Unmap(m_nv12StagingTex.Get(), 0);
        return true;
    }

    bool ConvertViaStagingFallback(std::vector<uint8_t>& outNv12) {
        if (!m_bgraStagingTex) return false;
        m_context->CopyResource(m_bgraStagingTex.Get(), m_cachedDesktopTex.Get());

        D3D11_MAPPED_SUBRESOURCE mapped = {};
        if (FAILED(m_context->Map(m_bgraStagingTex.Get(), 0, D3D11_MAP_READ, 0, &mapped))) return false;

        size_t ySize = (size_t)m_encodeWidth * m_encodeHeight;
        outNv12.resize(ySize + ySize / 2);
        uint8_t* dstY = outNv12.data();
        uint8_t* dstUV = dstY + ySize;

        const uint8_t* srcBase = static_cast<const uint8_t*>(mapped.pData);
        for (uint32_t y = 0; y < m_encodeHeight; ++y) {
            uint32_t sy0 = (y * m_desktopHeight) / m_encodeHeight;
            uint32_t sy1 = std::min<uint32_t>(m_desktopHeight - 1, sy0 + 1);
            const uint8_t* row0 = srcBase + (size_t)sy0 * mapped.RowPitch;
            const uint8_t* row1 = srcBase + (size_t)sy1 * mapped.RowPitch;
            uint8_t* yOut = dstY + (size_t)y * m_encodeWidth;
            uint8_t* uvOut = dstUV + (size_t)(y / 2) * m_encodeWidth;

            for (uint32_t x = 0; x < m_encodeWidth; ++x) {
                uint32_t sx0 = (x * m_desktopWidth) / m_encodeWidth;
                uint32_t sx1 = std::min<uint32_t>(m_desktopWidth - 1, sx0 + 1);
                const uint8_t* p00 = row0 + sx0 * 4;
                const uint8_t* p01 = row0 + sx1 * 4;
                const uint8_t* p10 = row1 + sx0 * 4;
                const uint8_t* p11 = row1 + sx1 * 4;

                int b = (p00[0] + p01[0] + p10[0] + p11[0]) >> 2;
                int g = (p00[1] + p01[1] + p10[1] + p11[1]) >> 2;
                int r = (p00[2] + p01[2] + p10[2] + p11[2]) >> 2;

                yOut[x] = (uint8_t)std::clamp(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16, 0, 255);
                if ((y & 1) == 0 && (x & 1) == 0) {
                    uvOut[x]     = (uint8_t)std::clamp(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128, 0, 255);
                    uvOut[x + 1] = (uint8_t)std::clamp(((112 * r - 94 * g - 18 * b + 128) >> 8) + 128, 0, 255);
                }
            }
        }
        m_context->Unmap(m_bgraStagingTex.Get(), 0);
        return true;
    }

    bool InitDuplication() {
        m_dupl.Reset();
        ComPtr<IDXGIDevice> dxgiDevice;
        if (FAILED(m_device.As(&dxgiDevice))) return false;
        ComPtr<IDXGIAdapter> adapter;
        if (FAILED(dxgiDevice->GetAdapter(&adapter))) return false;
        ComPtr<IDXGIOutput> output;
        if (FAILED(adapter->EnumOutputs(0, &output))) return false;

        DXGI_OUTPUT_DESC outDesc = {};
        output->GetDesc(&outDesc);
        m_desktopRect = outDesc.DesktopCoordinates;
        m_desktopWidth = std::max<uint32_t>(64, outDesc.DesktopCoordinates.right - outDesc.DesktopCoordinates.left);
        m_desktopHeight = std::max<uint32_t>(64, outDesc.DesktopCoordinates.bottom - outDesc.DesktopCoordinates.top);

        uint32_t targetW = m_desktopWidth, targetH = m_desktopHeight;
        if (targetW > m_maxEncodeW || targetH > m_maxEncodeH) {
            double scale = std::min((double)m_maxEncodeW / targetW, (double)m_maxEncodeH / targetH);
            targetW = (uint32_t)std::round(targetW * scale);
            targetH = (uint32_t)std::round(targetH * scale);
        }
        m_encodeWidth = std::min<uint32_t>(m_maxEncodeW & ~15u, std::max<uint32_t>(64, (targetW + 7) & ~15u));
        m_encodeHeight = std::min<uint32_t>(m_maxEncodeH & ~15u, std::max<uint32_t>(64, (targetH + 7) & ~15u));

        ComPtr<IDXGIOutput1> output1;
        if (FAILED(output.As(&output1))) return false;
        if (FAILED(output1->DuplicateOutput(m_device.Get(), &m_dupl))) return false;

        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = m_desktopWidth;
        desc.Height = m_desktopHeight;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
        if (FAILED(m_device->CreateTexture2D(&desc, nullptr, &m_cachedDesktopTex))) {
            desc.BindFlags = D3D11_BIND_RENDER_TARGET;
            if (FAILED(m_device->CreateTexture2D(&desc, nullptr, &m_cachedDesktopTex))) return false;
        }

        D3D11_TEXTURE2D_DESC stgDesc = desc;
        stgDesc.Usage = D3D11_USAGE_STAGING;
        stgDesc.BindFlags = 0;
        stgDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        m_device->CreateTexture2D(&stgDesc, nullptr, &m_bgraStagingTex);
        return true;
    }

    bool InitVideoProcessor() {
        m_videoProc.Reset();
        m_videoEnum.Reset();
        m_videoContext.Reset();
        m_videoDevice.Reset();
        if (FAILED(m_device.As(&m_videoDevice)) || FAILED(m_context.As(&m_videoContext))) return false;

        D3D11_VIDEO_PROCESSOR_CONTENT_DESC contentDesc = {};
        contentDesc.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
        contentDesc.InputWidth = m_desktopWidth;
        contentDesc.InputHeight = m_desktopHeight;
        contentDesc.OutputWidth = m_encodeWidth;
        contentDesc.OutputHeight = m_encodeHeight;
        contentDesc.Usage = D3D11_VIDEO_USAGE_OPTIMAL_QUALITY;

        if (FAILED(m_videoDevice->CreateVideoProcessorEnumerator(&contentDesc, &m_videoEnum))) return false;
        if (FAILED(m_videoDevice->CreateVideoProcessor(m_videoEnum.Get(), 0, &m_videoProc))) return false;
        m_videoContext->VideoProcessorSetStreamAutoProcessingMode(m_videoProc.Get(), 0, FALSE);

        D3D11_TEXTURE2D_DESC nv12Desc = {};
        nv12Desc.Width = m_encodeWidth;
        nv12Desc.Height = m_encodeHeight;
        nv12Desc.MipLevels = 1;
        nv12Desc.ArraySize = 1;
        nv12Desc.Format = DXGI_FORMAT_NV12;
        nv12Desc.SampleDesc.Count = 1;
        nv12Desc.Usage = D3D11_USAGE_DEFAULT;
        nv12Desc.BindFlags = D3D11_BIND_RENDER_TARGET;
        if (FAILED(m_device->CreateTexture2D(&nv12Desc, nullptr, &m_nv12GpuTex))) return false;

        nv12Desc.Usage = D3D11_USAGE_STAGING;
        nv12Desc.BindFlags = 0;
        nv12Desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        return SUCCEEDED(m_device->CreateTexture2D(&nv12Desc, nullptr, &m_nv12StagingTex));
    }

    ComPtr<ID3D11Device>                    m_device;
    ComPtr<ID3D11DeviceContext>             m_context;
    ComPtr<IDXGIOutputDuplication>          m_dupl;
    ComPtr<ID3D11VideoDevice>               m_videoDevice;
    ComPtr<ID3D11VideoContext>              m_videoContext;
    ComPtr<ID3D11VideoProcessorEnumerator>  m_videoEnum;
    ComPtr<ID3D11VideoProcessor>            m_videoProc;
    ComPtr<ID3D11Texture2D>                 m_cachedDesktopTex;
    ComPtr<ID3D11Texture2D>                 m_bgraStagingTex;
    ComPtr<ID3D11Texture2D>                 m_nv12GpuTex;
    ComPtr<ID3D11Texture2D>                 m_nv12StagingTex;

    RECT     m_desktopRect = {};
    uint32_t m_desktopWidth = 1920, m_desktopHeight = 1080;
    uint32_t m_encodeWidth = 1920,  m_encodeHeight = 1080;
    uint32_t m_maxEncodeW = 1920,   m_maxEncodeH = 1080;
    bool     m_hasCachedFrame = false;
    bool     m_vpReady = false;
};

// ============================================================================
// КОДИРОВЩИК И ДЕКОДЕР H.264 MEDIA FOUNDATION
// ============================================================================
class LowLatencyH264Encoder {
public:
    bool Initialize(uint32_t width, uint32_t height, uint32_t fps = 60) {
        m_encoder.Reset();
        m_codecApi.Reset();
        m_spsPpsHeader.clear();
        m_width = width;
        m_height = height;
        m_fps = fps;

        if (FAILED(CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&m_encoder))))
            return false;

        if (SUCCEEDED(m_encoder.As(&m_codecApi))) {
            VARIANT var = {};
            var.vt = VT_BOOL;
            var.boolVal = VARIANT_TRUE;
            m_codecApi->SetValue(&CODECAPI_AVLowLatencyMode, &var);

            VariantInit(&var);
            var.vt = VT_UI4;
            var.ulVal = 0;
            m_codecApi->SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &var);
            var.ulVal = eAVEncCommonRateControlMode_CBR;
            m_codecApi->SetValue(&CODECAPI_AVEncCommonRateControlMode, &var);
            var.ulVal = 10000000;
            m_codecApi->SetValue(&CODECAPI_AVEncCommonMeanBitRate, &var);
            var.ulVal = 0;
            m_codecApi->SetValue(&CODECAPI_AVEncCommonQualityVsSpeed, &var);
            var.ulVal = fps * 3;
            m_codecApi->SetValue(&CODECAPI_AVEncMPVGOPSize, &var);
        }

        ComPtr<IMFMediaType> outType;
        MFCreateMediaType(&outType);
        outType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        outType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
        outType->SetUINT32(MF_MT_AVG_BITRATE, 10000000);
        outType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
        outType->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main);
        MFSetAttributeSize(outType.Get(), MF_MT_FRAME_SIZE, width, height);
        MFSetAttributeRatio(outType.Get(), MF_MT_FRAME_RATE, fps, 1);
        MFSetAttributeRatio(outType.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);

        if (FAILED(m_encoder->SetOutputType(0, outType.Get(), 0))) {
            outType->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base);
            if (FAILED(m_encoder->SetOutputType(0, outType.Get(), 0))) return false;
        }

        ComPtr<IMFMediaType> inType;
        MFCreateMediaType(&inType);
        inType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        inType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        inType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
        MFSetAttributeSize(inType.Get(), MF_MT_FRAME_SIZE, width, height);
        MFSetAttributeRatio(inType.Get(), MF_MT_FRAME_RATE, fps, 1);
        MFSetAttributeRatio(inType.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);

        if (FAILED(m_encoder->SetInputType(0, inType.Get(), 0))) return false;
        UpdateSequenceHeaderCache();

        m_encoder->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
        m_encoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        return true;
    }

    void ForceKeyFrame() {
        if (m_codecApi) {
            VARIANT var = {};
            var.vt = VT_UI4;
            var.ulVal = 1;
            m_codecApi->SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &var);
        }
    }

    bool EncodeFrame(const std::vector<uint8_t>& nv12Data, std::vector<uint8_t>& outBitStream, bool& outIsKeyFrame) {
        outBitStream.clear();
        outIsKeyFrame = false;
        if (!m_encoder) return false;

        ComPtr<IMFMediaBuffer> inBuf;
        if (FAILED(MFCreateMemoryBuffer((DWORD)nv12Data.size(), &inBuf))) return false;
        BYTE* dst = nullptr;
        if (FAILED(inBuf->Lock(&dst, nullptr, nullptr))) return false;
        memcpy(dst, nv12Data.data(), nv12Data.size());
        inBuf->Unlock();
        inBuf->SetCurrentLength((DWORD)nv12Data.size());

        ComPtr<IMFSample> inSample;
        MFCreateSample(&inSample);
        inSample->AddBuffer(inBuf.Get());
        int64_t duration = 10000000LL / m_fps;
        inSample->SetSampleTime(m_pts);
        inSample->SetSampleDuration(duration);
        m_pts += duration;

        if (FAILED(m_encoder->ProcessInput(0, inSample.Get(), 0))) return false;

        while (true) {
            MFT_OUTPUT_STREAM_INFO streamInfo = {};
            m_encoder->GetOutputStreamInfo(0, &streamInfo);
            ComPtr<IMFSample> outSample;
            ComPtr<IMFMediaBuffer> outBuf;
            if (!(streamInfo.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES)) {
                MFCreateMemoryBuffer(streamInfo.cbSize ? streamInfo.cbSize : (m_width * m_height), &outBuf);
                MFCreateSample(&outSample);
                outSample->AddBuffer(outBuf.Get());
            }

            MFT_OUTPUT_DATA_BUFFER outData = {};
            outData.pSample = outSample.Get();
            DWORD status = 0;
            HRESULT hr = m_encoder->ProcessOutput(0, 1, &outData, &status);
            if (outData.pEvents) outData.pEvents->Release();

            if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
                ComPtr<IMFMediaType> newOutType;
                if (SUCCEEDED(m_encoder->GetOutputAvailableType(0, 0, &newOutType))) {
                    m_encoder->SetOutputType(0, newOutType.Get(), 0);
                    UpdateSequenceHeaderCache();
                }
                continue;
            }
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT || FAILED(hr)) break;

            ComPtr<IMFSample> resultSample = outData.pSample;
            if (resultSample) {
                UINT32 cleanPoint = 0;
                if (SUCCEEDED(resultSample->GetUINT32(MFSampleExtension_CleanPoint, &cleanPoint)) && cleanPoint)
                    outIsKeyFrame = true;

                ComPtr<IMFMediaBuffer> contiguousBuf;
                if (SUCCEEDED(resultSample->ConvertToContiguousBuffer(&contiguousBuf))) {
                    BYTE* pData = nullptr;
                    DWORD cbLen = 0;
                    if (SUCCEEDED(contiguousBuf->Lock(&pData, nullptr, &cbLen))) {
                        if (ContainsIdrOrSpsNal(pData, cbLen)) outIsKeyFrame = true;
                        if (outIsKeyFrame && !m_spsPpsHeader.empty() && outBitStream.empty())
                            outBitStream.insert(outBitStream.end(), m_spsPpsHeader.begin(), m_spsPpsHeader.end());
                        size_t cur = outBitStream.size();
                        outBitStream.resize(cur + cbLen);
                        memcpy(outBitStream.data() + cur, pData, cbLen);
                        contiguousBuf->Unlock();
                    }
                }
            }
        }
        return !outBitStream.empty();
    }

    uint32_t GetWidth() const { return m_width; }
    uint32_t GetHeight() const { return m_height; }

private:
    static bool ContainsIdrOrSpsNal(const uint8_t* data, size_t len) {
        for (size_t i = 0; i + 4 < len; ++i) {
            if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
                uint8_t nalType = data[i + 3] & 0x1F;
                if (nalType == 5 || nalType == 7) return true;
            }
        }
        return false;
    }

    void UpdateSequenceHeaderCache() {
        ComPtr<IMFMediaType> curOut;
        if (SUCCEEDED(m_encoder->GetOutputCurrentType(0, &curOut))) {
            UINT32 blobSize = 0;
            if (SUCCEEDED(curOut->GetBlobSize(MF_MT_MPEG_SEQUENCE_HEADER, &blobSize)) && blobSize > 0) {
                m_spsPpsHeader.resize(blobSize);
                curOut->GetBlob(MF_MT_MPEG_SEQUENCE_HEADER, m_spsPpsHeader.data(), blobSize, &blobSize);
            }
        }
    }

    ComPtr<IMFTransform> m_encoder;
    ComPtr<ICodecAPI>    m_codecApi;
    std::vector<uint8_t> m_spsPpsHeader;
    uint32_t             m_width = 0, m_height = 0, m_fps = 60;
    int64_t              m_pts = 0;
};

struct DecodedNv12Frame {
    std::vector<uint8_t> data;
    uint32_t displayWidth = 0;
    uint32_t displayHeight = 0;
    uint32_t surfaceHeight = 0;
    uint32_t stride = 0;
};

class LowLatencyH264Decoder {
public:
    bool Initialize(uint32_t width, uint32_t height) {
        m_decoder.Reset();
        m_displayWidth = width;
        m_displayHeight = height;
        m_alignedWidth = (width + 15) & ~15u;
        m_alignedHeight = (height + 15) & ~15u;
        m_stride = m_alignedWidth;

        if (FAILED(CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&m_decoder))))
            return false;

        ComPtr<IMFAttributes> attr;
        if (SUCCEEDED(m_decoder->GetAttributes(&attr))) attr->SetUINT32(CODECAPI_AVLowLatencyMode, TRUE);
        ComPtr<ICodecAPI> codecApi;
        if (SUCCEEDED(m_decoder.As(&codecApi))) {
            VARIANT var = {};
            var.vt = VT_BOOL;
            var.boolVal = VARIANT_TRUE;
            codecApi->SetValue(&CODECAPI_AVLowLatencyMode, &var);
        }

        ComPtr<IMFMediaType> inType;
        MFCreateMediaType(&inType);
        inType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        inType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
        MFSetAttributeSize(inType.Get(), MF_MT_FRAME_SIZE, width, height);
        inType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);

        if (FAILED(m_decoder->SetInputType(0, inType.Get(), 0))) return false;
        if (!NegotiateOutputType()) return false;

        m_decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
        m_decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        return true;
    }

    bool DecodeAccessUnit(const uint8_t* h264Data, size_t len, uint32_t dispW, uint32_t dispH, DecodedNv12Frame& outFrame) {
        if (!m_decoder || dispW != m_displayWidth || dispH != m_displayHeight) {
            if (!Initialize(dispW, dispH)) return false;
        }

        ComPtr<IMFMediaBuffer> inBuf;
        if (FAILED(MFCreateMemoryBuffer((DWORD)len, &inBuf))) return false;
        BYTE* dst = nullptr;
        if (FAILED(inBuf->Lock(&dst, nullptr, nullptr))) return false;
        memcpy(dst, h264Data, len);
        inBuf->Unlock();
        inBuf->SetCurrentLength((DWORD)len);

        ComPtr<IMFSample> inSample;
        MFCreateSample(&inSample);
        inSample->AddBuffer(inBuf.Get());
        inSample->SetSampleTime(m_pts);
        inSample->SetSampleDuration(166666);
        m_pts += 166666;

        if (FAILED(m_decoder->ProcessInput(0, inSample.Get(), 0))) return false;

        bool gotFrame = false;
        while (true) {
            MFT_OUTPUT_STREAM_INFO streamInfo = {};
            m_decoder->GetOutputStreamInfo(0, &streamInfo);
            ComPtr<IMFSample> outSample;
            ComPtr<IMFMediaBuffer> outBuf;
            if (!(streamInfo.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES)) {
                MFCreateMemoryBuffer(streamInfo.cbSize ? streamInfo.cbSize : (m_alignedWidth * m_alignedHeight * 2), &outBuf);
                MFCreateSample(&outSample);
                outSample->AddBuffer(outBuf.Get());
            }

            MFT_OUTPUT_DATA_BUFFER outData = {};
            outData.pSample = outSample.Get();
            DWORD status = 0;
            HRESULT hr = m_decoder->ProcessOutput(0, 1, &outData, &status);
            if (outData.pEvents) outData.pEvents->Release();

            if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
                NegotiateOutputType();
                continue;
            }
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT || FAILED(hr)) break;

            ComPtr<IMFSample> resultSample = outData.pSample;
            if (resultSample) {
                ComPtr<IMFMediaBuffer> mediaBuf;
                if (SUCCEEDED(resultSample->GetBufferByIndex(0, &mediaBuf))) {
                    ComPtr<IMF2DBuffer> buf2D;
                    DWORD contigLen = 0;
                    if (SUCCEEDED(mediaBuf.As(&buf2D)) && SUCCEEDED(buf2D->GetContiguousLength(&contigLen)) && contigLen > 0) {
                        outFrame.data.resize(contigLen);
                        if (SUCCEEDED(buf2D->ContiguousCopyTo(outFrame.data.data(), contigLen))) {
                            outFrame.displayWidth = m_displayWidth;
                            outFrame.displayHeight = m_displayHeight;
                            outFrame.stride = m_alignedWidth;
                            outFrame.surfaceHeight = (contigLen * 2) / (m_alignedWidth * 3);
                            gotFrame = true;
                        }
                    } else {
                        BYTE* pRaw = nullptr;
                        DWORD cbMax = 0, cbCur = 0;
                        if (SUCCEEDED(mediaBuf->Lock(&pRaw, &cbMax, &cbCur)) && cbCur > 0) {
                            outFrame.data.assign(pRaw, pRaw + cbCur);
                            outFrame.displayWidth = m_displayWidth;
                            outFrame.displayHeight = m_displayHeight;
                            outFrame.stride = m_stride;
                            outFrame.surfaceHeight = (cbCur * 2) / (m_stride * 3);
                            mediaBuf->Unlock();
                            gotFrame = true;
                        }
                    }
                }
            }
        }
        return gotFrame;
    }

private:
    bool NegotiateOutputType() {
        for (DWORD i = 0; ; ++i) {
            ComPtr<IMFMediaType> availType;
            if (FAILED(m_decoder->GetOutputAvailableType(0, i, &availType))) break;
            GUID subtype = {};
            availType->GetGUID(MF_MT_SUBTYPE, &subtype);
            if (subtype == MFVideoFormat_NV12) {
                if (SUCCEEDED(m_decoder->SetOutputType(0, availType.Get(), 0))) {
                    UINT32 w = 0, h = 0;
                    if (SUCCEEDED(MFGetAttributeSize(availType.Get(), MF_MT_FRAME_SIZE, &w, &h))) {
                        m_alignedWidth = w;
                        m_alignedHeight = h;
                    }
                    UINT32 stride = 0;
                    if (SUCCEEDED(availType->GetUINT32(MF_MT_DEFAULT_STRIDE, &stride)) && stride > 0)
                        m_stride = (uint32_t)std::abs((int32_t)stride);
                    else
                        m_stride = m_alignedWidth;
                    return true;
                }
            }
        }
        return false;
    }

    ComPtr<IMFTransform> m_decoder;
    uint32_t m_displayWidth = 1920, m_displayHeight = 1080;
    uint32_t m_alignedWidth = 1920, m_alignedHeight = 1088, m_stride = 1920;
    int64_t  m_pts = 0;
};

// ============================================================================
// КЛИЕНТСКИЙ DIRECT3D 11 РЕНДЕРЕР
// ============================================================================
static const char* g_hlslShaderSource = R"(
Texture2D<float>  texY  : register(t0);
Texture2D<float2> texUV : register(t1);
SamplerState      samp  : register(s0);

struct VSOut {
    float4 pos : SV_POSITION;
    float2 uv  : TEXCOORD0;
};

VSOut VSMain(uint id : SV_VertexID) {
    VSOut o;
    o.uv = float2((id << 1) & 2, id & 2);
    o.pos = float4(o.uv * float2(2.0f, -2.0f) + float2(-1.0f, 1.0f), 0.0f, 1.0f);
    return o;
}

float3 YuvToRgb(float yVal, float2 uvVal) {
    float y = max(0.0f, (yVal - 0.062745f) * 1.164383f);
    float u = uvVal.x - 0.5f;
    float v = uvVal.y - 0.5f;
    return saturate(float3(y + 1.792741f * v, y - 0.213248f * u - 0.532909f * v, y + 2.112401f * u));
}

float4 PSMain(VSOut i) : SV_TARGET {
    float2 dx = ddx(i.uv) * 0.25f;
    float2 dy = ddy(i.uv) * 0.25f;
    float y0 = texY.Sample(samp, i.uv).r;
    float y1 = texY.Sample(samp, i.uv - dx - dy).r;
    float y2 = texY.Sample(samp, i.uv + dx - dy).r;
    float y3 = texY.Sample(samp, i.uv - dx + dy).r;
    float y4 = texY.Sample(samp, i.uv + dx + dy).r;
    float yAvg = y0 * 0.4f + (y1 + y2 + y3 + y4) * 0.15f;
    float2 uv = texUV.Sample(samp, i.uv).rg;
    return float4(YuvToRgb(yAvg, uv), 1.0f);
}
)";

class D3D11ClientRenderer {
public:
    bool Initialize(HWND hwnd) {
        std::lock_guard<std::mutex> lock(m_renderMutex);
        ShutdownInternal();
        m_hwnd = hwnd;

        RECT rc = {};
        GetClientRect(hwnd, &rc);
        m_winWidth = std::max<uint32_t>(1, rc.right - rc.left);
        m_winHeight = std::max<uint32_t>(1, rc.bottom - rc.top);

        D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0 };
        D3D_FEATURE_LEVEL achieved;
        if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                     levels, _countof(levels), D3D11_SDK_VERSION,
                                     &m_device, &achieved, &m_context))) return false;

        ComPtr<ID3D10Multithread> mt;
        if (SUCCEEDED(m_device.As(&mt))) mt->SetMultithreadProtected(TRUE);

        ComPtr<IDXGIDevice> dxgiDev;
        m_device.As(&dxgiDev);
        ComPtr<IDXGIAdapter> adapter;
        dxgiDev->GetAdapter(&adapter);
        ComPtr<IDXGIFactory2> factory;
        adapter->GetParent(IID_PPV_ARGS(&factory));

        DXGI_SWAP_CHAIN_DESC1 scDesc = {};
        scDesc.Width = m_winWidth;
        scDesc.Height = m_winHeight;
        scDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        scDesc.SampleDesc.Count = 1;
        scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        scDesc.BufferCount = 2;
        scDesc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        scDesc.Scaling = DXGI_SCALING_NONE;

        if (FAILED(factory->CreateSwapChainForHwnd(m_device.Get(), hwnd, &scDesc, nullptr, nullptr, &m_swapChain))) {
            scDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
            scDesc.Scaling = DXGI_SCALING_STRETCH;
            if (FAILED(factory->CreateSwapChainForHwnd(m_device.Get(), hwnd, &scDesc, nullptr, nullptr, &m_swapChain)))
                return false;
        }
        factory->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
        return CreateBackBufferRTV() && CompileShaders();
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(m_renderMutex);
        ShutdownInternal();
    }

    void OnResize(uint32_t newWidth, uint32_t newHeight) {
        std::lock_guard<std::mutex> lock(m_renderMutex);
        if (!m_swapChain || newWidth == 0 || newHeight == 0) return;
        m_winWidth = newWidth;
        m_winHeight = newHeight;
        m_context->OMSetRenderTargets(0, nullptr, nullptr);
        m_rtv.Reset();
        m_swapChain->ResizeBuffers(0, newWidth, newHeight, DXGI_FORMAT_UNKNOWN, 0);
        CreateBackBufferRTV();
    }

    void RenderFrame(const DecodedNv12Frame& frame) {
        std::lock_guard<std::mutex> lock(m_renderMutex);
        if (!m_device || !m_swapChain || frame.data.empty() || frame.surfaceHeight == 0) return;

        if (frame.displayWidth != m_streamWidth || frame.displayHeight != m_streamHeight) {
            if (!CreateStreamTextures(frame.displayWidth, frame.displayHeight)) return;
        }

        size_t uvOffset = (size_t)frame.stride * frame.surfaceHeight;
        if (frame.data.size() < uvOffset + (size_t)frame.stride * (frame.displayHeight / 2)) return;

        const uint8_t* yPlane = frame.data.data();
        const uint8_t* uvPlane = yPlane + uvOffset;

        D3D11_BOX yBox = { 0, 0, 0, frame.displayWidth, frame.displayHeight, 1 };
        m_context->UpdateSubresource(m_texY.Get(), 0, &yBox, yPlane, frame.stride, 0);

        D3D11_BOX uvBox = { 0, 0, 0, frame.displayWidth / 2, frame.displayHeight / 2, 1 };
        m_context->UpdateSubresource(m_texUV.Get(), 0, &uvBox, uvPlane, frame.stride, 0);

        float clearColor[4] = { 0.04f, 0.04f, 0.06f, 1.0f };
        m_context->ClearRenderTargetView(m_rtv.Get(), clearColor);

        D3D11_VIEWPORT vp = CalculateLetterboxViewport();
        m_context->RSSetViewports(1, &vp);

        ID3D11RenderTargetView* rtvs[] = { m_rtv.Get() };
        m_context->OMSetRenderTargets(1, rtvs, nullptr);
        m_context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
        m_context->VSSetShader(m_vs.Get(), nullptr, 0);
        m_context->PSSetShader(m_ps.Get(), nullptr, 0);

        ID3D11ShaderResourceView* srvs[] = { m_srvY.Get(), m_srvUV.Get() };
        m_context->PSSetShaderResources(0, 2, srvs);
        ID3D11SamplerState* samplers[] = { m_sampler.Get() };
        m_context->PSSetSamplers(0, 1, samplers);

        m_context->Draw(4, 0);

        ID3D11ShaderResourceView* nullSrvs[] = { nullptr, nullptr };
        m_context->PSSetShaderResources(0, 2, nullSrvs);
        m_swapChain->Present(0, 0);
    }

    bool MapWindowPointToNormalized(int clientX, int clientY, float& outNormX, float& outNormY) {
        std::lock_guard<std::mutex> lock(m_renderMutex);
        if (m_streamWidth == 0 || m_streamHeight == 0) return false;
        D3D11_VIEWPORT vp = CalculateLetterboxViewport();
        if (vp.Width <= 1.0f || vp.Height <= 1.0f) return false;
        outNormX = std::clamp(((float)clientX - vp.TopLeftX) / vp.Width, 0.0f, 1.0f);
        outNormY = std::clamp(((float)clientY - vp.TopLeftY) / vp.Height, 0.0f, 1.0f);
        return true;
    }

private:
    void ShutdownInternal() {
        m_srvY.Reset(); m_srvUV.Reset(); m_texY.Reset(); m_texUV.Reset();
        m_sampler.Reset(); m_vs.Reset(); m_ps.Reset(); m_rtv.Reset();
        m_swapChain.Reset(); m_context.Reset(); m_device.Reset();
        m_streamWidth = 0; m_streamHeight = 0;
    }

    D3D11_VIEWPORT CalculateLetterboxViewport() const {
        D3D11_VIEWPORT vp = { 0, 0, 0, 0, 0.0f, 1.0f };
        uint32_t sw = m_streamWidth ? m_streamWidth : 1920;
        uint32_t sh = m_streamHeight ? m_streamHeight : 1080;
        float winAspect = (float)m_winWidth / (float)std::max<uint32_t>(1, m_winHeight);
        float streamAspect = (float)sw / (float)std::max<uint32_t>(1, sh);

        if (winAspect > streamAspect) {
            vp.Height = (float)m_winHeight;
            vp.Width = vp.Height * streamAspect;
            vp.TopLeftX = ((float)m_winWidth - vp.Width) * 0.5f;
        } else {
            vp.Width = (float)m_winWidth;
            vp.Height = vp.Width / streamAspect;
            vp.TopLeftY = ((float)m_winHeight - vp.Height) * 0.5f;
        }
        return vp;
    }

    bool CreateBackBufferRTV() {
        ComPtr<ID3D11Texture2D> backBuffer;
        if (FAILED(m_swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer)))) return false;
        return SUCCEEDED(m_device->CreateRenderTargetView(backBuffer.Get(), nullptr, &m_rtv));
    }

    bool CompileShaders() {
        ComPtr<ID3DBlob> vsBlob, psBlob, errBlob;
        if (FAILED(D3DCompile(g_hlslShaderSource, strlen(g_hlslShaderSource), nullptr, nullptr, nullptr,
                              "VSMain", "vs_5_0", D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &vsBlob, &errBlob))) return false;
        if (FAILED(D3DCompile(g_hlslShaderSource, strlen(g_hlslShaderSource), nullptr, nullptr, nullptr,
                              "PSMain", "ps_5_0", D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &psBlob, &errBlob))) return false;
        if (FAILED(m_device->CreateVertexShader(vsBlob->GetBufferPointer(), vsBlob->GetBufferSize(), nullptr, &m_vs))) return false;
        if (FAILED(m_device->CreatePixelShader(psBlob->GetBufferPointer(), psBlob->GetBufferSize(), nullptr, &m_ps))) return false;

        D3D11_SAMPLER_DESC sampDesc = {};
        sampDesc.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
        sampDesc.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
        sampDesc.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
        sampDesc.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
        sampDesc.MaxLOD = D3D11_FLOAT32_MAX;
        return SUCCEEDED(m_device->CreateSamplerState(&sampDesc, &m_sampler));
    }

    bool CreateStreamTextures(uint32_t width, uint32_t height) {
        m_srvY.Reset(); m_srvUV.Reset(); m_texY.Reset(); m_texUV.Reset();
        D3D11_TEXTURE2D_DESC descY = {};
        descY.Width = width; descY.Height = height; descY.MipLevels = 1; descY.ArraySize = 1;
        descY.Format = DXGI_FORMAT_R8_UNORM; descY.SampleDesc.Count = 1;
        descY.Usage = D3D11_USAGE_DEFAULT; descY.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        if (FAILED(m_device->CreateTexture2D(&descY, nullptr, &m_texY)) ||
            FAILED(m_device->CreateShaderResourceView(m_texY.Get(), nullptr, &m_srvY))) return false;

        D3D11_TEXTURE2D_DESC descUV = descY;
        descUV.Width = width / 2; descUV.Height = height / 2; descUV.Format = DXGI_FORMAT_R8G8_UNORM;
        if (FAILED(m_device->CreateTexture2D(&descUV, nullptr, &m_texUV)) ||
            FAILED(m_device->CreateShaderResourceView(m_texUV.Get(), nullptr, &m_srvUV))) return false;

        m_streamWidth = width; m_streamHeight = height;
        return true;
    }

    std::mutex                          m_renderMutex;
    HWND                                m_hwnd = nullptr;
    ComPtr<ID3D11Device>                m_device;
    ComPtr<ID3D11DeviceContext>         m_context;
    ComPtr<IDXGISwapChain1>             m_swapChain;
    ComPtr<ID3D11RenderTargetView>      m_rtv;
    ComPtr<ID3D11VertexShader>          m_vs;
    ComPtr<ID3D11PixelShader>           m_ps;
    ComPtr<ID3D11SamplerState>          m_sampler;
    ComPtr<ID3D11Texture2D>             m_texY, m_texUV;
    ComPtr<ID3D11ShaderResourceView>    m_srvY, m_srvUV;
    uint32_t m_winWidth = 1280, m_winHeight = 720, m_streamWidth = 0, m_streamHeight = 0;
};

// ============================================================================
// ИНЪЕКЦИЯ ВВОДА И БУФЕР ОБМЕНА
// ============================================================================
class InputAndClipboardManager {
public:
    void InjectMouseEvent(const MouseEventPayload& ev, const RECT& desktopRect, bool isLocalLoopback) {
        if (isLocalLoopback) return;
        INPUT inp = {};
        inp.type = INPUT_MOUSE;
        inp.mi.dwExtraInfo = INJECTED_SIGNATURE;

        if (ev.flags & MBTN_MOVE) {
            if (ev.flags & MBTN_RELATIVE) {
                inp.mi.dx = ev.deltaX;
                inp.mi.dy = ev.deltaY;
                inp.mi.dwFlags |= MOUSEEVENTF_MOVE;
            } else {
                int deskW = std::max<int>(1, desktopRect.right - desktopRect.left);
                int deskH = std::max<int>(1, desktopRect.bottom - desktopRect.top);
                int targetX = desktopRect.left + (int)(ev.normX * (deskW - 1));
                int targetY = desktopRect.top  + (int)(ev.normY * (deskH - 1));
                int virtW = std::max<int>(1, GetSystemMetrics(SM_CXVIRTUALSCREEN));
                int virtH = std::max<int>(1, GetSystemMetrics(SM_CYVIRTUALSCREEN));
                int virtX = GetSystemMetrics(SM_XVIRTUALSCREEN);
                int virtY = GetSystemMetrics(SM_YVIRTUALSCREEN);

                inp.mi.dx = MulDiv(targetX - virtX, 65535, virtW - 1);
                inp.mi.dy = MulDiv(targetY - virtY, 65535, virtH - 1);
                inp.mi.dwFlags |= MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            }
        }

        if (ev.flags & MBTN_LEFT_DOWN)  inp.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
        if (ev.flags & MBTN_LEFT_UP)    inp.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
        if (ev.flags & MBTN_RIGHT_DOWN) inp.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
        if (ev.flags & MBTN_RIGHT_UP)   inp.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
        if (ev.flags & MBTN_MID_DOWN)   inp.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
        if (ev.flags & MBTN_MID_UP)     inp.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;
        if (ev.flags & MBTN_WHEEL_V)    { inp.mi.dwFlags |= MOUSEEVENTF_WHEEL;  inp.mi.mouseData = (DWORD)ev.wheelDelta; }
        if (ev.flags & MBTN_WHEEL_H)    { inp.mi.dwFlags |= MOUSEEVENTF_HWHEEL; inp.mi.mouseData = (DWORD)ev.wheelDelta; }

        SendInput(1, &inp, sizeof(INPUT));
    }

    void InjectKeyEvent(const KeyEventPayload& ev, bool isLocalLoopback) {
        if (isLocalLoopback) return;
        {
            std::lock_guard<std::mutex> lock(m_keyStateMutex);
            if (ev.vKey < 256) {
                m_heldVKeys[ev.vKey] = (ev.isDown != 0);
                m_heldScans[ev.vKey] = ev.scanCode;
                m_heldExt[ev.vKey]   = (ev.isExtended != 0);
            }
        }

        INPUT inp = {};
        inp.type = INPUT_KEYBOARD;
        inp.ki.wVk = ev.vKey;
        inp.ki.wScan = ev.scanCode;
        inp.ki.dwExtraInfo = INJECTED_SIGNATURE;

        if (ev.vKey == VK_LWIN || ev.vKey == VK_RWIN) {
            inp.ki.dwFlags = KEYEVENTF_EXTENDEDKEY | (ev.isDown ? 0 : KEYEVENTF_KEYUP);
        } else {
            if (ev.scanCode != 0) inp.ki.dwFlags = KEYEVENTF_SCANCODE;
            if (ev.isExtended)    inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            if (!ev.isDown)       inp.ki.dwFlags |= KEYEVENTF_KEYUP;
        }
        SendInput(1, &inp, sizeof(INPUT));
    }

    void ReleaseAllHeldKeys() {
        std::lock_guard<std::mutex> lock(m_keyStateMutex);
        std::vector<INPUT> inputs;
        auto AddVkRelease = [&](WORD vk, WORD scan, bool ext) {
            INPUT inp = {};
            inp.type = INPUT_KEYBOARD;
            inp.ki.wVk = vk;
            inp.ki.wScan = scan;
            inp.ki.dwExtraInfo = INJECTED_SIGNATURE;
            if (vk == VK_LWIN || vk == VK_RWIN || scan == 0)
                inp.ki.dwFlags = KEYEVENTF_KEYUP | (ext ? KEYEVENTF_EXTENDEDKEY : 0);
            else
                inp.ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP | (ext ? KEYEVENTF_EXTENDEDKEY : 0);
            inputs.push_back(inp);
        };

        for (int vk = 1; vk < 256; ++vk) {
            if (m_heldVKeys[vk]) {
                AddVkRelease((WORD)vk, m_heldScans[vk], m_heldExt[vk]);
                m_heldVKeys[vk] = false;
            }
        }
        AddVkRelease(VK_LWIN, 0x5B, true);
        AddVkRelease(VK_RWIN, 0x5C, true);
        AddVkRelease(VK_LSHIFT, (WORD)MapVirtualKeyW(VK_LSHIFT, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_RSHIFT, (WORD)MapVirtualKeyW(VK_RSHIFT, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_LCONTROL, (WORD)MapVirtualKeyW(VK_LCONTROL, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_RCONTROL, (WORD)MapVirtualKeyW(VK_RCONTROL, MAPVK_VK_TO_VSC), true);
        AddVkRelease(VK_LMENU, (WORD)MapVirtualKeyW(VK_LMENU, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_RMENU, (WORD)MapVirtualKeyW(VK_RMENU, MAPVK_VK_TO_VSC), true);

        if (!inputs.empty()) SendInput((UINT)inputs.size(), inputs.data(), sizeof(INPUT));
    }

    bool CaptureClipboardIfChanged(HWND hwndOwner, uint8_t& outFormat, std::vector<uint8_t>& outData, uint8_t outHash[32]) {
        if (m_ignoreNextEvent.exchange(false)) return false;
        bool opened = false;
        for (int i = 0; i < 5; ++i) { if (OpenClipboard(hwndOwner)) { opened = true; break; } Sleep(5); }
        if (!opened) return false;

        bool captured = false;
        if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                SIZE_T bytes = GlobalSize(hData);
                const void* ptr = GlobalLock(hData);
                if (ptr && bytes > 0 && bytes <= MAX_CLIPBOARD_BYTES) {
                    outFormat = CLIP_FORMAT_TEXT_UTF16;
                    outData.assign(static_cast<const uint8_t*>(ptr), static_cast<const uint8_t*>(ptr) + bytes);
                    captured = true;
                }
                if (ptr) GlobalUnlock(hData);
            }
        } else if (IsClipboardFormatAvailable(CF_DIB)) {
            HANDLE hData = GetClipboardData(CF_DIB);
            if (hData) {
                SIZE_T bytes = GlobalSize(hData);
                const void* ptr = GlobalLock(hData);
                if (ptr && bytes > 0 && bytes <= MAX_CLIPBOARD_BYTES) {
                    outFormat = CLIP_FORMAT_IMAGE_DIB;
                    outData.assign(static_cast<const uint8_t*>(ptr), static_cast<const uint8_t*>(ptr) + bytes);
                    captured = true;
                }
                if (ptr) GlobalUnlock(hData);
            }
        }
        CloseClipboard();
        if (!captured) return false;

        CryptoEngine::ComputeSHA256(outData.data(), outData.size(), outHash);
        std::lock_guard<std::mutex> lock(m_hashMutex);
        if (memcmp(outHash, m_lastSyncedHash, 32) == 0) return false;
        memcpy(m_lastSyncedHash, outHash, 32);
        return true;
    }

    void ApplyRemoteClipboard(HWND hwndOwner, uint8_t format, const std::vector<uint8_t>& data, const uint8_t hash[32]) {
        if (data.empty() || data.size() > MAX_CLIPBOARD_BYTES) return;
        {
            std::lock_guard<std::mutex> lock(m_hashMutex);
            if (memcmp(hash, m_lastSyncedHash, 32) == 0) return;
            memcpy(m_lastSyncedHash, hash, 32);
        }
        m_ignoreNextEvent = true;
        bool opened = false;
        for (int i = 0; i < 5; ++i) { if (OpenClipboard(hwndOwner)) { opened = true; break; } Sleep(5); }
        if (!opened) return;

        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, data.size());
        if (hMem) {
            void* dst = GlobalLock(hMem);
            if (dst) {
                memcpy(dst, data.data(), data.size());
                GlobalUnlock(hMem);
                if (!SetClipboardData((format == CLIP_FORMAT_IMAGE_DIB) ? CF_DIB : CF_UNICODETEXT, hMem))
                    GlobalFree(hMem);
            } else GlobalFree(hMem);
        }
        CloseClipboard();
    }

private:
    std::mutex        m_keyStateMutex;
    bool              m_heldVKeys[256] = {};
    uint16_t          m_heldScans[256] = {};
    bool              m_heldExt[256]   = {};
    std::atomic<bool> m_ignoreNextEvent{ false };
    std::mutex        m_hashMutex;
    uint8_t           m_lastSyncedHash[32] = {};
};

// ============================================================================
// ВЫСОКОТОЧНЫЙ QPC-ТАЙМЕР КАДРОВ (FRAME PACER) И DIRECT2D ДВОЙНОЙ БУФЕР
// ============================================================================
class UiFramePacer {
public:
    static constexpr size_t HISTORY_SIZE = 24;

    void Initialize() {
        RefreshTargetHz();
        ResetTiming();
    }

    void RefreshTargetHz() {
        DEVMODEW dm = {};
        dm.dmSize = sizeof(dm);
        uint32_t hz = 60;
        if (EnumDisplaySettingsW(nullptr, ENUM_CURRENT_SETTINGS, &dm) &&
            dm.dmDisplayFrequency >= 30 && dm.dmDisplayFrequency <= 360) {
            hz = dm.dmDisplayFrequency;
        }
        m_targetHz = hz;
        m_targetFrameUs = 1000000ULL / hz;
    }

    void ResetTiming() {
        uint64_t now = NowMicros();
        m_lastFrameUs = now;
        m_nextTargetUs = now;
        m_statsWindowStartUs = now;
        m_framesInWindow = 0;
    }

    bool WaitOrCheckFrameReady(bool animateActive, float& outDtSec) {
        outDtSec = 0.0f;
        if (!animateActive) {
            MsgWaitForMultipleObjectsEx(0, nullptr, 100, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
            ResetTiming();
            return false;
        }

        uint64_t now = NowMicros();
        if (m_nextTargetUs == 0) {
            m_nextTargetUs = now;
            m_lastFrameUs = now;
            m_statsWindowStartUs = now;
        }

        if (now < m_nextTargetUs) {
            uint64_t remUs = m_nextTargetUs - now;
            if (remUs > 1800ULL) {
                DWORD waitMs = (DWORD)((remUs - 1200ULL) / 1000ULL);
                MsgWaitForMultipleObjectsEx(0, nullptr, waitMs, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
                return false;
            }
            while (NowMicros() < m_nextTargetUs) {
                MSG peek = {};
                if (PeekMessageW(&peek, nullptr, 0, 0, PM_NOREMOVE)) return false;
                YieldProcessor();
            }
            now = NowMicros();
        }

        uint64_t dtUs = (m_lastFrameUs > 0 && now > m_lastFrameUs) ? (now - m_lastFrameUs) : m_targetFrameUs;
        outDtSec = std::clamp((float)dtUs / 1000000.0f, 0.0005f, 0.08f);
        m_lastFrameUs = now;

        m_nextTargetUs += m_targetFrameUs;
        if (now > m_nextTargetUs + m_targetFrameUs * 2) {
            m_nextTargetUs = now + m_targetFrameUs;
        }

        m_frameHistoryMs[m_historyCursor] = (float)dtUs / 1000.0f;
        m_historyCursor = (m_historyCursor + 1) % HISTORY_SIZE;

        m_framesInWindow++;
        uint64_t windowElapsedUs = now - m_statsWindowStartUs;
        if (windowElapsedUs >= 220000ULL && m_framesInWindow > 0) {
            m_displayFps = (float)((double)m_framesInWindow * 1000000.0 / (double)windowElapsedUs);
            m_displayFrameMs = (float)(((double)windowElapsedUs / 1000.0) / (double)m_framesInWindow);
            m_framesInWindow = 0;
            m_statsWindowStartUs = now;
        }
        return true;
    }

    float    GetDisplayFps() const { return m_displayFps; }
    float    GetDisplayFrameMs() const { return m_displayFrameMs; }
    uint32_t GetTargetHz() const { return m_targetHz; }
    const std::array<float, HISTORY_SIZE>& GetHistoryMs() const { return m_frameHistoryMs; }
    size_t   GetHistoryCursor() const { return m_historyCursor; }

private:
    uint32_t m_targetHz = 60;
    uint64_t m_targetFrameUs = 16666;
    uint64_t m_lastFrameUs = 0;
    uint64_t m_nextTargetUs = 0;
    uint64_t m_statsWindowStartUs = 0;
    uint32_t m_framesInWindow = 0;
    float    m_displayFps = 60.0f;
    float    m_displayFrameMs = 16.67f;
    std::array<float, HISTORY_SIZE> m_frameHistoryMs = {};
    size_t   m_historyCursor = 0;
};

static inline D2D1_COLOR_F HexColor(uint32_t rgb, float alpha = 1.0f) {
    return D2D1::ColorF(
        ((rgb >> 16) & 0xFF) / 255.0f,
        ((rgb >> 8)  & 0xFF) / 255.0f,
        (rgb & 0xFF)         / 255.0f,
        alpha
    );
}

static inline D2D1_COLOR_F LerpColor(const D2D1_COLOR_F& a, const D2D1_COLOR_F& b, float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    return D2D1::ColorF(
        a.r + (b.r - a.r) * t,
        a.g + (b.g - a.g) * t,
        a.b + (b.b - a.b) * t,
        a.a + (b.a - a.a) * t
    );
}

static inline float SmoothApproach(float current, float target, float speed, float dt) {
    float alpha = 1.0f - std::exp(-speed * dt);
    float next = current + (target - current) * alpha;
    if (std::fabs(next - target) < 0.001f) return target;
    return next;
}

class D2DOffscreenTarget {
public:
    ~D2DOffscreenTarget() { Destroy(); }

    bool BeginFrame(HWND hwnd, uint32_t width, uint32_t height, ID2D1DCRenderTarget** outRt) {
        if (width == 0 || height == 0) return false;
        if (!EnsureResources(hwnd, width, height)) return false;

        RECT rc = { 0, 0, (LONG)width, (LONG)height };
        if (FAILED(m_dcTarget->BindDC(m_memDC, &rc))) {
            ResetTarget();
            return false;
        }
        m_dcTarget->BeginDraw();
        *outRt = m_dcTarget.Get();
        return true;
    }

    void EndFrameAndBlit(HDC targetDC, uint32_t width, uint32_t height) {
        if (!m_dcTarget) return;
        HRESULT hr = m_dcTarget->EndDraw();
        if (hr == D2DERR_RECREATE_TARGET) {
            ResetTarget();
            return;
        }
        BitBlt(targetDC, 0, 0, (int)width, (int)height, m_memDC, 0, 0, SRCCOPY);
    }

    ID2D1SolidColorBrush* Brush(const D2D1_COLOR_F& col) {
        if (!m_brush && m_dcTarget) {
            m_dcTarget->CreateSolidColorBrush(col, &m_brush);
        } else if (m_brush) {
            m_brush->SetColor(col);
        }
        return m_brush.Get();
    }

    void DrawTextBox(const std::wstring& text, IDWriteTextFormat* fmt, const D2D1_RECT_F& rect, const D2D1_COLOR_F& col) {
        if (!m_dcTarget || !m_dwriteFactory || !fmt || text.empty()) return;
        float w = std::max(1.0f, rect.right - rect.left);
        float h = std::max(1.0f, rect.bottom - rect.top);
        ComPtr<IDWriteTextLayout> layout;
        if (SUCCEEDED(m_dwriteFactory->CreateTextLayout(text.c_str(), (UINT32)text.size(), fmt, w, h, &layout))) {
            m_dcTarget->DrawTextLayout(D2D1::Point2F(rect.left, rect.top), layout.Get(), Brush(col), D2D1_DRAW_TEXT_OPTIONS_CLIP);
        }
    }

    void UpdateFontsForDpi(UINT dpi) {
        if (!m_dwriteFactory) {
            DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                                reinterpret_cast<IUnknown**>(m_dwriteFactory.GetAddressOf()));
        }
        if (!m_dwriteFactory || (m_fontDpi == dpi && m_fmtTitle)) return;
        m_fontDpi = dpi;

        auto MakeFmt = [&](const wchar_t* family, float pt96, DWRITE_FONT_WEIGHT weight,
                           DWRITE_TEXT_ALIGNMENT hAlign, DWRITE_PARAGRAPH_ALIGNMENT vAlign,
                           bool ellipsis, ComPtr<IDWriteTextFormat>& outFmt) {
            outFmt.Reset();
            float px = pt96 * ((float)dpi / 96.0f);
            if (SUCCEEDED(m_dwriteFactory->CreateTextFormat(
                    family, nullptr, weight, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
                    px, L"ru-RU", &outFmt))) {
                outFmt->SetTextAlignment(hAlign);
                outFmt->SetParagraphAlignment(vAlign);
                if (ellipsis) {
                    ComPtr<IDWriteInlineObject> trimSign;
                    if (SUCCEEDED(m_dwriteFactory->CreateEllipsisTrimmingSign(outFmt.Get(), &trimSign))) {
                        DWRITE_TRIMMING trim = { DWRITE_TRIMMING_GRANULARITY_CHARACTER, 0, 0 };
                        outFmt->SetTrimming(&trim, trimSign.Get());
                    }
                }
            }
        };

        MakeFmt(L"Segoe UI", 16.0f, DWRITE_FONT_WEIGHT_BOLD,      DWRITE_TEXT_ALIGNMENT_LEADING,  DWRITE_PARAGRAPH_ALIGNMENT_CENTER, true,  m_fmtTitle);
        MakeFmt(L"Segoe UI", 13.5f, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_TEXT_ALIGNMENT_LEADING,  DWRITE_PARAGRAPH_ALIGNMENT_CENTER, true,  m_fmtCardTitle);
        MakeFmt(L"Segoe UI", 12.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_TEXT_ALIGNMENT_CENTER,   DWRITE_PARAGRAPH_ALIGNMENT_CENTER, true,  m_fmtButton);
        MakeFmt(L"Segoe UI", 11.8f, DWRITE_FONT_WEIGHT_NORMAL,    DWRITE_TEXT_ALIGNMENT_LEADING,  DWRITE_PARAGRAPH_ALIGNMENT_CENTER, true,  m_fmtLabel);
        MakeFmt(L"Segoe UI", 11.2f, DWRITE_FONT_WEIGHT_NORMAL,    DWRITE_TEXT_ALIGNMENT_LEADING,  DWRITE_PARAGRAPH_ALIGNMENT_NEAR,   false, m_fmtBody);
        MakeFmt(L"Segoe UI", 10.5f, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_TEXT_ALIGNMENT_CENTER,   DWRITE_PARAGRAPH_ALIGNMENT_CENTER, true,  m_fmtBadge);
        MakeFmt(L"Consolas", 11.2f, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_TEXT_ALIGNMENT_CENTER,   DWRITE_PARAGRAPH_ALIGNMENT_CENTER, true,  m_fmtMono);
    }

    void Destroy() {
        ResetTarget();
        DestroyDib();
        m_fmtTitle.Reset(); m_fmtCardTitle.Reset(); m_fmtButton.Reset();
        m_fmtLabel.Reset(); m_fmtBody.Reset(); m_fmtBadge.Reset(); m_fmtMono.Reset();
        m_dwriteFactory.Reset();
        m_d2dFactory.Reset();
    }

    IDWriteTextFormat* FmtTitle()     const { return m_fmtTitle.Get(); }
    IDWriteTextFormat* FmtCardTitle() const { return m_fmtCardTitle.Get(); }
    IDWriteTextFormat* FmtButton()    const { return m_fmtButton.Get(); }
    IDWriteTextFormat* FmtLabel()     const { return m_fmtLabel.Get(); }
    IDWriteTextFormat* FmtBody()      const { return m_fmtBody.Get(); }
    IDWriteTextFormat* FmtBadge()     const { return m_fmtBadge.Get(); }
    IDWriteTextFormat* FmtMono()      const { return m_fmtMono.Get(); }

private:
    bool EnsureResources(HWND hwnd, uint32_t width, uint32_t height) {
        if (!m_d2dFactory) {
            if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, __uuidof(ID2D1Factory),
                                         nullptr, reinterpret_cast<void**>(m_d2dFactory.GetAddressOf()))))
                return false;
        }
        if (!m_dwriteFactory) {
            if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                                           reinterpret_cast<IUnknown**>(m_dwriteFactory.GetAddressOf()))))
                return false;
        }
        UpdateFontsForDpi(GetDpiForWindow(hwnd));

        if (!m_dcTarget) {
            D2D1_RENDER_TARGET_PROPERTIES props = D2D1::RenderTargetProperties(
                D2D1_RENDER_TARGET_TYPE_DEFAULT,
                D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED),
                96.0f, 96.0f,
                D2D1_RENDER_TARGET_USAGE_NONE,
                D2D1_FEATURE_LEVEL_DEFAULT
            );
            if (FAILED(m_d2dFactory->CreateDCRenderTarget(&props, &m_dcTarget)))
                return false;
            m_dcTarget->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
        }

        if (!m_memDC || !m_dib || m_width != width || m_height != height) {
            DestroyDib();
            HDC screenDC = GetDC(hwnd);
            m_memDC = CreateCompatibleDC(screenDC);
            ReleaseDC(hwnd, screenDC);
            if (!m_memDC) return false;

            BITMAPINFO bmi = {};
            bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bmi.bmiHeader.biWidth = (LONG)width;
            bmi.bmiHeader.biHeight = -(LONG)height;
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB;

            void* bits = nullptr;
            m_dib = CreateDIBSection(m_memDC, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
            if (!m_dib) {
                DeleteDC(m_memDC);
                m_memDC = nullptr;
                return false;
            }
            m_oldBmp = SelectObject(m_memDC, m_dib);
            m_width = width;
            m_height = height;
        }
        return true;
    }

    void ResetTarget() {
        m_brush.Reset();
        m_dcTarget.Reset();
    }

    void DestroyDib() {
        if (m_memDC) {
            if (m_oldBmp) SelectObject(m_memDC, m_oldBmp);
            DeleteDC(m_memDC);
            m_memDC = nullptr;
            m_oldBmp = nullptr;
        }
        if (m_dib) {
            DeleteObject(m_dib);
            m_dib = nullptr;
        }
        m_width = 0;
        m_height = 0;
    }

    ComPtr<ID2D1Factory>          m_d2dFactory;
    ComPtr<IDWriteFactory>        m_dwriteFactory;
    ComPtr<ID2D1DCRenderTarget>   m_dcTarget;
    ComPtr<ID2D1SolidColorBrush>  m_brush;
    ComPtr<IDWriteTextFormat>     m_fmtTitle, m_fmtCardTitle, m_fmtButton, m_fmtLabel, m_fmtBody, m_fmtBadge, m_fmtMono;
    HDC     m_memDC = nullptr;
    HBITMAP m_dib = nullptr;
    HGDIOBJ m_oldBmp = nullptr;
    uint32_t m_width = 0, m_height = 0;
    UINT     m_fontDpi = 0;
};

// ============================================================================
// МОДЕЛЬ КНОПОК, ПОЛЕЙ И МОДАЛЬНЫХ ОКОН В ТЁМНОЙ ТЕМЕ
// ============================================================================
enum ButtonVariant : uint8_t {
    BTN_VAR_SECONDARY = 0,
    BTN_VAR_PRIMARY_BLUE,
    BTN_VAR_PRIMARY_GREEN,
    BTN_VAR_DANGER,
    BTN_VAR_GHOST
};

struct CanvasButton {
    int           id = 0;
    D2D1_RECT_F   rect = {};
    std::wstring  text;
    ButtonVariant variant = BTN_VAR_SECONDARY;
    bool          enabled = true;
    float         hoverT = 0.0f;
    float         pressT = 0.0f;
};

struct CanvasToggle {
    D2D1_RECT_F  hitRect = {};
    D2D1_RECT_F  trackRect = {};
    std::wstring label;
    bool         checked = false;
    float        hoverT = 0.0f;
    float        knobT = 0.0f;
};

struct InputFrameBox {
    HWND        hwnd = nullptr;
    D2D1_RECT_F rect = {};
    std::wstring label;
    D2D1_RECT_F labelRect = {};
    float       focusT = 0.0f;
    bool        isReadOnly = false;
};

enum class ModalPinMode {
    SetHostSessionPin,
    ConfirmExitHostSession
};

enum GuiControlIds : int {
    IDC_EDIT_SRV_NAME    = 102,
    IDC_EDIT_SRV_PASS    = 104,
    IDC_EDIT_SRV_PORT    = 106,
    IDC_BTN_SRV_TOGGLE   = 108,
    IDC_BTN_SRV_TRAY     = 109,
    IDC_BTN_SRV_SENDFILE = 110,
    IDC_TOGGLE_AUTO_MIN  = 112,

    IDC_BTN_CLI_SCAN     = 201,
    IDC_LIST_HOSTS       = 202,
    IDC_EDIT_CLI_IP      = 204,
    IDC_EDIT_CLI_PORT    = 205,
    IDC_EDIT_CLI_PASS    = 207,
    IDC_BTN_CLI_CONNECT  = 208,
    IDC_BTN_CLI_SENDFILE = 209,

    IDM_TRAY_RESTORE     = 301,
    IDM_TRAY_STOP_SRV    = 302,
    IDM_TRAY_EXIT        = 303,

    IDC_MODAL_EDIT_PIN   = 401,
    IDC_MODAL_BTN_OK     = 402,
    IDC_MODAL_BTN_CANCEL = 403,
    IDC_MODAL_BTN_EYE    = 404
};

static constexpr UINT WM_APP_UPDATE_UI     = WM_APP + 10;
static constexpr UINT WM_APP_HOST_FOUND    = WM_APP + 11;
static constexpr UINT WM_APP_CLIENT_LOST   = WM_APP + 12;
static constexpr UINT WM_APP_TRAY_ICON     = WM_APP + 13;
static constexpr UINT WM_APP_AUTO_MINIMIZE = WM_APP + 14;

struct DiscoveredHostInfo {
    std::string name, ip;
    uint16_t    port;
    uint32_t    width, height;
};

class RemoteDesktopApp {
public:
    HWND  m_hwndMain = nullptr;
    HWND  m_hwndViewer = nullptr;
    HFONT m_hEditFont = nullptr;
    HFONT m_hListFont = nullptr;
    HFONT m_hListFontBold = nullptr;
    HBRUSH m_hDarkInputBrush = nullptr;
    HBRUSH m_hDarkListBrush  = nullptr;
    HHOOK m_hKeyboardHook = nullptr;
    bool  m_trayAdded = false;

    // Редактируемые Win32-контролы (внутри кастомных рамок Direct2D)
    HWND m_editSrvName = nullptr, m_editSrvPass = nullptr, m_editSrvPort = nullptr;
    HWND m_listHosts   = nullptr;
    HWND m_editCliIp   = nullptr, m_editCliPort = nullptr, m_editCliPass = nullptr;

    // Рендеринг и pacer главного меню
    UiFramePacer       m_framePacer;
    D2DOffscreenTarget m_mainCanvas;
    float              m_pulsePhase = 0.0f;
    float              m_srvCardGlow = 0.0f;
    float              m_cliCardGlow = 0.0f;
    float              m_listFocusT  = 0.0f;
    D2D1_RECT_F        m_srvCardRect = {};
    D2D1_RECT_F        m_cliCardRect = {};
    D2D1_RECT_F        m_listFrameRect = {};
    D2D1_RECT_F        m_srvStatusBoxRect = {};
    D2D1_RECT_F        m_cliStatusBoxRect = {};
    D2D1_RECT_F        m_headerRect = {};
    std::array<InputFrameBox, 6> m_inputFrames;
    std::array<CanvasButton, 6>  m_buttons;
    CanvasToggle       m_autoMinToggle;
    int                m_hoveredBtnId = -1;
    int                m_pressedBtnId = -1;
    bool               m_hoveredToggle = false;
    bool               m_pressedToggle = false;
    bool               m_trackingMouse = false;

    // Состояние модального диалога PIN-кода сессии
    struct PinModalState {
        bool               active = false;
        ModalPinMode       mode = ModalPinMode::SetHostSessionPin;
        HWND               hwnd = nullptr;
        HWND               hwndEdit = nullptr;
        D2DOffscreenTarget canvas;
        std::wstring       errorText;
        float              shakeTimer = 0.0f;
        bool               showPassword = false;
        bool               confirmed = false;
        bool               trackingMouse = false;
        int                hoveredBtnId = -1;
        int                pressedBtnId = -1;
        D2D1_RECT_F        editFrameRect = {};
        std::array<CanvasButton, 3> buttons; // OK, Cancel, Show/Hide
    } m_modal;

    // Runtime PIN-код текущей хост-сессии (хранится ТОЛЬКО в памяти в виде солёного SHA-256)
    std::mutex m_pinMutex;
    bool       m_hasSessionPin = false;
    uint8_t    m_sessionPinSalt[32] = {};
    uint8_t    m_sessionPinHash[32] = {};

    // Состояние Сервера
    std::atomic<bool>     m_serverRunning{ false };
    std::atomic<bool>     m_clientAuthorized{ false };
    std::atomic<bool>     m_autoMinimize{ false };
    std::atomic<bool>     m_forceIdrNextFrame{ true };
    std::atomic<uint32_t> m_srvFps{ 0 }, m_srvEncodeUs{ 0 }, m_srvClientDecodeUs{ 0 }, m_srvRttUs{ 0 };
    std::mutex            m_srvInfoMutex;
    std::string           m_radminIp, m_connectedClientIp;
    uint16_t              m_serverPort = DEFAULT_STREAM_PORT;

    SOCKET                m_srvListenTcp = INVALID_SOCKET, m_srvClientTcp = INVALID_SOCKET;
    SOCKET                m_srvVideoUdp  = INVALID_SOCKET, m_srvDiscUdp   = INVALID_SOCKET;
    std::mutex            m_srvTcpSendMutex, m_srvClientUdpMutex;
    sockaddr_in           m_srvClientUdpAddr = {};
    bool                  m_hasClientUdpAddr = false;
    uint64_t              m_activeUdpToken = 0;
    uint8_t               m_srvSessionKey[32] = {};
    std::thread           m_srvAcceptThread, m_srvDiscoveryThread, m_srvCaptureThread;

    // Состояние Клиента
    std::atomic<bool>     m_clientRunning{ false };
    std::atomic<bool>     m_viewerVisible{ false };
    std::atomic<bool>     m_scanInProgress{ false };
    std::atomic<uint32_t> m_cliFps{ 0 }, m_cliEncodeUs{ 0 }, m_cliDecodeUs{ 0 }, m_cliRttUs{ 0 };
    SOCKET                m_cliTcpSock = INVALID_SOCKET, m_cliUdpSock = INVALID_SOCKET;
    std::mutex            m_cliTcpSendMutex;
    uint8_t               m_cliSessionKey[32] = {};
    uint64_t              m_cliUdpToken = 0, m_lastIdrReqUs = 0;
    std::thread           m_cliTcpThread, m_cliUdpThread;
    D3D11ClientRenderer   m_renderer;
    InputAndClipboardManager m_inputAndClip;

    // Состояние передачи файлов
    std::atomic<bool>     m_srvSendingFile{ false };
    std::atomic<bool>     m_cliSendingFile{ false };
    std::mutex            m_fileStatusMutex;
    std::wstring          m_srvFileStatus = L"Файлы: готово (сохранение на Рабочий стол)";
    std::wstring          m_cliFileStatus = L"Файлы: готово (сохранение на Рабочий стол)";
    float                 m_srvFilePct = 0.0f;
    float                 m_cliFilePct = 0.0f;

    std::mutex                      m_hostsMutex;
    std::vector<DiscoveredHostInfo> m_discoveredHosts;
    bool m_isViewerFullscreen = false;
    WINDOWPLACEMENT m_viewerPrevPlacement = { sizeof(WINDOWPLACEMENT) };

    // ========================================================================
    // УПРАВЛЕНИЕ ДИНАМИЧЕСКИМ PIN-КОДОМ СЕССИИ
    // ========================================================================
    bool SetRuntimeSessionPin(const wchar_t* pinChars, size_t charCount) {
        if (!pinChars || charCount == 0) return false;
        uint8_t salt[32] = {};
        if (!CryptoEngine::RandomBytes(salt, sizeof(salt))) return false;

        std::vector<uint8_t> material(charCount * sizeof(wchar_t) + sizeof(salt));
        memcpy(material.data(), pinChars, charCount * sizeof(wchar_t));
        memcpy(material.data() + charCount * sizeof(wchar_t), salt, sizeof(salt));

        uint8_t digest[32] = {};
        bool ok = CryptoEngine::ComputeSHA256(material.data(), material.size(), digest);
        SecureZeroMemory(material.data(), material.size());
        if (!ok) return false;

        std::lock_guard<std::mutex> lock(m_pinMutex);
        memcpy(m_sessionPinSalt, salt, sizeof(salt));
        memcpy(m_sessionPinHash, digest, sizeof(digest));
        m_hasSessionPin = true;
        SecureZeroMemory(salt, sizeof(salt));
        SecureZeroMemory(digest, sizeof(digest));
        return true;
    }

    bool VerifyRuntimeSessionPin(const wchar_t* pinChars, size_t charCount) {
        if (!pinChars || charCount == 0) return false;
        uint8_t saltCopy[32] = {}, expectedCopy[32] = {};
        {
            std::lock_guard<std::mutex> lock(m_pinMutex);
            if (!m_hasSessionPin) return false;
            memcpy(saltCopy, m_sessionPinSalt, 32);
            memcpy(expectedCopy, m_sessionPinHash, 32);
        }

        std::vector<uint8_t> material(charCount * sizeof(wchar_t) + sizeof(saltCopy));
        memcpy(material.data(), pinChars, charCount * sizeof(wchar_t));
        memcpy(material.data() + charCount * sizeof(wchar_t), saltCopy, sizeof(saltCopy));

        uint8_t actual[32] = {};
        bool ok = CryptoEngine::ComputeSHA256(material.data(), material.size(), actual);
        bool match = ok && CryptoEngine::ConstantTimeEqual32(actual, expectedCopy);

        SecureZeroMemory(material.data(), material.size());
        SecureZeroMemory(actual, sizeof(actual));
        SecureZeroMemory(saltCopy, sizeof(saltCopy));
        SecureZeroMemory(expectedCopy, sizeof(expectedCopy));
        return match;
    }

    void ClearRuntimeSessionPin() {
        std::lock_guard<std::mutex> lock(m_pinMutex);
        m_hasSessionPin = false;
        SecureZeroMemory(m_sessionPinSalt, sizeof(m_sessionPinSalt));
        SecureZeroMemory(m_sessionPinHash, sizeof(m_sessionPinHash));
    }

    // Объявления методов реализации модального окна и главного цикла отрисовки
    bool RunPinModalDialog(ModalPinMode mode);
    void HandleCloseRequest();
    void TickAndRenderUi(float dt);
    void PaintMainWindow(HWND hwnd);
    void PaintModalWindow(HWND hwnd);

    void SetFileStatus(bool forServer, const std::wstring& text, float pct = -1.0f) {
        {
            std::lock_guard<std::mutex> lock(m_fileStatusMutex);
            if (forServer) {
                m_srvFileStatus = text;
                if (pct >= 0.0f) m_srvFilePct = pct;
            } else {
                m_cliFileStatus = text;
                if (pct >= 0.0f) m_cliFilePct = pct;
            }
        }
        if (m_hwndMain) PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);
    }

    void PromptAndSendFile(bool fromServer) {
        if (fromServer) {
            if (!m_serverRunning || !m_clientAuthorized || m_srvClientTcp == INVALID_SOCKET) {
                MessageBoxW(m_hwndMain, L"Нет подключенного клиента для отправки файла!", L"Отправка файла", MB_ICONWARNING);
                return;
            }
            if (m_srvSendingFile) {
                MessageBoxW(m_hwndMain, L"Дождитесь завершения текущей отправки файла!", L"Отправка файла", MB_ICONINFORMATION);
                return;
            }
        } else {
            if (!m_clientRunning || m_cliTcpSock == INVALID_SOCKET) {
                MessageBoxW(m_hwndMain, L"Сначала подключитесь к удаленному ПК!", L"Отправка файла", MB_ICONWARNING);
                return;
            }
            if (m_cliSendingFile) {
                MessageBoxW(m_hwndMain, L"Дождитесь завершения текущей отправки файла!", L"Отправка файла", MB_ICONINFORMATION);
                return;
            }
        }

        wchar_t filePath[MAX_PATH] = {};
        OPENFILENAMEW ofn = { sizeof(OPENFILENAMEW) };
        ofn.hwndOwner = m_hwndMain;
        ofn.lpstrFilter = L"Все файлы (*.*)\0*.*\0";
        ofn.lpstrFile = filePath;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrTitle = fromServer ? L"Выберите файл для отправки клиенту" : L"Выберите файл для отправки на удаленный ПК";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

        if (GetOpenFileNameW(&ofn)) {
            SendFileAsync(filePath, fromServer);
        }
    }

    void SendFileAsync(const std::wstring& filePath, bool fromServer) {
        if (fromServer) {
            if (m_srvSendingFile.exchange(true)) return;
        } else {
            if (m_cliSendingFile.exchange(true)) return;
        }

        std::thread([this, filePath, fromServer]() {
            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                SetFileStatus(fromServer, L"Ошибка открытия файла для отправки!", 0.0f);
                if (fromServer) m_srvSendingFile = false; else m_cliSendingFile = false;
                return;
            }

            LARGE_INTEGER fileSizeLi = {};
            GetFileSizeEx(hFile, &fileSizeLi);
            uint64_t totalSize = (uint64_t)fileSizeLi.QuadPart;

            std::wstring baseName = filePath;
            size_t slash = baseName.find_last_of(L"\\/");
            if (slash != std::wstring::npos) baseName = baseName.substr(slash + 1);

            uint32_t transferId = (uint32_t)(NowMicros() & 0xFFFFFFFFu);
            if (transferId == 0) transferId = 1;

            SOCKET& sockRef = fromServer ? m_srvClientTcp : m_cliTcpSock;
            std::mutex& mtxRef = fromServer ? m_srvTcpSendMutex : m_cliTcpSendMutex;
            const uint8_t* keyPtr = fromServer ? m_srvSessionKey : m_cliSessionKey;

            FileStartPayload startPkt = {};
            startPkt.transferId = transferId;
            startPkt.totalSize = totalSize;
            wcsncpy_s(startPkt.fileName, baseName.c_str(), _TRUNCATE);

            FileStartPayload encStart = startPkt;
            CryptoEngine::StreamCrypt(reinterpret_cast<uint8_t*>(&encStart), sizeof(encStart), keyPtr, 4);

            ControlHeader startHdr = { MAGIC_CONTROL, CTRL_FILE_START, sizeof(encStart) };
            bool sendOk = false;
            {
                std::lock_guard<std::mutex> lock(mtxRef);
                sendOk = SendAllTcp(sockRef, &startHdr, sizeof(startHdr)) &&
                         SendAllTcp(sockRef, &encStart, sizeof(encStart));
            }

            SetFileStatus(fromServer, L"Отправка: " + baseName + L" (0%)", 0.0f);

            std::vector<uint8_t> chunkBuf(sizeof(FileChunkHeaderPayload) + FILE_CHUNK_SIZE);
            uint64_t sentBytes = 0;
            uint64_t lastUiUs = 0;

            while (sendOk && sentBytes < totalSize) {
                if (fromServer && (!m_serverRunning || !m_clientAuthorized)) { sendOk = false; break; }
                if (!fromServer && !m_clientRunning) { sendOk = false; break; }

                DWORD toRead = (DWORD)std::min<uint64_t>(FILE_CHUNK_SIZE, totalSize - sentBytes);
                DWORD bytesRead = 0;
                if (!ReadFile(hFile, chunkBuf.data() + sizeof(FileChunkHeaderPayload), toRead, &bytesRead, nullptr) || bytesRead == 0) {
                    sendOk = false;
                    break;
                }

                auto* cHdr = reinterpret_cast<FileChunkHeaderPayload*>(chunkBuf.data());
                cHdr->transferId = transferId;
                cHdr->offset = sentBytes;
                cHdr->chunkSize = bytesRead;

                CryptoEngine::StreamCrypt(chunkBuf.data() + sizeof(FileChunkHeaderPayload), bytesRead, keyPtr, 5 ^ sentBytes);

                uint32_t totalPayload = sizeof(FileChunkHeaderPayload) + bytesRead;
                ControlHeader pktHdr = { MAGIC_CONTROL, CTRL_FILE_CHUNK, totalPayload };
                {
                    std::lock_guard<std::mutex> lock(mtxRef);
                    sendOk = SendAllTcp(sockRef, &pktHdr, sizeof(pktHdr)) &&
                             SendAllTcp(sockRef, chunkBuf.data(), totalPayload);
                }
                if (!sendOk) break;

                sentBytes += bytesRead;
                uint64_t now = NowMicros();
                if (now - lastUiUs > 100000ULL || sentBytes == totalSize) {
                    lastUiUs = now;
                    float frac = (totalSize > 0) ? std::clamp((float)sentBytes / (float)totalSize, 0.0f, 1.0f) : 1.0f;
                    int pct = (int)(frac * 100.0f);
                    std::wstringstream ss;
                    ss << L"Отправка: " << baseName << L" [" << pct << L"%, "
                       << std::fixed << std::setprecision(1) << (sentBytes / 1048576.0)
                       << L" / " << (totalSize / 1048576.0) << L" МБ]";
                    SetFileStatus(fromServer, ss.str(), frac);
                }
            }

            CloseHandle(hFile);

            if (sockRef != INVALID_SOCKET) {
                FileEndPayload endPkt = { transferId, (uint8_t)(sendOk ? 1 : 0) };
                ControlHeader endHdr = { MAGIC_CONTROL, CTRL_FILE_END, sizeof(endPkt) };
                std::lock_guard<std::mutex> lock(mtxRef);
                SendAllTcp(sockRef, &endHdr, sizeof(endHdr));
                SendAllTcp(sockRef, &endPkt, sizeof(endPkt));
            }

            SetFileStatus(fromServer,
                sendOk ? (L"Файл успешно отправлен: " + baseName) : (L"Ошибка при отправке файла: " + baseName),
                sendOk ? 1.0f : 0.0f);

            if (fromServer) m_srvSendingFile = false;
            else            m_cliSendingFile = false;
        }).detach();
    }

    // ========================================================================
    // СИСТЕМНЫЙ ТРЕЙ
    // ========================================================================
    void ShowInTray(bool hideWindow) {
        if (!m_trayAdded) {
            NOTIFYICONDATAW nid = { sizeof(NOTIFYICONDATAW) };
            nid.hWnd = m_hwndMain;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_APP_TRAY_ICON;
            nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
            wcscpy_s(nid.szTip, L"Radmin Ultra RD");
            Shell_NotifyIconW(NIM_ADD, &nid);
            m_trayAdded = true;
        }
        UpdateTrayTooltip();
        if (hideWindow) ShowWindow(m_hwndMain, SW_HIDE);
    }

    void UpdateTrayTooltip() {
        if (!m_trayAdded) return;
        NOTIFYICONDATAW nid = { sizeof(NOTIFYICONDATAW) };
        nid.hWnd = m_hwndMain;
        nid.uID = 1;
        nid.uFlags = NIF_TIP;
        wcscpy_s(nid.szTip, m_serverRunning
            ? L"Radmin Ultra RD (Хост активен · защищено PIN-кодом)"
            : L"Radmin Ultra RD (Ожидание)");
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    void RestoreFromTray() {
        ShowWindow(m_hwndMain, SW_RESTORE);
        ShowWindow(m_hwndMain, SW_SHOW);
        SetForegroundWindow(m_hwndMain);
        m_framePacer.ResetTiming();
    }

    void RemoveTrayIcon() {
        if (m_trayAdded) {
            NOTIFYICONDATAW nid = { sizeof(NOTIFYICONDATAW) };
            nid.hWnd = m_hwndMain;
            nid.uID = 1;
            Shell_NotifyIconW(NIM_DELETE, &nid);
            m_trayAdded = false;
        }
    }

    // ========================================================================
    // СЕРВЕРНАЯ ЛОГИКА
    // ========================================================================
    void StartServerWithPinPrompt() {
        if (m_serverRunning) return;
        if (!RunPinModalDialog(ModalPinMode::SetHostSessionPin)) {
            ClearRuntimeSessionPin();
            return;
        }
        StartServerInternal();
    }

    void StartServerInternal() {
        if (m_serverRunning) return;

        char nameBuf[64] = {}, passBuf[128] = {}, portBuf[16] = {};
        GetWindowTextA(m_editSrvName, nameBuf, sizeof(nameBuf));
        GetWindowTextA(m_editSrvPass, passBuf, sizeof(passBuf));
        GetWindowTextA(m_editSrvPort, portBuf, sizeof(portBuf));

        m_serverPort = (uint16_t)std::atoi(portBuf);
        if (m_serverPort == 0) m_serverPort = DEFAULT_STREAM_PORT;
        {
            std::lock_guard<std::mutex> lock(m_srvInfoMutex);
            m_radminIp = DetectRadminVpnIP();
        }

        m_srvListenTcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL reuse = TRUE;
        setsockopt(m_srvListenTcp, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

        sockaddr_in bindAddr = {};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = htons(m_serverPort);

        if (bind(m_srvListenTcp, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR ||
            listen(m_srvListenTcp, 1) == SOCKET_ERROR) {
            closesocket(m_srvListenTcp);
            m_srvListenTcp = INVALID_SOCKET;
            ClearRuntimeSessionPin();
            MessageBoxW(m_hwndMain, L"Не удалось занять порт сервера!", L"Ошибка", MB_ICONERROR);
            return;
        }

        m_srvVideoUdp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int sndBuf = 8 * 1024 * 1024;
        setsockopt(m_srvVideoUdp, SOL_SOCKET, SO_SNDBUF, (const char*)&sndBuf, sizeof(sndBuf));
        DisableUdpConnReset(m_srvVideoUdp);
        bind(m_srvVideoUdp, (sockaddr*)&bindAddr, sizeof(bindAddr));

        m_srvDiscUdp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        setsockopt(m_srvDiscUdp, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        DisableUdpConnReset(m_srvDiscUdp);

        sockaddr_in discAddr = {};
        discAddr.sin_family = AF_INET;
        discAddr.sin_addr.s_addr = INADDR_ANY;
        discAddr.sin_port = htons(DISCOVERY_UDP_PORT);
        bind(m_srvDiscUdp, (sockaddr*)&discAddr, sizeof(discAddr));

        m_serverRunning = true;
        if (IsWindow(m_editSrvName)) SendMessageW(m_editSrvName, EM_SETREADONLY, TRUE, 0);
        if (IsWindow(m_editSrvPass)) SendMessageW(m_editSrvPass, EM_SETREADONLY, TRUE, 0);
        if (IsWindow(m_editSrvPort)) SendMessageW(m_editSrvPort, EM_SETREADONLY, TRUE, 0);
        UpdateTrayTooltip();

        std::string serverName = nameBuf[0] ? nameBuf : "Radmin-Host";
        std::string serverPass = passBuf;
        SecureZeroMemory(passBuf, sizeof(passBuf));

        m_srvDiscoveryThread = std::thread(&RemoteDesktopApp::ServerDiscoveryLoop, this, serverName);
        m_srvAcceptThread    = std::thread(&RemoteDesktopApp::ServerAcceptAndControlLoop, this, serverPass);
        m_srvCaptureThread   = std::thread(&RemoteDesktopApp::ServerCaptureAndEncodeLoop, this);
        SecureZeroMemory(serverPass.data(), serverPass.size());

        RefreshButtonVisualStates();
        if (m_autoMinimize.load()) {
            ShowWindow(m_hwndMain, SW_MINIMIZE);
        }
    }

    void StopServer() {
        if (!m_serverRunning.exchange(false)) {
            ClearRuntimeSessionPin();
            return;
        }
        m_clientAuthorized = false;

        if (m_srvListenTcp != INVALID_SOCKET) { closesocket(m_srvListenTcp); m_srvListenTcp = INVALID_SOCKET; }
        if (m_srvClientTcp != INVALID_SOCKET) { closesocket(m_srvClientTcp); m_srvClientTcp = INVALID_SOCKET; }
        if (m_srvVideoUdp  != INVALID_SOCKET) { closesocket(m_srvVideoUdp);  m_srvVideoUdp  = INVALID_SOCKET; }
        if (m_srvDiscUdp   != INVALID_SOCKET) { closesocket(m_srvDiscUdp);   m_srvDiscUdp   = INVALID_SOCKET; }

        if (m_srvDiscoveryThread.joinable()) m_srvDiscoveryThread.join();
        if (m_srvAcceptThread.joinable())    m_srvAcceptThread.join();
        if (m_srvCaptureThread.joinable())   m_srvCaptureThread.join();

        m_inputAndClip.ReleaseAllHeldKeys();
        {
            std::lock_guard<std::mutex> lock(m_srvInfoMutex);
            m_connectedClientIp.clear();
        }
        m_srvFps = 0;
        m_srvEncodeUs = 0;
        m_srvClientDecodeUs = 0;
        m_srvRttUs = 0;
        ClearRuntimeSessionPin();

        if (IsWindow(m_editSrvName)) SendMessageW(m_editSrvName, EM_SETREADONLY, FALSE, 0);
        if (IsWindow(m_editSrvPass)) SendMessageW(m_editSrvPass, EM_SETREADONLY, FALSE, 0);
        if (IsWindow(m_editSrvPort)) SendMessageW(m_editSrvPort, EM_SETREADONLY, FALSE, 0);
        UpdateTrayTooltip();
        RefreshButtonVisualStates();
    }

    void ServerDiscoveryLoop(std::string serverName) {
        while (m_serverRunning) {
            DiscoveryPacket pkt = {};
            sockaddr_in from = {};
            int fromLen = sizeof(from);
            int r = recvfrom(m_srvDiscUdp, (char*)&pkt, sizeof(pkt), 0, (sockaddr*)&from, &fromLen);
            if (r == sizeof(DiscoveryPacket) && pkt.magic == MAGIC_DISCOVERY && pkt.isResponse == 0) {
                DiscoveryPacket resp = {};
                resp.magic = MAGIC_DISCOVERY;
                resp.isResponse = 1;
                strncpy_s(resp.serverName, serverName.c_str(), _TRUNCATE);
                std::string curIp = DetectRadminVpnIP();
                strncpy_s(resp.serverIp, curIp.c_str(), _TRUNCATE);
                resp.port = m_serverPort;
                resp.width = GetSystemMetrics(SM_CXSCREEN);
                resp.height = GetSystemMetrics(SM_CYSCREEN);
                sendto(m_srvDiscUdp, (const char*)&resp, sizeof(resp), 0, (sockaddr*)&from, fromLen);
            }
        }
    }

    void ServerAcceptAndControlLoop(std::string password) {
        std::thread udpHandshakeListener([this]() {
            char buf[64];
            while (m_serverRunning) {
                sockaddr_in from = {};
                int fromLen = sizeof(from);
                int r = recvfrom(m_srvVideoUdp, buf, sizeof(buf), 0, (sockaddr*)&from, &fromLen);
                if (r >= 12 && *reinterpret_cast<uint32_t*>(buf) == MAGIC_VIDEO) {
                    uint64_t token = *reinterpret_cast<uint64_t*>(buf + 4);
                    if (token == m_activeUdpToken && token != 0) {
                        std::lock_guard<std::mutex> lock(m_srvClientUdpMutex);
                        m_srvClientUdpAddr = from;
                        m_hasClientUdpAddr = true;
                        m_forceIdrNextFrame = true;
                    }
                }
            }
        });

        while (m_serverRunning) {
            sockaddr_in cliAddr = {};
            int addrLen = sizeof(cliAddr);
            SOCKET clientSock = accept(m_srvListenTcp, (sockaddr*)&cliAddr, &addrLen);
            if (clientSock == INVALID_SOCKET) break;

            BOOL noDelay = TRUE;
            setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (const char*)&noDelay, sizeof(noDelay));

            AuthChallengePayload chal = {};
            CryptoEngine::RandomBytes(chal.salt, 32);
            CryptoEngine::RandomBytes(chal.challenge, 32);
            chal.screenWidth = GetSystemMetrics(SM_CXSCREEN);
            chal.screenHeight = GetSystemMetrics(SM_CYSCREEN);

            ControlHeader hdr = { MAGIC_CONTROL, CTRL_AUTH_CHALLENGE, sizeof(chal) };
            if (!SendAllTcp(clientSock, &hdr, sizeof(hdr)) || !SendAllTcp(clientSock, &chal, sizeof(chal))) {
                closesocket(clientSock);
                continue;
            }

            ControlHeader respHdr = {};
            AuthResponsePayload resp = {};
            if (!RecvAllTcp(clientSock, &respHdr, sizeof(respHdr)) ||
                respHdr.magic != MAGIC_CONTROL || respHdr.type != CTRL_AUTH_RESPONSE ||
                respHdr.payloadSize != sizeof(resp) ||
                !RecvAllTcp(clientSock, &resp, sizeof(resp))) {
                closesocket(clientSock);
                continue;
            }

            std::vector<uint8_t> pwdSalt(password.begin(), password.end());
            pwdSalt.insert(pwdSalt.end(), chal.salt, chal.salt + 32);
            uint8_t pwdHash[32] = {}, expectedHmac[32] = {};
            CryptoEngine::ComputeSHA256(pwdSalt.data(), pwdSalt.size(), pwdHash);
            CryptoEngine::ComputeHMACSHA256(pwdHash, 32, chal.challenge, 32, expectedHmac);

            bool authOk = CryptoEngine::ConstantTimeEqual32(expectedHmac, resp.hmac);

            AuthResultPayload resPayload = {};
            resPayload.authenticated = authOk ? 1 : 0;
            CryptoEngine::RandomBytes(reinterpret_cast<uint8_t*>(&resPayload.udpSessionToken), 8);
            if (resPayload.udpSessionToken == 0) resPayload.udpSessionToken = 1;

            std::string clientIpStr;
            if (authOk) {
                CryptoEngine::ComputeHMACSHA256(pwdHash, 32, chal.salt, 32, m_srvSessionKey);
                m_activeUdpToken = resPayload.udpSessionToken;

                char ipStr[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &cliAddr.sin_addr, ipStr, sizeof(ipStr));
                clientIpStr = ipStr;
                {
                    std::lock_guard<std::mutex> lock(m_srvInfoMutex);
                    m_connectedClientIp = clientIpStr;
                }

                {
                    std::lock_guard<std::mutex> lock(m_srvClientUdpMutex);
                    m_srvClientUdpAddr = cliAddr;
                    m_srvClientUdpAddr.sin_port = htons(resp.clientUdpPort);
                    m_hasClientUdpAddr = (resp.clientUdpPort != 0);
                }

                m_srvClientTcp = clientSock;
                m_forceIdrNextFrame = true;
                m_clientAuthorized = true;

                if (m_autoMinimize.load() && m_hwndMain) {
                    PostMessageW(m_hwndMain, WM_APP_AUTO_MINIMIZE, 0, 0);
                }
            }

            ControlHeader resHdr = { MAGIC_CONTROL, CTRL_AUTH_RESULT, sizeof(resPayload) };
            SendAllTcp(clientSock, &resHdr, sizeof(resHdr));
            SendAllTcp(clientSock, &resPayload, sizeof(resPayload));

            if (!authOk) {
                closesocket(clientSock);
                continue;
            }

            PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);

            bool isLoopbackTest = (clientIpStr == "127.0.0.1" ||
                                   (m_clientRunning.load() && clientIpStr == DetectRadminVpnIP()));
            FileTransferReceiver fileReceiver;

            while (m_serverRunning && m_clientAuthorized) {
                ControlHeader cHdr = {};
                if (!RecvAllTcp(clientSock, &cHdr, sizeof(cHdr)) || cHdr.magic != MAGIC_CONTROL) break;

                RECT deskRect = { 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) };
                bool blockSelfInput = isLoopbackTest || (m_clientRunning.load() && m_viewerVisible.load());

                if (cHdr.type == CTRL_MOUSE_EVENT && cHdr.payloadSize == sizeof(MouseEventPayload)) {
                    MouseEventPayload mev = {};
                    if (!RecvAllTcp(clientSock, &mev, sizeof(mev))) break;
                    CryptoEngine::StreamCrypt(reinterpret_cast<uint8_t*>(&mev), sizeof(mev), m_srvSessionKey, 1);
                    m_inputAndClip.InjectMouseEvent(mev, deskRect, blockSelfInput);
                } else if (cHdr.type == CTRL_KEY_EVENT && cHdr.payloadSize == sizeof(KeyEventPayload)) {
                    KeyEventPayload kev = {};
                    if (!RecvAllTcp(clientSock, &kev, sizeof(kev))) break;
                    CryptoEngine::StreamCrypt(reinterpret_cast<uint8_t*>(&kev), sizeof(kev), m_srvSessionKey, 2);
                    m_inputAndClip.InjectKeyEvent(kev, blockSelfInput);
                } else if (cHdr.type == CTRL_RELEASE_ALL_KEYS) {
                    m_inputAndClip.ReleaseAllHeldKeys();
                } else if (cHdr.type == CTRL_REQ_IDR) {
                    m_forceIdrNextFrame = true;
                } else if (cHdr.type == CTRL_PING && cHdr.payloadSize == sizeof(PingPongPayload)) {
                    PingPongPayload ping = {};
                    if (!RecvAllTcp(clientSock, &ping, sizeof(ping))) break;
                    m_srvClientDecodeUs = ping.lastDecodeUs;
                    ControlHeader pongHdr = { MAGIC_CONTROL, CTRL_PONG, sizeof(ping) };
                    std::lock_guard<std::mutex> sendLock(m_srvTcpSendMutex);
                    SendAllTcp(clientSock, &pongHdr, sizeof(pongHdr));
                    SendAllTcp(clientSock, &ping, sizeof(ping));
                } else if (cHdr.type == CTRL_PONG && cHdr.payloadSize == sizeof(PingPongPayload)) {
                    PingPongPayload pong = {};
                    if (!RecvAllTcp(clientSock, &pong, sizeof(pong))) break;
                    m_srvRttUs = (uint32_t)(NowMicros() - pong.timestampUs);
                } else if (cHdr.type == CTRL_CLIPBOARD_DATA && cHdr.payloadSize >= sizeof(ClipboardHeaderPayload)) {
                    ClipboardHeaderPayload clipHdr = {};
                    if (!RecvAllTcp(clientSock, &clipHdr, sizeof(clipHdr))) break;
                    uint32_t rawLen = cHdr.payloadSize - sizeof(ClipboardHeaderPayload);
                    if (rawLen > 0 && rawLen <= MAX_CLIPBOARD_BYTES && rawLen == clipHdr.dataSize) {
                        std::vector<uint8_t> clipData(rawLen);
                        if (!RecvAllTcp(clientSock, clipData.data(), rawLen)) break;
                        CryptoEngine::StreamCrypt(clipData.data(), clipData.size(), m_srvSessionKey, 3);
                        m_inputAndClip.ApplyRemoteClipboard(m_hwndMain, clipHdr.dataType, clipData, clipHdr.sha256);
                    }
                } else if (cHdr.type == CTRL_FILE_START && cHdr.payloadSize == sizeof(FileStartPayload)) {
                    FileStartPayload fStart = {};
                    if (!RecvAllTcp(clientSock, &fStart, sizeof(fStart))) break;
                    CryptoEngine::StreamCrypt(reinterpret_cast<uint8_t*>(&fStart), sizeof(fStart), m_srvSessionKey, 4);
                    std::wstring status;
                    float pct = 0.0f;
                    fileReceiver.OnFileStart(fStart, status, pct);
                    SetFileStatus(true, status, pct);
                } else if (cHdr.type == CTRL_FILE_CHUNK && cHdr.payloadSize > sizeof(FileChunkHeaderPayload)) {
                    FileChunkHeaderPayload chunkHdr = {};
                    if (!RecvAllTcp(clientSock, &chunkHdr, sizeof(chunkHdr))) break;
                    uint32_t dataLen = cHdr.payloadSize - sizeof(FileChunkHeaderPayload);
                    if (dataLen != chunkHdr.chunkSize || dataLen > FILE_CHUNK_SIZE * 2) break;
                    std::vector<uint8_t> chunkData(dataLen);
                    if (!RecvAllTcp(clientSock, chunkData.data(), dataLen)) break;
                    CryptoEngine::StreamCrypt(chunkData.data(), dataLen, m_srvSessionKey, 5 ^ chunkHdr.offset);
                    std::wstring status;
                    float pct = 0.0f;
                    bool notifyUi = false;
                    fileReceiver.OnFileChunk(chunkHdr, chunkData.data(), status, pct, notifyUi);
                    if (notifyUi) SetFileStatus(true, status, pct);
                } else if (cHdr.type == CTRL_FILE_END && cHdr.payloadSize == sizeof(FileEndPayload)) {
                    FileEndPayload fEnd = {};
                    if (!RecvAllTcp(clientSock, &fEnd, sizeof(fEnd))) break;
                    std::wstring status;
                    float pct = 0.0f;
                    fileReceiver.OnFileEnd(fEnd, status, pct);
                    SetFileStatus(true, status, pct);
                } else if (cHdr.payloadSize > 0) {
                    std::vector<uint8_t> skip(std::min<uint32_t>(cHdr.payloadSize, MAX_CLIPBOARD_BYTES));
                    if (!RecvAllTcp(clientSock, skip.data(), skip.size())) break;
                }
            }

            fileReceiver.CloseActiveFile();
            m_inputAndClip.ReleaseAllHeldKeys();
            m_clientAuthorized = false;
            {
                std::lock_guard<std::mutex> lock(m_srvInfoMutex);
                m_connectedClientIp.clear();
            }
            closesocket(clientSock);
            m_srvClientTcp = INVALID_SOCKET;
            PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);
        }

        SecureZeroMemory(password.data(), password.size());
        if (udpHandshakeListener.joinable()) udpHandshakeListener.join();
    }

    void ServerCaptureAndEncodeLoop() {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

        DxgiScreenCapturer capturer;
        capturer.Initialize(1920, 1080);

        LowLatencyH264Encoder encoder;
        bool encoderReady = false;

        std::vector<uint8_t> nv12Buffer, h264Stream;
        uint32_t frameId = 1, framesInSec = 0;
        uint64_t secTimer = NowMicros(), lastPingUs = 0;

        while (m_serverRunning) {
            if (!m_clientAuthorized) { Sleep(15); continue; }

            uint64_t loopStartUs = NowMicros();
            if (loopStartUs - lastPingUs > 500000 && m_srvClientTcp != INVALID_SOCKET) {
                lastPingUs = loopStartUs;
                PingPongPayload ping = { loopStartUs, 0 };
                ControlHeader pHdr = { MAGIC_CONTROL, CTRL_PING, sizeof(ping) };
                std::lock_guard<std::mutex> sendLock(m_srvTcpSendMutex);
                SendAllTcp(m_srvClientTcp, &pHdr, sizeof(pHdr));
                SendAllTcp(m_srvClientTcp, &ping, sizeof(ping));
            }

            bool needIdr = m_forceIdrNextFrame.load();
            uint32_t capW = 0, capH = 0;
            if (!capturer.CaptureToNv12(nv12Buffer, capW, capH, needIdr)) {
                Sleep(1);
                continue;
            }

            if (!encoderReady || encoder.GetWidth() != capW || encoder.GetHeight() != capH) {
                encoderReady = encoder.Initialize(capW, capH, 60);
                needIdr = true;
            }
            if (!encoderReady) { Sleep(10); continue; }

            if (needIdr) {
                m_forceIdrNextFrame = false;
                encoder.ForceKeyFrame();
            }

            uint64_t encStartUs = NowMicros();
            bool isKeyFrame = false;
            if (encoder.EncodeFrame(nv12Buffer, h264Stream, isKeyFrame) && !h264Stream.empty()) {
                uint32_t encElapsedUs = (uint32_t)(NowMicros() - encStartUs);
                m_srvEncodeUs = encElapsedUs;

                sockaddr_in targetAddr = {};
                bool canSendUdp = false;
                {
                    std::lock_guard<std::mutex> lock(m_srvClientUdpMutex);
                    targetAddr = m_srvClientUdpAddr;
                    canSendUdp = m_hasClientUdpAddr;
                }

                if (canSendUdp) {
                    size_t totalBytes = h264Stream.size();
                    uint16_t totalChunks = (uint16_t)((totalBytes + MAX_UDP_PAYLOAD - 1) / MAX_UDP_PAYLOAD);
                    uint8_t packetBuf[sizeof(UdpVideoHeader) + MAX_UDP_PAYLOAD];

                    for (uint16_t idx = 0; idx < totalChunks; ++idx) {
                        size_t offset = (size_t)idx * MAX_UDP_PAYLOAD;
                        uint16_t chunkLen = (uint16_t)std::min<size_t>(MAX_UDP_PAYLOAD, totalBytes - offset);

                        auto* vHdr = reinterpret_cast<UdpVideoHeader*>(packetBuf);
                        vHdr->magic = MAGIC_VIDEO;
                        vHdr->sessionToken = m_activeUdpToken;
                        vHdr->frameId = frameId;
                        vHdr->chunkIdx = idx;
                        vHdr->totalChunks = totalChunks;
                        vHdr->flags = isKeyFrame ? 0x01 : 0x00;
                        vHdr->width = (uint16_t)capW;
                        vHdr->height = (uint16_t)capH;
                        vHdr->encodeUs = encElapsedUs;
                        vHdr->captureQpcUs = loopStartUs;
                        vHdr->payloadSize = chunkLen;

                        memcpy(packetBuf + sizeof(UdpVideoHeader), h264Stream.data() + offset, chunkLen);
                        sendto(m_srvVideoUdp, (const char*)packetBuf, sizeof(UdpVideoHeader) + chunkLen,
                               0, (sockaddr*)&targetAddr, sizeof(targetAddr));

                        if ((idx & 15) == 15) MicroSpinWait(80);
                    }
                    frameId++;
                    framesInSec++;
                }
            }

            uint64_t now = NowMicros();
            if (now - secTimer >= 1000000ULL) {
                m_srvFps = framesInSec;
                framesInSec = 0;
                secTimer = now;
                PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);
            }
        }

        capturer.Shutdown();
        CoUninitialize();
    }

    // ========================================================================
    // КЛИЕНТСКАЯ ЛОГИКА
    // ========================================================================
    void ScanNetworkForServers() {
        if (m_scanInProgress.exchange(true)) return;
        SendMessageW(m_listHosts, LB_RESETCONTENT, 0, 0);
        {
            std::lock_guard<std::mutex> lock(m_hostsMutex);
            m_discoveredHosts.clear();
        }
        RefreshButtonVisualStates();

        std::thread([this]() {
            SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (s != INVALID_SOCKET) {
                BOOL bcast = TRUE;
                setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char*)&bcast, sizeof(bcast));
                DWORD timeoutMs = 450;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
                DisableUdpConnReset(s);

                std::vector<std::string> bcastTargets;
                DetectRadminVpnIP(&bcastTargets);

                DiscoveryPacket req = { MAGIC_DISCOVERY, 0 };
                for (const auto& addrStr : bcastTargets) {
                    sockaddr_in dst = {};
                    dst.sin_family = AF_INET;
                    dst.sin_port = htons(DISCOVERY_UDP_PORT);
                    inet_pton(AF_INET, addrStr.c_str(), &dst.sin_addr);
                    sendto(s, (const char*)&req, sizeof(req), 0, (sockaddr*)&dst, sizeof(dst));
                }

                uint64_t start = NowMicros();
                while (NowMicros() - start < 600000ULL) {
                    DiscoveryPacket resp = {};
                    sockaddr_in from = {};
                    int fromLen = sizeof(from);
                    int r = recvfrom(s, (char*)&resp, sizeof(resp), 0, (sockaddr*)&from, &fromLen);
                    if (r == sizeof(DiscoveryPacket) && resp.magic == MAGIC_DISCOVERY && resp.isResponse == 1) {
                        char fromIp[INET_ADDRSTRLEN] = {};
                        inet_ntop(AF_INET, &from.sin_addr, fromIp, sizeof(fromIp));

                        DiscoveredHostInfo info;
                        info.name = resp.serverName;
                        info.ip = (resp.serverIp[0] && strcmp(resp.serverIp, "127.0.0.1") != 0) ? resp.serverIp : fromIp;
                        info.port = resp.port;
                        info.width = resp.width;
                        info.height = resp.height;

                        bool exists = false;
                        {
                            std::lock_guard<std::mutex> lock(m_hostsMutex);
                            for (const auto& h : m_discoveredHosts) {
                                if (h.ip == info.ip && h.port == info.port) { exists = true; break; }
                            }
                            if (!exists) m_discoveredHosts.push_back(info);
                        }
                        if (!exists && m_hwndMain) PostMessageW(m_hwndMain, WM_APP_HOST_FOUND, 0, 0);
                    } else if (r <= 0) break;
                }
                closesocket(s);
            }
            m_scanInProgress = false;
            if (m_hwndMain) PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);
        }).detach();
    }

    void ConnectToServer() {
        if (m_clientRunning) return;

        char ipBuf[64] = {}, portBuf[16] = {}, passBuf[128] = {};
        GetWindowTextA(m_editCliIp, ipBuf, sizeof(ipBuf));
        GetWindowTextA(m_editCliPort, portBuf, sizeof(portBuf));
        GetWindowTextA(m_editCliPass, passBuf, sizeof(passBuf));

        std::string hostIp = ipBuf, password = passBuf;
        SecureZeroMemory(passBuf, sizeof(passBuf));
        uint16_t port = (uint16_t)std::atoi(portBuf);
        if (port == 0) port = DEFAULT_STREAM_PORT;

        if (hostIp.empty()) {
            MessageBoxW(m_hwndMain, L"Выберите сервер из списка или введите IP-адрес!", L"Внимание", MB_ICONWARNING);
            return;
        }

        SOCKET tcpSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL noDelay = TRUE;
        setsockopt(tcpSock, IPPROTO_TCP, TCP_NODELAY, (const char*)&noDelay, sizeof(noDelay));

        sockaddr_in srvAddr = {};
        srvAddr.sin_family = AF_INET;
        srvAddr.sin_port = htons(port);
        if (inet_pton(AF_INET, hostIp.c_str(), &srvAddr.sin_addr) <= 0 ||
            connect(tcpSock, (sockaddr*)&srvAddr, sizeof(srvAddr)) == SOCKET_ERROR) {
            closesocket(tcpSock);
            MessageBoxW(m_hwndMain, L"Не удалось подключиться к серверу по TCP!", L"Ошибка подключения", MB_ICONERROR);
            return;
        }

        SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int rcvBuf = 8 * 1024 * 1024;
        setsockopt(udpSock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvBuf, sizeof(rcvBuf));
        DisableUdpConnReset(udpSock);

        sockaddr_in localUdp = { AF_INET, 0 };
        localUdp.sin_addr.s_addr = INADDR_ANY;
        bind(udpSock, (sockaddr*)&localUdp, sizeof(localUdp));

        sockaddr_in boundUdp = {};
        int boundLen = sizeof(boundUdp);
        getsockname(udpSock, (sockaddr*)&boundUdp, &boundLen);
        uint16_t localUdpPort = ntohs(boundUdp.sin_port);

        ControlHeader cHdr = {};
        AuthChallengePayload chal = {};
        if (!RecvAllTcp(tcpSock, &cHdr, sizeof(cHdr)) || cHdr.magic != MAGIC_CONTROL ||
            cHdr.type != CTRL_AUTH_CHALLENGE || !RecvAllTcp(tcpSock, &chal, sizeof(chal))) {
            closesocket(udpSock);
            closesocket(tcpSock);
            MessageBoxW(m_hwndMain, L"Ошибка протокола рукопожатия!", L"Ошибка", MB_ICONERROR);
            return;
        }

        std::vector<uint8_t> pwdSalt(password.begin(), password.end());
        SecureZeroMemory(password.data(), password.size());
        pwdSalt.insert(pwdSalt.end(), chal.salt, chal.salt + 32);
        uint8_t pwdHash[32] = {};
        CryptoEngine::ComputeSHA256(pwdSalt.data(), pwdSalt.size(), pwdHash);
        SecureZeroMemory(pwdSalt.data(), pwdSalt.size());

        AuthResponsePayload authResp = {};
        CryptoEngine::ComputeHMACSHA256(pwdHash, 32, chal.challenge, 32, authResp.hmac);
        authResp.clientUdpPort = localUdpPort;

        ControlHeader respHdr = { MAGIC_CONTROL, CTRL_AUTH_RESPONSE, sizeof(authResp) };
        SendAllTcp(tcpSock, &respHdr, sizeof(respHdr));
        SendAllTcp(tcpSock, &authResp, sizeof(authResp));

        ControlHeader resHdr = {};
        AuthResultPayload resPayload = {};
        if (!RecvAllTcp(tcpSock, &resHdr, sizeof(resHdr)) || resHdr.type != CTRL_AUTH_RESULT ||
            !RecvAllTcp(tcpSock, &resPayload, sizeof(resPayload)) || !resPayload.authenticated) {
            closesocket(udpSock);
            closesocket(tcpSock);
            MessageBoxW(m_hwndMain, L"Неверный пароль доступа!", L"Отказ в доступе", MB_ICONERROR);
            return;
        }

        CryptoEngine::ComputeHMACSHA256(pwdHash, 32, chal.salt, 32, m_cliSessionKey);
        SecureZeroMemory(pwdHash, sizeof(pwdHash));
        m_cliUdpToken = resPayload.udpSessionToken;
        m_cliTcpSock = tcpSock;
        m_cliUdpSock = udpSock;

        PositionViewerWindowAdaptively(chal.screenWidth, chal.screenHeight);
        ShowWindow(m_hwndViewer, SW_SHOW);
        m_viewerVisible = true;
        SetForegroundWindow(m_hwndViewer);
        m_renderer.Initialize(m_hwndViewer);

        m_clientRunning = true;
        RefreshButtonVisualStates();

        m_cliTcpThread = std::thread(&RemoteDesktopApp::ClientTcpControlLoop, this);
        m_cliUdpThread = std::thread(&RemoteDesktopApp::ClientUdpVideoLoop, this, srvAddr);
    }

    void PositionViewerWindowAdaptively(uint32_t remoteW, uint32_t remoteH) {
        if (m_isViewerFullscreen) ToggleViewerFullscreen();
        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
        int maxW = (int)((workArea.right - workArea.left) * 0.88);
        int maxH = (int)((workArea.bottom - workArea.top) * 0.88);

        double aspect = (remoteW > 0 && remoteH > 0) ? ((double)remoteW / remoteH) : (16.0 / 9.0);
        int winW = maxW;
        int winH = (int)(winW / aspect);
        if (winH > maxH) { winH = maxH; winW = (int)(winH * aspect); }

        int posX = workArea.left + ((workArea.right - workArea.left) - winW) / 2;
        int posY = workArea.top + ((workArea.bottom - workArea.top) - winH) / 2;
        SetWindowPos(m_hwndViewer, HWND_TOP, posX, posY, winW, winH, SWP_NOACTIVATE);
    }

    void DisconnectClient() {
        if (!m_clientRunning.exchange(false)) return;
        SendClientReleaseAllKeys();

        if (m_cliTcpSock != INVALID_SOCKET) {
            shutdown(m_cliTcpSock, SD_BOTH);
            closesocket(m_cliTcpSock);
            m_cliTcpSock = INVALID_SOCKET;
        }
        if (m_cliUdpSock != INVALID_SOCKET) {
            closesocket(m_cliUdpSock);
            m_cliUdpSock = INVALID_SOCKET;
        }

        if (m_cliTcpThread.joinable()) m_cliTcpThread.join();
        if (m_cliUdpThread.joinable()) m_cliUdpThread.join();

        m_renderer.Shutdown();
        m_viewerVisible = false;
        if (IsWindow(m_hwndViewer)) ShowWindow(m_hwndViewer, SW_HIDE);
        m_cliFps = 0;
        m_cliEncodeUs = 0;
        m_cliDecodeUs = 0;
        m_cliRttUs = 0;
        RefreshButtonVisualStates();
    }

    void ClientTcpControlLoop() {
        uint64_t lastPingSent = 0;
        FileTransferReceiver fileReceiver;

        while (m_clientRunning) {
            ControlHeader cHdr = {};
            if (!RecvAllTcp(m_cliTcpSock, &cHdr, sizeof(cHdr)) || cHdr.magic != MAGIC_CONTROL) break;

            if (cHdr.type == CTRL_PING && cHdr.payloadSize == sizeof(PingPongPayload)) {
                PingPongPayload ping = {};
                if (!RecvAllTcp(m_cliTcpSock, &ping, sizeof(ping))) break;
                ping.lastDecodeUs = m_cliDecodeUs.load();

                ControlHeader pongHdr = { MAGIC_CONTROL, CTRL_PONG, sizeof(ping) };
                {
                    std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
                    SendAllTcp(m_cliTcpSock, &pongHdr, sizeof(pongHdr));
                    SendAllTcp(m_cliTcpSock, &ping, sizeof(ping));
                }

                uint64_t now = NowMicros();
                if (now - lastPingSent > 400000) {
                    lastPingSent = now;
                    PingPongPayload cliPing = { now, m_cliDecodeUs.load() };
                    ControlHeader cpHdr = { MAGIC_CONTROL, CTRL_PING, sizeof(cliPing) };
                    std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
                    SendAllTcp(m_cliTcpSock, &cpHdr, sizeof(cpHdr));
                    SendAllTcp(m_cliTcpSock, &cliPing, sizeof(cliPing));
                }
            } else if (cHdr.type == CTRL_PONG && cHdr.payloadSize == sizeof(PingPongPayload)) {
                PingPongPayload pong = {};
                if (!RecvAllTcp(m_cliTcpSock, &pong, sizeof(pong))) break;
                m_cliRttUs = (uint32_t)(NowMicros() - pong.timestampUs);
            } else if (cHdr.type == CTRL_CLIPBOARD_DATA && cHdr.payloadSize >= sizeof(ClipboardHeaderPayload)) {
                ClipboardHeaderPayload clipHdr = {};
                if (!RecvAllTcp(m_cliTcpSock, &clipHdr, sizeof(clipHdr))) break;
                uint32_t rawLen = cHdr.payloadSize - sizeof(ClipboardHeaderPayload);
                if (rawLen > 0 && rawLen <= MAX_CLIPBOARD_BYTES && rawLen == clipHdr.dataSize) {
                    std::vector<uint8_t> clipData(rawLen);
                    if (!RecvAllTcp(m_cliTcpSock, clipData.data(), rawLen)) break;
                    CryptoEngine::StreamCrypt(clipData.data(), clipData.size(), m_cliSessionKey, 3);
                    m_inputAndClip.ApplyRemoteClipboard(m_hwndMain, clipHdr.dataType, clipData, clipHdr.sha256);
                }
            } else if (cHdr.type == CTRL_FILE_START && cHdr.payloadSize == sizeof(FileStartPayload)) {
                FileStartPayload fStart = {};
                if (!RecvAllTcp(m_cliTcpSock, &fStart, sizeof(fStart))) break;
                CryptoEngine::StreamCrypt(reinterpret_cast<uint8_t*>(&fStart), sizeof(fStart), m_cliSessionKey, 4);
                std::wstring status;
                float pct = 0.0f;
                fileReceiver.OnFileStart(fStart, status, pct);
                SetFileStatus(false, status, pct);
            } else if (cHdr.type == CTRL_FILE_CHUNK && cHdr.payloadSize > sizeof(FileChunkHeaderPayload)) {
                FileChunkHeaderPayload chunkHdr = {};
                if (!RecvAllTcp(m_cliTcpSock, &chunkHdr, sizeof(chunkHdr))) break;
                uint32_t dataLen = cHdr.payloadSize - sizeof(FileChunkHeaderPayload);
                if (dataLen != chunkHdr.chunkSize || dataLen > FILE_CHUNK_SIZE * 2) break;
                std::vector<uint8_t> chunkData(dataLen);
                if (!RecvAllTcp(m_cliTcpSock, chunkData.data(), dataLen)) break;
                CryptoEngine::StreamCrypt(chunkData.data(), dataLen, m_cliSessionKey, 5 ^ chunkHdr.offset);
                std::wstring status;
                float pct = 0.0f;
                bool notifyUi = false;
                fileReceiver.OnFileChunk(chunkHdr, chunkData.data(), status, pct, notifyUi);
                if (notifyUi) SetFileStatus(false, status, pct);
            } else if (cHdr.type == CTRL_FILE_END && cHdr.payloadSize == sizeof(FileEndPayload)) {
                FileEndPayload fEnd = {};
                if (!RecvAllTcp(m_cliTcpSock, &fEnd, sizeof(fEnd))) break;
                std::wstring status;
                float pct = 0.0f;
                fileReceiver.OnFileEnd(fEnd, status, pct);
                SetFileStatus(false, status, pct);
            } else if (cHdr.payloadSize > 0) {
                std::vector<uint8_t> skip(std::min<uint32_t>(cHdr.payloadSize, MAX_CLIPBOARD_BYTES));
                if (!RecvAllTcp(m_cliTcpSock, skip.data(), skip.size())) break;
            }
        }

        fileReceiver.CloseActiveFile();
        if (m_clientRunning && m_hwndMain) PostMessageW(m_hwndMain, WM_APP_CLIENT_LOST, 0, 0);
    }

    void ClientUdpVideoLoop(sockaddr_in srvUdpAddr) {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

        #pragma pack(push, 1)
        struct UdpHello { uint32_t magic; uint64_t token; } hello = { MAGIC_VIDEO, m_cliUdpToken };
        #pragma pack(pop)
        for (int i = 0; i < 4; ++i) {
            sendto(m_cliUdpSock, (const char*)&hello, sizeof(hello), 0, (sockaddr*)&srvUdpAddr, sizeof(srvUdpAddr));
        }

        LowLatencyH264Decoder decoder;
        DecodedNv12Frame decodedFrame;

        struct FrameReassembly {
            uint32_t frameId = 0;
            uint16_t totalChunks = 0, receivedChunks = 0;
            uint8_t  flags = 0;
            uint16_t width = 0, height = 0;
            uint32_t encodeUs = 0;
            std::vector<bool> chunkMask;
            std::vector<uint8_t> buffer;
        } currentFrame;

        uint8_t recvBuf[2048];
        uint32_t expectedFrameId = 0, fpsCounter = 0;
        bool waitingForKeyframe = true;
        uint64_t fpsTimer = NowMicros(), lastHelloUs = NowMicros();

        DWORD rcvTimeoutMs = 150;
        setsockopt(m_cliUdpSock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcvTimeoutMs, sizeof(rcvTimeoutMs));

        while (m_clientRunning) {
            sockaddr_in from = {};
            int fromLen = sizeof(from);
            int r = recvfrom(m_cliUdpSock, (char*)recvBuf, sizeof(recvBuf), 0, (sockaddr*)&from, &fromLen);

            uint64_t now = NowMicros();
            if (r <= 0) {
                if (now - lastHelloUs > 350000ULL) {
                    lastHelloUs = now;
                    sendto(m_cliUdpSock, (const char*)&hello, sizeof(hello), 0, (sockaddr*)&srvUdpAddr, sizeof(srvUdpAddr));
                    RequestServerKeyframe();
                }
                continue;
            }

            if (r < (int)sizeof(UdpVideoHeader)) continue;
            const auto* hdr = reinterpret_cast<const UdpVideoHeader*>(recvBuf);
            if (hdr->magic != MAGIC_VIDEO || hdr->sessionToken != m_cliUdpToken) continue;
            if (hdr->chunkIdx >= hdr->totalChunks || hdr->totalChunks == 0) continue;
            if (r < (int)(sizeof(UdpVideoHeader) + hdr->payloadSize)) continue;

            if (hdr->frameId != currentFrame.frameId) {
                if (currentFrame.frameId != 0 && currentFrame.receivedChunks < currentFrame.totalChunks) {
                    waitingForKeyframe = true;
                    RequestServerKeyframe();
                }
                currentFrame.frameId = hdr->frameId;
                currentFrame.totalChunks = hdr->totalChunks;
                currentFrame.receivedChunks = 0;
                currentFrame.flags = hdr->flags;
                currentFrame.width = hdr->width;
                currentFrame.height = hdr->height;
                currentFrame.encodeUs = hdr->encodeUs;
                currentFrame.chunkMask.assign(hdr->totalChunks, false);
                currentFrame.buffer.resize((size_t)hdr->totalChunks * MAX_UDP_PAYLOAD);
            }

            if (!currentFrame.chunkMask[hdr->chunkIdx]) {
                currentFrame.chunkMask[hdr->chunkIdx] = true;
                currentFrame.receivedChunks++;

                size_t dstOffset = (size_t)hdr->chunkIdx * MAX_UDP_PAYLOAD;
                memcpy(currentFrame.buffer.data() + dstOffset, recvBuf + sizeof(UdpVideoHeader), hdr->payloadSize);
                if (hdr->chunkIdx == hdr->totalChunks - 1) {
                    currentFrame.buffer.resize(dstOffset + hdr->payloadSize);
                }
            }

            if (currentFrame.receivedChunks == currentFrame.totalChunks) {
                bool isIdr = (currentFrame.flags & 0x01) != 0;
                if (!isIdr && expectedFrameId != 0 && currentFrame.frameId != expectedFrameId) {
                    waitingForKeyframe = true;
                    RequestServerKeyframe();
                }

                if (isIdr || !waitingForKeyframe) {
                    waitingForKeyframe = false;
                    expectedFrameId = currentFrame.frameId + 1;
                    m_cliEncodeUs = currentFrame.encodeUs;

                    uint64_t decStart = NowMicros();
                    if (decoder.DecodeAccessUnit(currentFrame.buffer.data(), currentFrame.buffer.size(),
                                                 currentFrame.width, currentFrame.height, decodedFrame)) {
                        m_cliDecodeUs = (uint32_t)(NowMicros() - decStart);
                        m_renderer.RenderFrame(decodedFrame);
                        fpsCounter++;
                    } else {
                        waitingForKeyframe = true;
                        RequestServerKeyframe();
                    }
                } else {
                    RequestServerKeyframe();
                }
                currentFrame.frameId = 0;
            }

            if (now - fpsTimer >= 1000000ULL) {
                m_cliFps = fpsCounter;
                fpsCounter = 0;
                fpsTimer = now;
                if (m_hwndMain) PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);
            }
        }
        CoUninitialize();
    }

    void RequestServerKeyframe() {
        if (!m_clientRunning || m_cliTcpSock == INVALID_SOCKET) return;
        uint64_t now = NowMicros();
        if (now - m_lastIdrReqUs < 120000ULL) return;
        m_lastIdrReqUs = now;
        ControlHeader hdr = { MAGIC_CONTROL, CTRL_REQ_IDR, 0 };
        std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
        SendAllTcp(m_cliTcpSock, &hdr, sizeof(hdr));
    }

    void SendClientMouseEvent(int clientX, int clientY, int wheelDelta, uint32_t buttonFlags) {
        if (!m_clientRunning || m_cliTcpSock == INVALID_SOCKET) return;
        float normX = 0.0f, normY = 0.0f;
        if (!m_renderer.MapWindowPointToNormalized(clientX, clientY, normX, normY)) return;

        MouseEventPayload ev = { normX, normY, 0, 0, wheelDelta, buttonFlags };
        CryptoEngine::StreamCrypt(reinterpret_cast<uint8_t*>(&ev), sizeof(ev), m_cliSessionKey, 1);
        ControlHeader hdr = { MAGIC_CONTROL, CTRL_MOUSE_EVENT, sizeof(ev) };
        std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
        SendAllTcp(m_cliTcpSock, &hdr, sizeof(hdr));
        SendAllTcp(m_cliTcpSock, &ev, sizeof(ev));
    }

    void SendClientKeyEvent(uint16_t scanCode, uint16_t vKey, bool isDown, bool isExtended) {
        if (!m_clientRunning || m_cliTcpSock == INVALID_SOCKET) return;
        KeyEventPayload ev = { scanCode, vKey, (uint8_t)(isDown ? 1 : 0), (uint8_t)(isExtended ? 1 : 0) };
        CryptoEngine::StreamCrypt(reinterpret_cast<uint8_t*>(&ev), sizeof(ev), m_cliSessionKey, 2);
        ControlHeader hdr = { MAGIC_CONTROL, CTRL_KEY_EVENT, sizeof(ev) };
        std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
        SendAllTcp(m_cliTcpSock, &hdr, sizeof(hdr));
        SendAllTcp(m_cliTcpSock, &ev, sizeof(ev));
    }

    void SendClientReleaseAllKeys() {
        if (!m_clientRunning || m_cliTcpSock == INVALID_SOCKET) return;
        ControlHeader hdr = { MAGIC_CONTROL, CTRL_RELEASE_ALL_KEYS, 0 };
        std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
        SendAllTcp(m_cliTcpSock, &hdr, sizeof(hdr));
    }

    void BroadcastLocalClipboardChange() {
        uint8_t fmt = 0;
        std::vector<uint8_t> data;
        uint8_t hash[32] = {};
        if (!m_inputAndClip.CaptureClipboardIfChanged(m_hwndMain, fmt, data, hash)) return;

        ClipboardHeaderPayload clipHdr = { fmt };
        memcpy(clipHdr.sha256, hash, 32);
        clipHdr.dataSize = (uint32_t)data.size();
        ControlHeader hdr = { MAGIC_CONTROL, CTRL_CLIPBOARD_DATA, (uint32_t)(sizeof(clipHdr) + data.size()) };

        if (m_serverRunning && m_clientAuthorized && m_srvClientTcp != INVALID_SOCKET) {
            std::vector<uint8_t> encData = data;
            CryptoEngine::StreamCrypt(encData.data(), encData.size(), m_srvSessionKey, 3);
            std::lock_guard<std::mutex> lock(m_srvTcpSendMutex);
            SendAllTcp(m_srvClientTcp, &hdr, sizeof(hdr));
            SendAllTcp(m_srvClientTcp, &clipHdr, sizeof(clipHdr));
            SendAllTcp(m_srvClientTcp, encData.data(), encData.size());
        }
        if (m_clientRunning && m_cliTcpSock != INVALID_SOCKET) {
            std::vector<uint8_t> encData = data;
            CryptoEngine::StreamCrypt(encData.data(), encData.size(), m_cliSessionKey, 3);
            std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
            SendAllTcp(m_cliTcpSock, &hdr, sizeof(hdr));
            SendAllTcp(m_cliTcpSock, &clipHdr, sizeof(clipHdr));
            SendAllTcp(m_cliTcpSock, encData.data(), encData.size());
        }
    }

    void ToggleViewerFullscreen() {
        if (!m_hwndViewer) return;
        DWORD style = GetWindowLongW(m_hwndViewer, GWL_STYLE);
        if (!m_isViewerFullscreen) {
            GetWindowPlacement(m_hwndViewer, &m_viewerPrevPlacement);
            HMONITOR hMon = MonitorFromWindow(m_hwndViewer, MONITOR_DEFAULTTONEAREST);
            MONITORINFO mi = { sizeof(mi) };
            GetMonitorInfoW(hMon, &mi);
            SetWindowLongW(m_hwndViewer, GWL_STYLE, style & ~WS_OVERLAPPEDWINDOW);
            SetWindowPos(m_hwndViewer, HWND_TOP, mi.rcMonitor.left, mi.rcMonitor.top,
                         mi.rcMonitor.right - mi.rcMonitor.left, mi.rcMonitor.bottom - mi.rcMonitor.top,
                         SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            m_isViewerFullscreen = true;
        } else {
            SetWindowLongW(m_hwndViewer, GWL_STYLE, style | WS_OVERLAPPEDWINDOW);
            SetWindowPlacement(m_hwndViewer, &m_viewerPrevPlacement);
            SetWindowPos(m_hwndViewer, nullptr, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            m_isViewerFullscreen = false;
        }
    }

    // ========================================================================
    // АДАПТИВНАЯ КОМПОНОВКА, КНОПКИ И ВЗАИМОДЕЙСТВИЕ В ГЛАВНОМ МЕНЮ
    // ========================================================================
    void InitCanvasWidgets() {
        m_buttons[0] = { IDC_BTN_SRV_TOGGLE,   {}, L"Запустить сервер",                  BTN_VAR_PRIMARY_GREEN, true };
        m_buttons[1] = { IDC_BTN_SRV_TRAY,     {}, L"Свернуть в трей",                   BTN_VAR_SECONDARY,     true };
        m_buttons[2] = { IDC_BTN_SRV_SENDFILE, {}, L"Отправить файл клиенту...",         BTN_VAR_SECONDARY,     false };
        m_buttons[3] = { IDC_BTN_CLI_SCAN,     {}, L"Поиск серверов в сети Radmin VPN",  BTN_VAR_SECONDARY,     true };
        m_buttons[4] = { IDC_BTN_CLI_CONNECT,  {}, L"Подключиться",                      BTN_VAR_PRIMARY_BLUE,  true };
        m_buttons[5] = { IDC_BTN_CLI_SENDFILE, {}, L"Отправить файл...",                 BTN_VAR_SECONDARY,     false };

        m_autoMinToggle.label = L"Сворачивать панель при подключении клиента";
        m_autoMinToggle.checked = false;
        m_autoMinToggle.knobT = 0.0f;

        RefreshButtonVisualStates();
    }

    void RefreshButtonVisualStates() {
        bool srvRun  = m_serverRunning.load();
        bool srvAuth = m_clientAuthorized.load();
        bool cliRun  = m_clientRunning.load();
        bool scanning = m_scanInProgress.load();

        m_buttons[0].text    = srvRun ? L"Остановить сервер" : L"Запустить сервер";
        m_buttons[0].variant = srvRun ? BTN_VAR_DANGER : BTN_VAR_PRIMARY_GREEN;

        m_buttons[2].enabled = (srvRun && srvAuth);
        m_buttons[2].variant = (srvRun && srvAuth) ? BTN_VAR_PRIMARY_BLUE : BTN_VAR_SECONDARY;

        m_buttons[3].text    = scanning ? L"Поиск серверов в сети..." : L"Поиск серверов в сети Radmin VPN";
        m_buttons[3].enabled = !scanning;

        m_buttons[4].text    = cliRun ? L"Отключиться" : L"Подключиться";
        m_buttons[4].variant = cliRun ? BTN_VAR_DANGER : BTN_VAR_PRIMARY_BLUE;

        m_buttons[5].enabled = cliRun;
        m_buttons[5].variant = cliRun ? BTN_VAR_PRIMARY_BLUE : BTN_VAR_SECONDARY;

        UpdateViewerTitle();
    }

    void UpdateViewerTitle() {
        if (!m_clientRunning || !IsWindow(m_hwndViewer)) return;
        std::wstringstream titleSs;
        titleSs << L"Radmin Ultra-Low Latency Viewer — FPS: " << m_cliFps.load()
                << L" | Enc: " << std::fixed << std::setprecision(1) << (m_cliEncodeUs.load() / 1000.0) << L"ms"
                << L" | Dec: " << (m_cliDecodeUs.load() / 1000.0) << L"ms"
                << L" | RTT: " << (m_cliRttUs.load() / 1000.0) << L"ms"
                << L" | [Ctrl+Alt+F - Полный экран | Drag&Drop файла]";
        SetWindowTextW(m_hwndViewer, titleSs.str().c_str());
    }

    void UpdateFontsForDpi(UINT dpi) {
        int editH = -MulDiv(10, dpi, 72);
        int listH = -MulDiv(9, dpi, 72);
        HFONT newEditFont = CreateFontW(editH, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT newListFont = CreateFontW(listH, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT newListBold = CreateFontW(listH, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        HWND edits[] = { m_editSrvName, m_editSrvPass, m_editSrvPort, m_editCliIp, m_editCliPort, m_editCliPass };
        for (HWND h : edits) if (h) SendMessageW(h, WM_SETFONT, (WPARAM)newEditFont, TRUE);
        if (m_listHosts) {
            SendMessageW(m_listHosts, WM_SETFONT, (WPARAM)newListFont, TRUE);
            SendMessageW(m_listHosts, LB_SETITEMHEIGHT, 0, MulDiv(28, dpi, 96));
        }

        if (m_hEditFont) DeleteObject(m_hEditFont);
        if (m_hListFont) DeleteObject(m_hListFont);
        if (m_hListFontBold) DeleteObject(m_hListFontBold);
        m_hEditFont = newEditFont;
        m_hListFont = newListFont;
        m_hListFontBold = newListBold;
        m_mainCanvas.UpdateFontsForDpi(dpi);
    }

    void RelayoutMainWindow() {
        if (!m_hwndMain || !m_editSrvName) return;
        RECT rc = {};
        GetClientRect(m_hwndMain, &rc);
        int cw = rc.right - rc.left, ch = rc.bottom - rc.top;
        if (cw <= 50 || ch <= 50) return;

        UINT dpi = GetDpiForWindow(m_hwndMain);
        auto S = [&](int v) { return (float)MulDiv(v, dpi, 96); };
        auto Si = [&](int v) { return MulDiv(v, dpi, 96); };

        float headerH = S(62);
        m_headerRect = D2D1::RectF(0.0f, 0.0f, (float)cw, headerH);

        float margin = S(16);
        float gap = S(16);
        float colW = ((float)cw - margin * 2.0f - gap) * 0.5f;
        float cardTop = headerH + S(14);
        float cardH = (float)ch - cardTop - margin;
        float leftX = margin;
        float rightX = margin + colW + gap;
        float pad = S(18);
        float sw = colW - pad * 2.0f;

        m_srvCardRect = D2D1::RectF(leftX, cardTop, leftX + colW, cardTop + cardH);
        m_cliCardRect = D2D1::RectF(rightX, cardTop, rightX + colW, cardTop + cardH);

        // Внутренняя геометрия поля ввода (рамка + отступы вокруг Win32 EDIT)
        int editInsetX = Si(9);
        int editInsetY = Si(6);
        float rowH = S(32);
        float rowStep = S(40);
        float btnH = S(34);

        HDWP hdwp = BeginDeferWindowPos(10);
        auto PlaceInput = [&](size_t idx, HWND hEdit, const std::wstring& lbl,
                              float x, float y, float lblW, float boxW) {
            m_inputFrames[idx].hwnd = hEdit;
            m_inputFrames[idx].label = lbl;
            m_inputFrames[idx].labelRect = D2D1::RectF(x, y, x + lblW, y + rowH);
            float bx = x + lblW + S(8);
            m_inputFrames[idx].rect = D2D1::RectF(bx, y, bx + boxW, y + rowH);
            if (hEdit) {
                hdwp = DeferWindowPos(hdwp, hEdit, nullptr,
                    (int)bx + editInsetX, (int)y + editInsetY,
                    std::max(10, (int)boxW - editInsetX * 2),
                    std::max(10, (int)rowH - editInsetY * 2),
                    SWP_NOZORDER | SWP_NOACTIVATE);
            }
        };

        // --- ЛЕВАЯ КАРТОЧКА: СЕРВЕР ---
        float sx = leftX + pad;
        float sy = cardTop + S(52);
        float srvLblW = std::min(S(165), sw * 0.45f);
        float srvBoxW = sw - srvLblW - S(8);

        PlaceInput(0, m_editSrvName, L"Имя машины / сервера:", sx, sy, srvLblW, srvBoxW); sy += rowStep;
        PlaceInput(1, m_editSrvPass, L"Пароль доступа:",       sx, sy, srvLblW, srvBoxW); sy += rowStep;
        PlaceInput(2, m_editSrvPort, L"Порт (TCP + UDP):",     sx, sy, srvLblW, srvBoxW); sy += rowStep;

        float toggleH = S(24);
        float trackW = S(38), trackH = S(20);
        m_autoMinToggle.hitRect = D2D1::RectF(sx, sy, sx + sw, sy + toggleH);
        m_autoMinToggle.trackRect = D2D1::RectF(sx, sy + (toggleH - trackH) * 0.5f,
                                                sx + trackW, sy + (toggleH + trackH) * 0.5f);
        sy += toggleH + S(12);

        float halfW = (sw - S(10)) * 0.5f;
        m_buttons[0].rect = D2D1::RectF(sx, sy, sx + halfW, sy + btnH);
        m_buttons[1].rect = D2D1::RectF(sx + halfW + S(10), sy, sx + sw, sy + btnH);
        sy += btnH + S(10);

        m_buttons[2].rect = D2D1::RectF(sx, sy, sx + sw, sy + btnH);
        sy += btnH + S(14);

        m_srvStatusBoxRect = D2D1::RectF(sx, sy, sx + sw, std::max(sy + S(70), cardTop + cardH - pad));

        // --- ПРАВАЯ КАРТОЧКА: КЛИЕНТ ---
        float cx = rightX + pad;
        float cy = cardTop + S(52);
        m_buttons[3].rect = D2D1::RectF(cx, cy, cx + sw, cy + S(32));
        cy += S(42);

        float reservedCliBottom = rowStep * 2.0f + btnH + S(14) + S(86) + pad;
        float listH = std::max(S(68), (cardTop + cardH) - cy - reservedCliBottom);
        m_listFrameRect = D2D1::RectF(cx, cy, cx + sw, cy + listH);
        if (m_listHosts) {
            int listPad = Si(4);
            hdwp = DeferWindowPos(hdwp, m_listHosts, nullptr,
                (int)cx + listPad, (int)cy + listPad,
                std::max(10, (int)sw - listPad * 2), std::max(10, (int)listH - listPad * 2),
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
        cy += listH + S(12);

        float cliLblW = std::min(S(130), sw * 0.34f);
        float portBoxW = S(76);
        float ipBoxW = sw - cliLblW - portBoxW - S(16);
        PlaceInput(3, m_editCliIp, L"IP и порт хоста:", cx, cy, cliLblW, ipBoxW);

        // Поле порта клиента справа от IP
        float portX = cx + cliLblW + S(8) + ipBoxW + S(8);
        m_inputFrames[4].hwnd = m_editCliPort;
        m_inputFrames[4].label.clear();
        m_inputFrames[4].rect = D2D1::RectF(portX, cy, portX + portBoxW, cy + rowH);
        if (m_editCliPort) {
            hdwp = DeferWindowPos(hdwp, m_editCliPort, nullptr,
                (int)portX + editInsetX, (int)cy + editInsetY,
                std::max(10, (int)portBoxW - editInsetX * 2),
                std::max(10, (int)rowH - editInsetY * 2),
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
        cy += rowStep;

        PlaceInput(5, m_editCliPass, L"Пароль сервера:", cx, cy, cliLblW, sw - cliLblW - S(8));
        cy += rowStep;

        float cliHalfW = (sw - S(10)) * 0.5f;
        m_buttons[4].rect = D2D1::RectF(cx, cy, cx + cliHalfW, cy + btnH);
        m_buttons[5].rect = D2D1::RectF(cx + cliHalfW + S(10), cy, cx + sw, cy + btnH);
        cy += btnH + S(14);

        m_cliStatusBoxRect = D2D1::RectF(cx, cy, cx + sw, std::max(cy + S(70), cardTop + cardH - pad));

        EndDeferWindowPos(hdwp);
        InvalidateRect(m_hwndMain, nullptr, FALSE);
    }

    int HitTestMainButton(POINT pt) const {
        for (const auto& b : m_buttons) {
            if (b.enabled && pt.x >= b.rect.left && pt.x <= b.rect.right &&
                pt.y >= b.rect.top && pt.y <= b.rect.bottom) {
                return b.id;
            }
        }
        return -1;
    }

    bool HitTestAutoMinToggle(POINT pt) const {
        const auto& r = m_autoMinToggle.hitRect;
        return pt.x >= r.left && pt.x <= r.right && pt.y >= r.top && pt.y <= r.bottom;
    }

    void OnMainCanvasButtonClick(int id) {
        switch (id) {
        case IDC_BTN_SRV_TOGGLE:
            if (!m_serverRunning) StartServerWithPinPrompt(); else StopServer();
            break;
        case IDC_BTN_SRV_TRAY:
            ShowInTray(true);
            break;
        case IDC_BTN_SRV_SENDFILE:
            PromptAndSendFile(true);
            break;
        case IDC_BTN_CLI_SCAN:
            ScanNetworkForServers();
            break;
        case IDC_BTN_CLI_CONNECT:
            if (!m_clientRunning) ConnectToServer(); else DisconnectClient();
            break;
        case IDC_BTN_CLI_SENDFILE:
            PromptAndSendFile(false);
            break;
        }
    }

    void DrawStyledButton(D2DOffscreenTarget& target, ID2D1DCRenderTarget* rt, const CanvasButton& btn, float scale) {
        D2D1_COLOR_F baseBg = HexColor(0x1E2638);
        D2D1_COLOR_F hoverBg = HexColor(0x28334A);
        D2D1_COLOR_F pressBg = HexColor(0x161D2B);
        D2D1_COLOR_F borderCol = HexColor(0x31405C);
        D2D1_COLOR_F txtCol = HexColor(0xE2E8F0);

        if (!btn.enabled) {
            baseBg = hoverBg = pressBg = HexColor(0x151B28);
            borderCol = HexColor(0x20293B);
            txtCol = HexColor(0x52607A);
        } else if (btn.variant == BTN_VAR_PRIMARY_BLUE) {
            baseBg = HexColor(0x2563EB);
            hoverBg = HexColor(0x3B82F6);
            pressBg = HexColor(0x1D4ED8);
            borderCol = HexColor(0x60A5FA, 0.55f);
            txtCol = HexColor(0xFFFFFF);
        } else if (btn.variant == BTN_VAR_PRIMARY_GREEN) {
            baseBg = HexColor(0x059669);
            hoverBg = HexColor(0x10B981);
            pressBg = HexColor(0x047857);
            borderCol = HexColor(0x34D399, 0.55f);
            txtCol = HexColor(0xFFFFFF);
        } else if (btn.variant == BTN_VAR_DANGER) {
            baseBg = HexColor(0xDC2626);
            hoverBg = HexColor(0xEF4444);
            pressBg = HexColor(0xB91C1C);
            borderCol = HexColor(0xFCA5A5, 0.5f);
            txtCol = HexColor(0xFFFFFF);
        } else if (btn.variant == BTN_VAR_GHOST) {
            baseBg = HexColor(0x141A27, 0.0f);
            hoverBg = HexColor(0x253047);
            pressBg = HexColor(0x1C2538);
            borderCol = HexColor(0x2C3852, btn.hoverT);
            txtCol = LerpColor(HexColor(0x94A3B8), HexColor(0xF8FAFC), btn.hoverT);
        }

        D2D1_COLOR_F fill = LerpColor(baseBg, hoverBg, btn.hoverT);
        fill = LerpColor(fill, pressBg, btn.pressT);

        float radius = 8.0f * scale;
        D2D1_ROUNDED_RECT rr = D2D1::RoundedRect(btn.rect, radius, radius);
        rt->FillRoundedRectangle(rr, target.Brush(fill));
        if (borderCol.a > 0.01f) {
            rt->DrawRoundedRectangle(rr, target.Brush(borderCol), 1.0f * scale);
        }

        if (btn.enabled && btn.hoverT > 0.02f && btn.variant != BTN_VAR_GHOST) {
            D2D1_ROUNDED_RECT topHighlight = D2D1::RoundedRect(
                D2D1::RectF(btn.rect.left + 1.0f, btn.rect.top + 1.0f, btn.rect.right - 1.0f, btn.rect.bottom - 1.0f),
                radius, radius);
            rt->DrawRoundedRectangle(topHighlight, target.Brush(HexColor(0xFFFFFF, 0.08f * btn.hoverT)), 1.0f);
        }

        target.DrawTextBox(btn.text, target.FmtButton(), btn.rect, txtCol);
    }

    void DrawBadgePill(D2DOffscreenTarget& target, ID2D1DCRenderTarget* rt, float rightX, float centerY,
                       const std::wstring& text, const D2D1_COLOR_F& dotCol, const D2D1_COLOR_F& bgCol,
                       const D2D1_COLOR_F& borderCol, const D2D1_COLOR_F& txtCol, float scale, float pulseAlpha) {
        float w = (float)(text.size() * 6.5 + 34.0) * scale;
        float h = 24.0f * scale;
        D2D1_RECT_F pill = D2D1::RectF(rightX - w, centerY - h * 0.5f, rightX, centerY + h * 0.5f);
        D2D1_ROUNDED_RECT rr = D2D1::RoundedRect(pill, h * 0.5f, h * 0.5f);
        rt->FillRoundedRectangle(rr, target.Brush(bgCol));
        rt->DrawRoundedRectangle(rr, target.Brush(borderCol), 1.0f * scale);

        float dotX = pill.left + 12.0f * scale;
        if (pulseAlpha > 0.01f) {
            D2D1_COLOR_F halo = dotCol;
            halo.a = pulseAlpha * 0.35f;
            rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(dotX, centerY), 6.5f * scale, 6.5f * scale), target.Brush(halo));
        }
        rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(dotX, centerY), 3.6f * scale, 3.6f * scale), target.Brush(dotCol));

        D2D1_RECT_F txtRect = D2D1::RectF(dotX + 7.0f * scale, pill.top, pill.right - 8.0f * scale, pill.bottom);
        target.DrawTextBox(text, target.FmtBadge(), txtRect, txtCol);
    }
};

static RemoteDesktopApp g_app;

// ============================================================================
// РЕАЛИЗАЦИЯ КАДРОВОГО ТИКА, ОТРИСОВКИ ГЛАВНОГО МЕНЮ И МОДАЛЬНОГО ДИАЛОГА PIN
// ============================================================================
void RemoteDesktopApp::TickAndRenderUi(float dt) {
    m_pulsePhase += dt * 3.4f;
    if (m_pulsePhase > 6.283185f) m_pulsePhase -= 6.283185f;

    float srvTargetGlow = m_serverRunning.load() ? (m_clientAuthorized.load() ? 1.0f : 0.65f) : 0.0f;
    float cliTargetGlow = m_clientRunning.load() ? 1.0f : 0.0f;
    m_srvCardGlow = SmoothApproach(m_srvCardGlow, srvTargetGlow, 9.0f, dt);
    m_cliCardGlow = SmoothApproach(m_cliCardGlow, cliTargetGlow, 9.0f, dt);

    HWND focused = GetFocus();
    for (auto& inp : m_inputFrames) {
        float target = (inp.hwnd && focused == inp.hwnd) ? 1.0f : 0.0f;
        inp.focusT = SmoothApproach(inp.focusT, target, 16.0f, dt);
    }
    m_listFocusT = SmoothApproach(m_listFocusT, (m_listHosts && focused == m_listHosts) ? 1.0f : 0.0f, 16.0f, dt);

    for (auto& b : m_buttons) {
        float hTarget = (b.enabled && m_hoveredBtnId == b.id && !m_modal.active) ? 1.0f : 0.0f;
        float pTarget = (b.enabled && m_pressedBtnId == b.id && m_hoveredBtnId == b.id && !m_modal.active) ? 1.0f : 0.0f;
        b.hoverT = SmoothApproach(b.hoverT, hTarget, 18.0f, dt);
        b.pressT = SmoothApproach(b.pressT, pTarget, 26.0f, dt);
    }

    m_autoMinToggle.hoverT = SmoothApproach(m_autoMinToggle.hoverT, (m_hoveredToggle && !m_modal.active) ? 1.0f : 0.0f, 18.0f, dt);
    m_autoMinToggle.knobT  = SmoothApproach(m_autoMinToggle.knobT, m_autoMinToggle.checked ? 1.0f : 0.0f, 20.0f, dt);

    if (m_hwndMain && IsWindowVisible(m_hwndMain) && !IsIconic(m_hwndMain)) {
        RedrawWindow(m_hwndMain, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_NOCHILDREN | RDW_NOERASE);
    }

    if (m_modal.active && m_modal.hwnd && IsWindowVisible(m_modal.hwnd)) {
        if (m_modal.shakeTimer > 0.0f) {
            m_modal.shakeTimer = std::max(0.0f, m_modal.shakeTimer - dt);
        }
        for (auto& mb : m_modal.buttons) {
            float hTarget = (m_modal.hoveredBtnId == mb.id) ? 1.0f : 0.0f;
            float pTarget = (m_modal.pressedBtnId == mb.id && m_modal.hoveredBtnId == mb.id) ? 1.0f : 0.0f;
            mb.hoverT = SmoothApproach(mb.hoverT, hTarget, 18.0f, dt);
            mb.pressT = SmoothApproach(mb.pressT, pTarget, 26.0f, dt);
        }
        RedrawWindow(m_modal.hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_NOCHILDREN | RDW_NOERASE);
    }
}

void RemoteDesktopApp::PaintMainWindow(HWND hwnd) {
    PAINTSTRUCT ps = {};
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc = {};
    GetClientRect(hwnd, &rc);
    uint32_t w = (uint32_t)std::max<LONG>(1, rc.right - rc.left);
    uint32_t h = (uint32_t)std::max<LONG>(1, rc.bottom - rc.top);

    ID2D1DCRenderTarget* rt = nullptr;
    if (!m_mainCanvas.BeginFrame(hwnd, w, h, &rt)) {
        EndPaint(hwnd, &ps);
        return;
    }

    UINT dpi = GetDpiForWindow(hwnd);
    float scale = (float)dpi / 96.0f;
    float pulseWave = 0.5f + 0.5f * std::sin(m_pulsePhase);

    // 1. Фон и верхняя панель заголовка
    rt->Clear(HexColor(0x0B0F17));
    rt->FillRectangle(m_headerRect, m_mainCanvas.Brush(HexColor(0x0F1522)));
    rt->DrawLine(D2D1::Point2F(0.0f, m_headerRect.bottom - 0.5f),
                 D2D1::Point2F((float)w, m_headerRect.bottom - 0.5f),
                 m_mainCanvas.Brush(HexColor(0x1E293B)), 1.0f * scale);

    // Векторный логотип в шапке
    float logoSize = 34.0f * scale;
    float logoX = 16.0f * scale;
    float logoY = (m_headerRect.bottom - logoSize) * 0.5f;
    D2D1_ROUNDED_RECT logoBox = D2D1::RoundedRect(D2D1::RectF(logoX, logoY, logoX + logoSize, logoY + logoSize),
                                                  8.0f * scale, 8.0f * scale);
    rt->FillRoundedRectangle(logoBox, m_mainCanvas.Brush(HexColor(0x1D4ED8, 0.28f)));
    rt->DrawRoundedRectangle(logoBox, m_mainCanvas.Brush(HexColor(0x3B82F6, 0.75f)), 1.2f * scale);

    float mPad = 7.0f * scale;
    D2D1_ROUNDED_RECT monitorGlyph = D2D1::RoundedRect(
        D2D1::RectF(logoX + mPad, logoY + mPad + 1.0f * scale, logoX + logoSize - mPad, logoY + logoSize - mPad - 3.0f * scale),
        2.5f * scale, 2.5f * scale);
    rt->DrawRoundedRectangle(monitorGlyph, m_mainCanvas.Brush(HexColor(0x60A5FA)), 1.6f * scale);
    rt->DrawLine(D2D1::Point2F(logoX + logoSize * 0.35f, logoY + logoSize - mPad + 0.5f * scale),
                 D2D1::Point2F(logoX + logoSize * 0.65f, logoY + logoSize - mPad + 0.5f * scale),
                 m_mainCanvas.Brush(HexColor(0x60A5FA)), 1.6f * scale);

    float titleX = logoX + logoSize + 12.0f * scale;
    m_mainCanvas.DrawTextBox(L"Radmin Ultra RD", m_mainCanvas.FmtTitle(),
                             D2D1::RectF(titleX, 8.0f * scale, (float)w * 0.55f, 34.0f * scale), HexColor(0xF8FAFC));
    m_mainCanvas.DrawTextBox(L"DXGI Capture · H.264 Low-Latency · UDP Stream · Encrypted File Transfer",
                             m_mainCanvas.FmtBadge(),
                             D2D1::RectF(titleX, 34.0f * scale, (float)w * 0.58f, 54.0f * scale), HexColor(0x64748B));
    // Выравнивание подзаголовка по левому краю
    // (создаём отдельный FmtLabel с мелким текстом или используем FmtBody для левого выравнивания)

    // Телеметрия в правой части шапки: FPS / Frame-Time счетчик + Radmin IP
    float pillH = 28.0f * scale;
    float pillY = (m_headerRect.bottom - pillH) * 0.5f;
    float fpsPillW = 205.0f * scale;
    float fpsPillX = (float)w - 16.0f * scale - fpsPillW;
    D2D1_RECT_F fpsPillRect = D2D1::RectF(fpsPillX, pillY, fpsPillX + fpsPillW, pillY + pillH);
    D2D1_ROUNDED_RECT fpsPillRR = D2D1::RoundedRect(fpsPillRect, 7.0f * scale, 7.0f * scale);
    rt->FillRoundedRectangle(fpsPillRR, m_mainCanvas.Brush(HexColor(0x131B2B)));
    rt->DrawRoundedRectangle(fpsPillRR, m_mainCanvas.Brush(HexColor(0x253248)), 1.0f * scale);

    float uiFps = m_framePacer.GetDisplayFps();
    float uiMs  = m_framePacer.GetDisplayFrameMs();
    bool smoothOk = (uiMs <= (1000.0f / std::max(30u, m_framePacer.GetTargetHz())) * 1.45f);
    D2D1_COLOR_F pacingDotCol = smoothOk ? HexColor(0x10B981) : HexColor(0xF59E0B);
    rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(fpsPillX + 11.0f * scale, pillY + pillH * 0.5f),
                                  3.5f * scale, 3.5f * scale), m_mainCanvas.Brush(pacingDotCol));

    std::wstringstream fpsSs;
    fpsSs << std::fixed << std::setprecision(1) << uiFps << L" FPS · " << std::setprecision(1) << uiMs << L" ms";
    m_mainCanvas.DrawTextBox(fpsSs.str(), m_mainCanvas.FmtMono(),
                             D2D1::RectF(fpsPillX + 17.0f * scale, pillY, fpsPillX + 148.0f * scale, pillY + pillH),
                             HexColor(0xE2E8F0));

    // Мини-график (Sparkline) времени последних 24 кадров UI
    const auto& hist = m_framePacer.GetHistoryMs();
    size_t cursor = m_framePacer.GetHistoryCursor();
    float sparkX = fpsPillX + 150.0f * scale;
    float sparkW = 48.0f * scale;
    float sparkBaseY = pillY + pillH - 6.0f * scale;
    float sparkMaxH = pillH - 12.0f * scale;
    float barW = sparkW / (float)UiFramePacer::HISTORY_SIZE;
    float refMs = 1000.0f / (float)std::max(30u, m_framePacer.GetTargetHz());
    for (size_t i = 0; i < UiFramePacer::HISTORY_SIZE; ++i) {
        float msVal = hist[(cursor + i) % UiFramePacer::HISTORY_SIZE];
        float norm = std::clamp(msVal / (refMs * 2.0f), 0.12f, 1.0f);
        float bh = norm * sparkMaxH;
        D2D1_COLOR_F bCol = (msVal <= refMs * 1.35f) ? HexColor(0x10B981, 0.85f) : HexColor(0xF59E0B, 0.9f);
        rt->FillRectangle(D2D1::RectF(sparkX + i * barW, sparkBaseY - bh,
                                      sparkX + (i + 1) * barW - 0.6f * scale, sparkBaseY),
                          m_mainCanvas.Brush(bCol));
    }

    // Плашка Radmin IP слева от счетчика FPS
    std::string radminIpCopy;
    {
        std::lock_guard<std::mutex> lock(m_srvInfoMutex);
        if (m_radminIp.empty()) m_radminIp = DetectRadminVpnIP();
        radminIpCopy = m_radminIp;
    }
    std::wstringstream ipPillSs;
    ipPillSs << L"VPN: " << std::wstring(radminIpCopy.begin(), radminIpCopy.end()) << L":" << m_serverPort;
    float ipPillW = 165.0f * scale;
    float ipPillX = fpsPillX - 10.0f * scale - ipPillW;
    if (ipPillX > (float)w * 0.56f) {
        D2D1_RECT_F ipRect = D2D1::RectF(ipPillX, pillY, ipPillX + ipPillW, pillY + pillH);
        D2D1_ROUNDED_RECT ipRR = D2D1::RoundedRect(ipRect, 7.0f * scale, 7.0f * scale);
        rt->FillRoundedRectangle(ipRR, m_mainCanvas.Brush(HexColor(0x131B2B)));
        rt->DrawRoundedRectangle(ipRR, m_mainCanvas.Brush(HexColor(0x253248)), 1.0f * scale);
        m_mainCanvas.DrawTextBox(ipPillSs.str(), m_mainCanvas.FmtMono(), ipRect, HexColor(0x93C5FD));
    }

    // 2. Карточки Хоста и Клиента
    auto DrawCard = [&](const D2D1_RECT_F& r, float glowT, const D2D1_COLOR_F& glowBorder,
                        const std::wstring& cardTitle, const std::wstring& badgeText,
                        const D2D1_COLOR_F& dotCol, const D2D1_COLOR_F& badgeBg,
                        const D2D1_COLOR_F& badgeBorder, const D2D1_COLOR_F& badgeTxt, float pulseAlpha) {
        D2D1_ROUNDED_RECT rr = D2D1::RoundedRect(r, 12.0f * scale, 12.0f * scale);
        rt->FillRoundedRectangle(rr, m_mainCanvas.Brush(HexColor(0x121926)));
        D2D1_COLOR_F bCol = LerpColor(HexColor(0x222D42), glowBorder, glowT);
        rt->DrawRoundedRectangle(rr, m_mainCanvas.Brush(bCol), (1.0f + 0.5f * glowT) * scale);

        float hdrBottom = r.top + 42.0f * scale;
        rt->DrawLine(D2D1::Point2F(r.left + 16.0f * scale, hdrBottom),
                     D2D1::Point2F(r.right - 16.0f * scale, hdrBottom),
                     m_mainCanvas.Brush(HexColor(0x1E293B)), 1.0f * scale);

        m_mainCanvas.DrawTextBox(cardTitle, m_mainCanvas.FmtCardTitle(),
                                 D2D1::RectF(r.left + 18.0f * scale, r.top + 6.0f * scale, r.right - 140.0f * scale, hdrBottom),
                                 HexColor(0xF1F5F9));

        DrawBadgePill(m_mainCanvas, rt, r.right - 16.0f * scale, r.top + 24.0f * scale,
                      badgeText, dotCol, badgeBg, badgeBorder, badgeTxt, scale, pulseAlpha);
    };

    bool srvRun = m_serverRunning.load();
    bool srvAuth = m_clientAuthorized.load();
    if (!srvRun) {
        DrawCard(m_srvCardRect, m_srvCardGlow, HexColor(0x10B981),
                 L"[1] Режим Хоста (Сервер)", L"Остановлен",
                 HexColor(0x64748B), HexColor(0x182030), HexColor(0x28344B), HexColor(0x94A3B8), 0.0f);
    } else if (!srvAuth) {
        DrawCard(m_srvCardRect, m_srvCardGlow, HexColor(0xF59E0B, 0.7f),
                 L"[1] Режим Хоста (Сервер)", L"Ожидание · PIN активен",
                 HexColor(0xF59E0B), HexColor(0x2A1F0D), HexColor(0x784B10), HexColor(0xFCD34D), pulseWave);
    } else {
        DrawCard(m_srvCardRect, m_srvCardGlow, HexColor(0x10B981, 0.85f),
                 L"[1] Режим Хоста (Сервер)", L"Активен · PIN защищён",
                 HexColor(0x10B981), HexColor(0x0B291E), HexColor(0x065F46), HexColor(0x6EE7B7), pulseWave);
    }

    bool cliRun = m_clientRunning.load();
    if (!cliRun) {
        DrawCard(m_cliCardRect, m_cliCardGlow, HexColor(0x3B82F6),
                 L"[2] Режим Клиента (Просмотр)", L"Отключен",
                 HexColor(0x64748B), HexColor(0x182030), HexColor(0x28344B), HexColor(0x94A3B8), 0.0f);
    } else {
        DrawCard(m_cliCardRect, m_cliCardGlow, HexColor(0x3B82F6, 0.85f),
                 L"[2] Режим Клиента (Просмотр)", L"Трансляция активна",
                 HexColor(0x38BDF8), HexColor(0x0C223B), HexColor(0x0369A1), HexColor(0x7DD3FC), pulseWave);
    }

    // 3. Рамки полей ввода
    for (const auto& inp : m_inputFrames) {
        if (!inp.label.empty()) {
            m_mainCanvas.DrawTextBox(inp.label, m_mainCanvas.FmtLabel(), inp.labelRect, HexColor(0x94A3B8));
        }
        D2D1_ROUNDED_RECT ir = D2D1::RoundedRect(inp.rect, 7.0f * scale, 7.0f * scale);
        rt->FillRoundedRectangle(ir, m_mainCanvas.Brush(HexColor(0x131824)));
        D2D1_COLOR_F bCol = LerpColor(HexColor(0x253047), HexColor(0x3B82F6), inp.focusT);
        rt->DrawRoundedRectangle(ir, m_mainCanvas.Brush(bCol), (1.0f + 0.5f * inp.focusT) * scale);
    }

    // 4. Рамка списка обнаруженных хостов
    {
        D2D1_ROUNDED_RECT lr = D2D1::RoundedRect(m_listFrameRect, 8.0f * scale, 8.0f * scale);
        rt->FillRoundedRectangle(lr, m_mainCanvas.Brush(HexColor(0x0F141F)));
        D2D1_COLOR_F lbCol = LerpColor(HexColor(0x232E45), HexColor(0x3B82F6), m_listFocusT);
        rt->DrawRoundedRectangle(lr, m_mainCanvas.Brush(lbCol), (1.0f + 0.4f * m_listFocusT) * scale);
    }

    // 5. Плавный переключатель "Сворачивать панель"
    {
        const auto& tr = m_autoMinToggle.trackRect;
        float r = (tr.bottom - tr.top) * 0.5f;
        D2D1_COLOR_F trackCol = LerpColor(HexColor(0x1E293B), HexColor(0x10B981), m_autoMinToggle.knobT);
        D2D1_COLOR_F trackBdr = LerpColor(HexColor(0x334155), HexColor(0x34D399, 0.7f), m_autoMinToggle.knobT);
        rt->FillRoundedRectangle(D2D1::RoundedRect(tr, r, r), m_mainCanvas.Brush(trackCol));
        rt->DrawRoundedRectangle(D2D1::RoundedRect(tr, r, r), m_mainCanvas.Brush(trackBdr), 1.0f * scale);

        float knobR = r - 3.0f * scale;
        float minX = tr.left + r;
        float maxX = tr.right - r;
        float knobX = minX + (maxX - minX) * m_autoMinToggle.knobT;
        float knobY = (tr.top + tr.bottom) * 0.5f;
        rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(knobX, knobY), knobR, knobR),
                        m_mainCanvas.Brush(HexColor(0xF8FAFC)));

        D2D1_RECT_F lblRect = D2D1::RectF(tr.right + 10.0f * scale, m_autoMinToggle.hitRect.top,
                                          m_autoMinToggle.hitRect.right, m_autoMinToggle.hitRect.bottom);
        D2D1_COLOR_F lblCol = LerpColor(HexColor(0x94A3B8), HexColor(0xE2E8F0), m_autoMinToggle.hoverT * 0.7f + m_autoMinToggle.knobT * 0.3f);
        m_mainCanvas.DrawTextBox(m_autoMinToggle.label, m_mainCanvas.FmtLabel(), lblRect, lblCol);
    }

    // 6. Кнопки
    for (const auto& btn : m_buttons) {
        DrawStyledButton(m_mainCanvas, rt, btn, scale);
    }

    // 7. Нижние панели телеметрии и статуса файлов
    std::wstring srvFileStr, cliFileStr;
    float srvPct = 0.0f, cliPct = 0.0f;
    {
        std::lock_guard<std::mutex> lock(m_fileStatusMutex);
        srvFileStr = m_srvFileStatus;
        cliFileStr = m_cliFileStatus;
        srvPct = m_srvFilePct;
        cliPct = m_cliFilePct;
    }

    std::string cliIpCopy;
    {
        std::lock_guard<std::mutex> lock(m_srvInfoMutex);
        cliIpCopy = m_connectedClientIp;
    }

    // Телеметрия сервера
    {
        D2D1_ROUNDED_RECT sr = D2D1::RoundedRect(m_srvStatusBoxRect, 8.0f * scale, 8.0f * scale);
        rt->FillRoundedRectangle(sr, m_mainCanvas.Brush(HexColor(0x0C111B)));
        rt->DrawRoundedRectangle(sr, m_mainCanvas.Brush(HexColor(0x1C2538)), 1.0f * scale);

        std::wstringstream ss;
        ss << L"Адрес Radmin VPN: " << std::wstring(radminIpCopy.begin(), radminIpCopy.end()) << L":" << m_serverPort << L"\n";
        if (!srvRun) {
            ss << L"Статус: Сервер остановлен (закройте окно без PIN-кода)\n";
        } else if (!srvAuth) {
            ss << L"Статус: Ожидание клиента (Discovery UDP:" << DISCOVERY_UDP_PORT << L") · Выход защищён PIN-кодом\n";
        } else {
            ss << L"Клиент: " << std::wstring(cliIpCopy.begin(), cliIpCopy.end())
               << L" | Stream FPS: " << m_srvFps.load()
               << L" | Enc: " << std::fixed << std::setprecision(1) << (m_srvEncodeUs.load() / 1000.0) << L"ms"
               << L" | Dec: " << (m_srvClientDecodeUs.load() / 1000.0) << L"ms"
               << L" | RTT: " << (m_srvRttUs.load() / 1000.0) << L"ms\n";
        }
        ss << srvFileStr;

        D2D1_RECT_F tr = D2D1::RectF(m_srvStatusBoxRect.left + 12.0f * scale, m_srvStatusBoxRect.top + 9.0f * scale,
                                     m_srvStatusBoxRect.right - 12.0f * scale, m_srvStatusBoxRect.bottom - 10.0f * scale);
        m_mainCanvas.DrawTextBox(ss.str(), m_mainCanvas.FmtBody(), tr, HexColor(0x94A3B8));

        if (m_srvSendingFile.load() && srvPct > 0.0f && srvPct < 1.0f) {
            float barY = m_srvStatusBoxRect.bottom - 5.0f * scale;
            float barW = (m_srvStatusBoxRect.right - m_srvStatusBoxRect.left - 24.0f * scale) * srvPct;
            rt->FillRectangle(D2D1::RectF(m_srvStatusBoxRect.left + 12.0f * scale, barY,
                                          m_srvStatusBoxRect.left + 12.0f * scale + barW, barY + 2.5f * scale),
                              m_mainCanvas.Brush(HexColor(0x3B82F6)));
        }
    }

    // Телеметрия клиента
    {
        D2D1_ROUNDED_RECT cr = D2D1::RoundedRect(m_cliStatusBoxRect, 8.0f * scale, 8.0f * scale);
        rt->FillRoundedRectangle(cr, m_mainCanvas.Brush(HexColor(0x0C111B)));
        rt->DrawRoundedRectangle(cr, m_mainCanvas.Brush(HexColor(0x1C2538)), 1.0f * scale);

        std::wstringstream ss;
        if (!cliRun) {
            ss << L"Статус: Отключен. Нажмите «Поиск серверов» или введите IP.\n"
               << L"Подсказка: перетащите файл в окно просмотра для быстрой отправки\n";
        } else {
            ss << L"Статус: Трансляция активна (Ctrl+Alt+F — полный экран)\n"
               << L"Stream FPS: " << m_cliFps.load()
               << L" | Enc: " << std::fixed << std::setprecision(1) << (m_cliEncodeUs.load() / 1000.0) << L"ms"
               << L" | Dec: " << (m_cliDecodeUs.load() / 1000.0) << L"ms"
               << L" | RTT: " << (m_cliRttUs.load() / 1000.0) << L"ms\n";
        }
        ss << cliFileStr;

        D2D1_RECT_F tr = D2D1::RectF(m_cliStatusBoxRect.left + 12.0f * scale, m_cliStatusBoxRect.top + 9.0f * scale,
                                     m_cliStatusBoxRect.right - 12.0f * scale, m_cliStatusBoxRect.bottom - 10.0f * scale);
        m_mainCanvas.DrawTextBox(ss.str(), m_mainCanvas.FmtBody(), tr, HexColor(0x94A3B8));

        if (m_cliSendingFile.load() && cliPct > 0.0f && cliPct < 1.0f) {
            float barY = m_cliStatusBoxRect.bottom - 5.0f * scale;
            float barW = (m_cliStatusBoxRect.right - m_cliStatusBoxRect.left - 24.0f * scale) * cliPct;
            rt->FillRectangle(D2D1::RectF(m_cliStatusBoxRect.left + 12.0f * scale, barY,
                                          m_cliStatusBoxRect.left + 12.0f * scale + barW, barY + 2.5f * scale),
                              m_mainCanvas.Brush(HexColor(0x3B82F6)));
        }
    }

    m_mainCanvas.EndFrameAndBlit(hdc, w, h);
    EndPaint(hwnd, &ps);
}

void RemoteDesktopApp::PaintModalWindow(HWND hwnd) {
    PAINTSTRUCT ps = {};
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc = {};
    GetClientRect(hwnd, &rc);
    uint32_t w = (uint32_t)std::max<LONG>(1, rc.right - rc.left);
    uint32_t h = (uint32_t)std::max<LONG>(1, rc.bottom - rc.top);

    ID2D1DCRenderTarget* rt = nullptr;
    if (!m_modal.canvas.BeginFrame(hwnd, w, h, &rt)) {
        EndPaint(hwnd, &ps);
        return;
    }

    UINT dpi = GetDpiForWindow(hwnd);
    float scale = (float)dpi / 96.0f;
    bool isConfirm = (m_modal.mode == ModalPinMode::ConfirmExitHostSession);

    rt->Clear(HexColor(0x111723));
    D2D1_RECT_F outer = D2D1::RectF(0.5f, 0.5f, (float)w - 0.5f, (float)h - 0.5f);
    rt->DrawRectangle(outer, m_modal.canvas.Brush(HexColor(0x2B3852)), 1.0f * scale);

    // Верхняя акцентная полоса
    D2D1_COLOR_F accent = isConfirm ? HexColor(0xEF4444) : HexColor(0x10B981);
    rt->FillRectangle(D2D1::RectF(0.0f, 0.0f, (float)w, 3.5f * scale), m_modal.canvas.Brush(accent));

    // Значок щита/замка
    float pad = 22.0f * scale;
    float iconSize = 32.0f * scale;
    D2D1_ROUNDED_RECT iconBox = D2D1::RoundedRect(D2D1::RectF(pad, 20.0f * scale, pad + iconSize, 20.0f * scale + iconSize),
                                                  8.0f * scale, 8.0f * scale);
    D2D1_COLOR_F iconBg = isConfirm ? HexColor(0xEF4444, 0.16f) : HexColor(0x10B981, 0.16f);
    rt->FillRoundedRectangle(iconBox, m_modal.canvas.Brush(iconBg));
    rt->DrawRoundedRectangle(iconBox, m_modal.canvas.Brush(accent), 1.1f * scale);

    // Простой векторный символ замка внутри иконки
    float lx = pad + iconSize * 0.5f;
    float ly = 20.0f * scale + iconSize * 0.54f;
    rt->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(lx - 5.5f * scale, ly - 3.0f * scale, lx + 5.5f * scale, ly + 5.5f * scale),
                                               1.8f * scale, 1.8f * scale),
                             m_modal.canvas.Brush(accent), 1.6f * scale);
    rt->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(lx, ly - 5.0f * scale), 3.2f * scale, 3.5f * scale),
                    m_modal.canvas.Brush(accent), 1.5f * scale);

    std::wstring title = isConfirm
        ? L"Подтверждение выхода из хост-сессии"
        : L"PIN-код защиты активной сессии";
    std::wstring subtitle = isConfirm
        ? L"Хост-сессия активна. Введите заданный при запуске PIN-код, чтобы остановить сервер и выйти (Esc — отмена):"
        : L"Задайте временный PIN-код (хранится только в ОЗУ на время этой сессии). Он потребуется для выхода из программы:";

    m_modal.canvas.DrawTextBox(title, m_modal.canvas.FmtCardTitle(),
                               D2D1::RectF(pad + iconSize + 12.0f * scale, 18.0f * scale, (float)w - pad, 52.0f * scale),
                               HexColor(0xF8FAFC));
    m_modal.canvas.DrawTextBox(subtitle, m_modal.canvas.FmtBody(),
                               D2D1::RectF(pad, 62.0f * scale, (float)w - pad, 108.0f * scale),
                               HexColor(0x94A3B8));

    // Сдвиг рамки поля ввода при ошибке (shake-анимация)
    float shakeX = 0.0f;
    if (m_modal.shakeTimer > 0.0f) {
        shakeX = std::sin(m_modal.shakeTimer * 52.0f) * 6.0f * scale * (m_modal.shakeTimer / 0.35f);
    }

    D2D1_RECT_F er = m_modal.editFrameRect;
    er.left += shakeX; er.right += shakeX;
    D2D1_ROUNDED_RECT editRR = D2D1::RoundedRect(er, 8.0f * scale, 8.0f * scale);
    rt->FillRoundedRectangle(editRR, m_modal.canvas.Brush(HexColor(0x161D2C)));
    bool hasErr = !m_modal.errorText.empty();
    D2D1_COLOR_F editBorder = hasErr ? HexColor(0xEF4444) : HexColor(0x3B82F6);
    rt->DrawRoundedRectangle(editRR, m_modal.canvas.Brush(editBorder), 1.4f * scale);

    if (hasErr) {
        m_modal.canvas.DrawTextBox(m_modal.errorText, m_modal.canvas.FmtLabel(),
                                   D2D1::RectF(pad, er.bottom + 6.0f * scale, (float)w - pad, er.bottom + 28.0f * scale),
                                   HexColor(0xF87171));
    }

    for (const auto& mb : m_modal.buttons) {
        DrawStyledButton(m_modal.canvas, rt, mb, scale);
    }

    m_modal.canvas.EndFrameAndBlit(hdc, w, h);
    EndPaint(hwnd, &ps);
}

// ============================================================================
// ПРОЦЕДУРЫ ОКОН И МОДАЛЬНОГО ДИАЛОГА PIN
// ============================================================================
LRESULT CALLBACK ModalPinWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto SubmitModal = []() {
        if (!g_app.m_modal.hwndEdit) return;
        wchar_t pinBuf[128] = {};
        int len = GetWindowTextW(g_app.m_modal.hwndEdit, pinBuf, (int)_countof(pinBuf));

        if (g_app.m_modal.mode == ModalPinMode::SetHostSessionPin) {
            if (len < 1) {
                g_app.m_modal.errorText = L"Введите непустой PIN-код или парольную фразу!";
                g_app.m_modal.shakeTimer = 0.35f;
                SetFocus(g_app.m_modal.hwndEdit);
                SecureZeroMemory(pinBuf, sizeof(pinBuf));
                return;
            }
            if (!g_app.SetRuntimeSessionPin(pinBuf, (size_t)len)) {
                g_app.m_modal.errorText = L"Ошибка инициализации криптографии!";
                g_app.m_modal.shakeTimer = 0.35f;
                SecureZeroMemory(pinBuf, sizeof(pinBuf));
                return;
            }
            SecureZeroMemory(pinBuf, sizeof(pinBuf));
            g_app.m_modal.confirmed = true;
            g_app.m_modal.active = false;
        } else {
            if (len < 1 || !g_app.VerifyRuntimeSessionPin(pinBuf, (size_t)len)) {
                g_app.m_modal.errorText = L"Неверный PIN-код сессии. Попробуйте ещё раз или нажмите Esc.";
                g_app.m_modal.shakeTimer = 0.35f;
                SetWindowTextW(g_app.m_modal.hwndEdit, L"");
                SetFocus(g_app.m_modal.hwndEdit);
                SecureZeroMemory(pinBuf, sizeof(pinBuf));
                return;
            }
            SecureZeroMemory(pinBuf, sizeof(pinBuf));
            g_app.m_modal.confirmed = true;
            g_app.m_modal.active = false;
        }
    };

    switch (msg) {
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(241, 245, 249));
        SetBkColor(hdc, RGB(22, 29, 44));
        static HBRUSH s_modalEditBrush = CreateSolidBrush(RGB(22, 29, 44));
        return (LRESULT)s_modalEditBrush;
    }

    case WM_NCHITTEST: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ScreenToClient(hwnd, &pt);
        for (const auto& b : g_app.m_modal.buttons) {
            if (pt.x >= b.rect.left && pt.x <= b.rect.right && pt.y >= b.rect.top && pt.y <= b.rect.bottom) {
                return HTCLIENT;
            }
        }
        if (pt.x >= g_app.m_modal.editFrameRect.left && pt.x <= g_app.m_modal.editFrameRect.right &&
            pt.y >= g_app.m_modal.editFrameRect.top  && pt.y <= g_app.m_modal.editFrameRect.bottom) {
            return HTCLIENT;
        }
        if (pt.y < 60) return HTCAPTION;
        return HTCLIENT;
    }

    case WM_PAINT:
        g_app.PaintModalWindow(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_MOUSEMOVE: {
        if (!g_app.m_modal.trackingMouse) {
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
            g_app.m_modal.trackingMouse = true;
        }
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        int hit = -1;
        for (const auto& b : g_app.m_modal.buttons) {
            if (pt.x >= b.rect.left && pt.x <= b.rect.right && pt.y >= b.rect.top && pt.y <= b.rect.bottom) {
                hit = b.id;
                break;
            }
        }
        g_app.m_modal.hoveredBtnId = hit;
        return 0;
    }

    case WM_MOUSELEAVE:
        g_app.m_modal.trackingMouse = false;
        g_app.m_modal.hoveredBtnId = -1;
        return 0;

    case WM_LBUTTONDOWN: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        int hit = -1;
        for (const auto& b : g_app.m_modal.buttons) {
            if (pt.x >= b.rect.left && pt.x <= b.rect.right && pt.y >= b.rect.top && pt.y <= b.rect.bottom) {
                hit = b.id;
                break;
            }
        }
        if (hit != -1) {
            g_app.m_modal.pressedBtnId = hit;
            SetCapture(hwnd);
        }
        return 0;
    }

    case WM_LBUTTONUP: {
        if (GetCapture() == hwnd) ReleaseCapture();
        int pressed = g_app.m_modal.pressedBtnId;
        g_app.m_modal.pressedBtnId = -1;
        if (pressed != -1 && pressed == g_app.m_modal.hoveredBtnId) {
            if (pressed == IDC_MODAL_BTN_OK) {
                SubmitModal();
            } else if (pressed == IDC_MODAL_BTN_CANCEL) {
                g_app.m_modal.confirmed = false;
                g_app.m_modal.active = false;
            } else if (pressed == IDC_MODAL_BTN_EYE) {
                g_app.m_modal.showPassword = !g_app.m_modal.showPassword;
                g_app.m_modal.buttons[2].text = g_app.m_modal.showPassword ? L"Скрыть" : L"Показать";
                SendMessageW(g_app.m_modal.hwndEdit, EM_SETPASSWORDCHAR,
                             g_app.m_modal.showPassword ? 0 : L'\x25CF', 0);
                InvalidateRect(g_app.m_modal.hwndEdit, nullptr, TRUE);
                SetFocus(g_app.m_modal.hwndEdit);
            }
        }
        return 0;
    }

    case WM_CAPTURECHANGED:
        g_app.m_modal.pressedBtnId = -1;
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_MODAL_EDIT_PIN && HIWORD(wParam) == EN_CHANGE) {
            g_app.m_modal.errorText.clear();
        }
        return 0;

    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE) {
            g_app.m_modal.confirmed = false;
            g_app.m_modal.active = false;
            return 0;
        } else if (wParam == VK_RETURN) {
            SubmitModal();
            return 0;
        }
        return 0;

    case WM_CLOSE:
        g_app.m_modal.confirmed = false;
        g_app.m_modal.active = false;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool RemoteDesktopApp::RunPinModalDialog(ModalPinMode mode) {
    if (m_modal.active) return false;
    if (!IsWindowVisible(m_hwndMain) || IsIconic(m_hwndMain)) {
        RestoreFromTray();
    }

    UINT dpi = GetDpiForWindow(m_hwndMain);
    auto S = [&](int v) { return (float)MulDiv(v, dpi, 96); };
    auto Si = [&](int v) { return MulDiv(v, dpi, 96); };

    int dlgW = Si(456);
    int dlgH = Si(236);

    RECT ownerRc = {};
    GetWindowRect(m_hwndMain, &ownerRc);
    int posX = ownerRc.left + ((ownerRc.right - ownerRc.left) - dlgW) / 2;
    int posY = ownerRc.top  + ((ownerRc.bottom - ownerRc.top) - dlgH) / 2;

    m_modal.mode = mode;
    m_modal.errorText.clear();
    m_modal.shakeTimer = 0.0f;
    m_modal.showPassword = false;
    m_modal.confirmed = false;
    m_modal.hoveredBtnId = -1;
    m_modal.pressedBtnId = -1;
    m_modal.trackingMouse = false;

    HINSTANCE hInst = GetModuleHandleW(nullptr);
    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"RadminUltraRD_PinModal",
        (mode == ModalPinMode::ConfirmExitHostSession) ? L"Подтверждение выхода" : L"PIN-код сессии",
        WS_POPUP | WS_CLIPCHILDREN,
        posX, posY, dlgW, dlgH,
        m_hwndMain, nullptr, hInst, nullptr);
    if (!hDlg) return false;

    ApplyWindowDarkChrome(hDlg, true);
    m_modal.hwnd = hDlg;

    float pad = S(22);
    float eyeW = S(86);
    float editTop = S(116);
    float editH = S(36);
    float editW = (float)dlgW - pad * 2.0f - eyeW - S(8);
    m_modal.editFrameRect = D2D1::RectF(pad, editTop, pad + editW, editTop + editH);

    int insetX = Si(10), insetY = Si(8);
    m_modal.hwndEdit = CreateWindowExW(
        0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
        (int)pad + insetX, (int)editTop + insetY,
        std::max(20, (int)editW - insetX * 2), std::max(16, (int)editH - insetY * 2),
        hDlg, (HMENU)(INT_PTR)IDC_MODAL_EDIT_PIN, hInst, nullptr);
    SendMessageW(m_modal.hwndEdit, WM_SETFONT, (WPARAM)m_hEditFont, TRUE);
    SendMessageW(m_modal.hwndEdit, EM_LIMITTEXT, 64, 0);
    SendMessageW(m_modal.hwndEdit, EM_SETPASSWORDCHAR, L'\x25CF', 0);

    float btnY = (float)dlgH - S(54);
    float btnH = S(34);
    float okW = (mode == ModalPinMode::ConfirmExitHostSession) ? S(162) : S(138);
    float cancelW = S(112);

    m_modal.buttons[0] = {
        IDC_MODAL_BTN_OK,
        D2D1::RectF((float)dlgW - pad - okW, btnY, (float)dlgW - pad, btnY + btnH),
        (mode == ModalPinMode::ConfirmExitHostSession) ? L"Остановить и выйти" : L"Запустить хост",
        (mode == ModalPinMode::ConfirmExitHostSession) ? BTN_VAR_DANGER : BTN_VAR_PRIMARY_GREEN,
        true
    };
    m_modal.buttons[1] = {
        IDC_MODAL_BTN_CANCEL,
        D2D1::RectF((float)dlgW - pad - okW - S(10) - cancelW, btnY, (float)dlgW - pad - okW - S(10), btnY + btnH),
        L"Отмена (Esc)",
        BTN_VAR_SECONDARY,
        true
    };
    m_modal.buttons[2] = {
        IDC_MODAL_BTN_EYE,
        D2D1::RectF(pad + editW + S(8), editTop, (float)dlgW - pad, editTop + editH),
        L"Показать",
        BTN_VAR_SECONDARY,
        true
    };

    m_modal.canvas.UpdateFontsForDpi(dpi);
    m_modal.active = true;

    EnableWindow(m_hwndMain, FALSE);
    ShowWindow(hDlg, SW_SHOW);
    SetForegroundWindow(hDlg);
    SetFocus(m_modal.hwndEdit);
    m_framePacer.ResetTiming();

    MSG msg = {};
    while (m_modal.active) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                PostQuitMessage((int)msg.wParam);
                m_modal.confirmed = false;
                m_modal.active = false;
                break;
            }
            if ((msg.message == WM_KEYDOWN || msg.message == WM_SYSKEYDOWN) &&
                (msg.wParam == VK_ESCAPE || msg.wParam == VK_RETURN)) {
                SendMessageW(hDlg, msg.message, msg.wParam, msg.lParam);
                continue;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if (!m_modal.active) break;

        float dt = 0.0f;
        if (m_framePacer.WaitOrCheckFrameReady(true, dt)) {
            TickAndRenderUi(dt);
        }
    }

    if (IsWindow(m_modal.hwndEdit)) {
        SetWindowTextW(m_modal.hwndEdit, L"");
        SendMessageW(m_modal.hwndEdit, EM_EMPTYUNDOBUFFER, 0, 0);
    }
    EnableWindow(m_hwndMain, TRUE);
    DestroyWindow(hDlg);
    m_modal.canvas.Destroy();
    m_modal.hwnd = nullptr;
    m_modal.hwndEdit = nullptr;
    SetForegroundWindow(m_hwndMain);
    m_framePacer.ResetTiming();
    return m_modal.confirmed;
}

void RemoteDesktopApp::HandleCloseRequest() {
    if (m_modal.active) return;

    if (m_serverRunning.load()) {
        if (RunPinModalDialog(ModalPinMode::ConfirmExitHostSession)) {
            StopServer();
            DestroyWindow(m_hwndMain);
        }
    } else {
        DestroyWindow(m_hwndMain);
    }
}

// ============================================================================
// ХУК КЛАВИШИ WINDOWS И ОКОННЫЕ ПРОЦЕДУРЫ WIN32
// ============================================================================
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && g_app.m_clientRunning) {
        auto* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        if (kb && kb->dwExtraInfo != INJECTED_SIGNATURE) {
            if ((kb->vkCode == VK_LWIN || kb->vkCode == VK_RWIN) &&
                GetForegroundWindow() == g_app.m_hwndViewer) {
                bool isDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
                g_app.SendClientKeyEvent((uint16_t)kb->scanCode, (uint16_t)kb->vkCode, isDown, true);
                return 1;
            }
        }
    }
    return CallNextHookEx(g_app.m_hKeyboardHook, nCode, wParam, lParam);
}

LRESULT CALLBACK ViewerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if ((msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) || (msg >= WM_KEYFIRST && msg <= WM_KEYLAST)) {
        if (GetMessageExtraInfo() == INJECTED_SIGNATURE) return 0;
    }

    switch (msg) {
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) g_app.m_renderer.OnResize(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wParam;
        wchar_t droppedPath[MAX_PATH] = {};
        if (DragQueryFileW(hDrop, 0, droppedPath, MAX_PATH)) {
            g_app.SendFileAsync(droppedPath, false);
        }
        DragFinish(hDrop);
        return 0;
    }

    case WM_KILLFOCUS:
        g_app.SendClientReleaseAllKeys();
        return 0;

    case WM_ACTIVATE:
        if (LOWORD(wParam) == WA_INACTIVE) g_app.SendClientReleaseAllKeys();
        return 0;

    case WM_CLOSE:
        g_app.DisconnectClient();
        return 0;

    case WM_MOUSEMOVE:
        g_app.SendClientMouseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), 0, MBTN_MOVE);
        return 0;
    case WM_LBUTTONDOWN:
        SetFocus(hwnd);
        g_app.SendClientMouseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), 0, MBTN_MOVE | MBTN_LEFT_DOWN);
        return 0;
    case WM_LBUTTONUP:
        g_app.SendClientMouseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), 0, MBTN_MOVE | MBTN_LEFT_UP);
        return 0;
    case WM_RBUTTONDOWN:
        SetFocus(hwnd);
        g_app.SendClientMouseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), 0, MBTN_MOVE | MBTN_RIGHT_DOWN);
        return 0;
    case WM_RBUTTONUP:
        g_app.SendClientMouseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), 0, MBTN_MOVE | MBTN_RIGHT_UP);
        return 0;
    case WM_MBUTTONDOWN:
        SetFocus(hwnd);
        g_app.SendClientMouseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), 0, MBTN_MOVE | MBTN_MID_DOWN);
        return 0;
    case WM_MBUTTONUP:
        g_app.SendClientMouseEvent(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), 0, MBTN_MOVE | MBTN_MID_UP);
        return 0;
    case WM_MOUSEWHEEL: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ScreenToClient(hwnd, &pt);
        g_app.SendClientMouseEvent(pt.x, pt.y, GET_WHEEL_DELTA_WPARAM(wParam), MBTN_WHEEL_V);
        return 0;
    }
    case WM_MOUSEHWHEEL: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ScreenToClient(hwnd, &pt);
        g_app.SendClientMouseEvent(pt.x, pt.y, GET_WHEEL_DELTA_WPARAM(wParam), MBTN_WHEEL_H);
        return 0;
    }

    case WM_KEYDOWN:
    case WM_SYSKEYDOWN: {
        if (wParam == 'F' && (GetKeyState(VK_CONTROL) & 0x8000) && (GetKeyState(VK_MENU) & 0x8000)) {
            g_app.ToggleViewerFullscreen();
            return 0;
        }
        g_app.SendClientKeyEvent((uint16_t)((lParam >> 16) & 0xFF), (uint16_t)wParam, true, (lParam & (1 << 24)) != 0);
        return 0;
    }

    case WM_KEYUP:
    case WM_SYSKEYUP:
        g_app.SendClientKeyEvent((uint16_t)((lParam >> 16) & 0xFF), (uint16_t)wParam, false, (lParam & (1 << 24)) != 0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_app.m_hwndMain = hwnd;
        ApplyWindowDarkChrome(hwnd, false);

        g_app.m_hDarkInputBrush = CreateSolidBrush(RGB(19, 24, 36));
        g_app.m_hDarkListBrush  = CreateSolidBrush(RGB(15, 20, 31));

        HINSTANCE hInst = GetModuleHandleW(nullptr);
        auto MakeCtrl = [&](LPCWSTR cls, LPCWSTR txt, DWORD style, int id) {
            return CreateWindowExW(0, cls, txt, WS_CHILD | WS_VISIBLE | style,
                                   0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)id, hInst, nullptr);
        };

        char compName[64] = "Radmin-PC";
        DWORD compLen = sizeof(compName);
        GetComputerNameA(compName, &compLen);
        std::wstring wCompName(compName, compName + strlen(compName));

        g_app.m_editSrvName = MakeCtrl(L"EDIT", wCompName.c_str(), ES_AUTOHSCROLL, IDC_EDIT_SRV_NAME);
        g_app.m_editSrvPass = MakeCtrl(L"EDIT", L"12345", ES_PASSWORD | ES_AUTOHSCROLL, IDC_EDIT_SRV_PASS);
        g_app.m_editSrvPort = MakeCtrl(L"EDIT", L"27000", ES_NUMBER, IDC_EDIT_SRV_PORT);

        g_app.m_listHosts   = MakeCtrl(L"LISTBOX", L"", WS_VSCROLL | LBS_NOTIFY | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS | LBS_NOINTEGRALHEIGHT, IDC_LIST_HOSTS);
        ApplyDarkScrollbarTheme(g_app.m_listHosts);

        g_app.m_editCliIp   = MakeCtrl(L"EDIT", L"", ES_AUTOHSCROLL, IDC_EDIT_CLI_IP);
        g_app.m_editCliPort = MakeCtrl(L"EDIT", L"27000", ES_NUMBER, IDC_EDIT_CLI_PORT);
        g_app.m_editCliPass = MakeCtrl(L"EDIT", L"12345", ES_PASSWORD | ES_AUTOHSCROLL, IDC_EDIT_CLI_PASS);

        g_app.InitCanvasWidgets();
        g_app.UpdateFontsForDpi(GetDpiForWindow(hwnd));
        g_app.RelayoutMainWindow();
        g_app.ShowInTray(false);

        AddClipboardFormatListener(hwnd);
        return 0;
    }

    case WM_GETMINMAXINFO: {
        auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        UINT dpi = GetDpiForWindow(hwnd);
        mmi->ptMinTrackSize.x = MulDiv(820, dpi, 96);
        m_min_h:
        mmi->ptMinTrackSize.y = MulDiv(480, dpi, 96);
        return 0;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(241, 245, 249));
        SetBkColor(hdc, RGB(19, 24, 36));
        return (LRESULT)g_app.m_hDarkInputBrush;
    }

    case WM_CTLCOLORSTATIC: {
        // Read-only EDIT controls send WM_CTLCOLORSTATIC instead of WM_CTLCOLOREDIT
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(148, 163, 184));
        SetBkColor(hdc, RGB(19, 24, 36));
        return (LRESULT)g_app.m_hDarkInputBrush;
    }

    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(226, 232, 240));
        SetBkColor(hdc, RGB(15, 20, 31));
        return (LRESULT)g_app.m_hDarkListBrush;
    }

    case WM_MEASUREITEM: {
        auto* mis = reinterpret_cast<MEASUREITEMSTRUCT*>(lParam);
        if (mis->CtlID == IDC_LIST_HOSTS) {
            mis->itemHeight = MulDiv(28, GetDpiForWindow(hwnd), 96);
            return TRUE;
        }
        break;
    }

    case WM_DRAWITEM: {
        auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
        if (dis->CtlID == IDC_LIST_HOSTS) {
            HDC hdc = dis->hDC;
            RECT r = dis->rcItem;
            bool selected = (dis->itemState & ODS_SELECTED) != 0;

            HBRUSH bgBrush = CreateSolidBrush(selected ? RGB(30, 58, 118) : RGB(15, 20, 31));
            FillRect(hdc, &r, bgBrush);
            DeleteObject(bgBrush);

            if (dis->itemID != (UINT)-1) {
                LRESULT len = SendMessageW(g_app.m_listHosts, LB_GETTEXTLEN, dis->itemID, 0);
                if (len > 0 && len < 512) {
                    std::wstring itemText((size_t)len, L'\0');
                    SendMessageW(g_app.m_listHosts, LB_GETTEXT, dis->itemID, (LPARAM)itemText.data());

                    if (selected) {
                        HBRUSH barBrush = CreateSolidBrush(RGB(59, 130, 246));
                        RECT bar = { r.left + 2, r.top + 4, r.left + 5, r.bottom - 4 };
                        FillRect(hdc, &bar, barBrush);
                        DeleteObject(barBrush);
                    }

                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, selected ? RGB(248, 250, 252) : RGB(203, 213, 225));
                    HGDIOBJ oldFont = SelectObject(hdc, selected ? g_app.m_hListFontBold : g_app.m_hListFont);
                    RECT txtRc = { r.left + 12, r.top, r.right - 8, r.bottom };
                    DrawTextW(hdc, itemText.c_str(), (int)itemText.size(), &txtRc,
                              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                    SelectObject(hdc, oldFont);
                }
            }
            return TRUE;
        }
        break;
    }

    case WM_PAINT:
        g_app.PaintMainWindow(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_MOUSEMOVE: {
        if (!g_app.m_trackingMouse) {
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
            g_app.m_trackingMouse = true;
        }
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        g_app.m_hoveredBtnId = g_app.HitTestMainButton(pt);
        g_app.m_hoveredToggle = (g_app.m_hoveredBtnId == -1) && g_app.HitTestAutoMinToggle(pt);
        return 0;
    }

    case WM_MOUSELEAVE:
        g_app.m_trackingMouse = false;
        g_app.m_hoveredBtnId = -1;
        g_app.m_hoveredToggle = false;
        return 0;

    case WM_LBUTTONDOWN: {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        int hit = g_app.HitTestMainButton(pt);
        if (hit != -1) {
            g_app.m_pressedBtnId = hit;
            SetCapture(hwnd);
            return 0;
        }
        if (g_app.HitTestAutoMinToggle(pt)) {
            g_app.m_pressedToggle = true;
            SetCapture(hwnd);
            return 0;
        }
        SetFocus(hwnd);
        return 0;
    }

    case WM_LBUTTONUP: {
        if (GetCapture() == hwnd) ReleaseCapture();
        int pressedBtn = g_app.m_pressedBtnId;
        bool pressedTgl = g_app.m_pressedToggle;
        g_app.m_pressedBtnId = -1;
        g_app.m_pressedToggle = false;

        if (pressedBtn != -1 && pressedBtn == g_app.m_hoveredBtnId) {
            g_app.OnMainCanvasButtonClick(pressedBtn);
        } else if (pressedTgl && g_app.m_hoveredToggle) {
            g_app.m_autoMinToggle.checked = !g_app.m_autoMinToggle.checked;
            g_app.m_autoMinimize = g_app.m_autoMinToggle.checked;
        }
        return 0;
    }

    case WM_CAPTURECHANGED:
        g_app.m_pressedBtnId = -1;
        g_app.m_pressedToggle = false;
        return 0;

    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) g_app.RelayoutMainWindow();
        return 0;

    case WM_EXITSIZEMOVE:
    case WM_DISPLAYCHANGE:
        g_app.m_framePacer.RefreshTargetHz();
        g_app.m_framePacer.ResetTiming();
        return 0;

    case WM_DPICHANGED: {
        g_app.UpdateFontsForDpi(HIWORD(wParam));
        const RECT* suggested = reinterpret_cast<const RECT*>(lParam);
        SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                     suggested->right - suggested->left, suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        g_app.RelayoutMainWindow();
        g_app.m_framePacer.ResetTiming();
        return 0;
    }

    case WM_APP_TRAY_ICON: {
        if (lParam == WM_LBUTTONDBLCLK) {
            g_app.RestoreFromTray();
        } else if (lParam == WM_RBUTTONUP) {
            POINT pt = {};
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_TRAY_RESTORE, L"Развернуть панель управления");
            if (g_app.m_serverRunning) AppendMenuW(hMenu, MF_STRING, IDM_TRAY_STOP_SRV, L"Остановить сервер");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"Выход");
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(hMenu);
        }
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam), code = HIWORD(wParam);
        if (id == IDM_TRAY_RESTORE) {
            g_app.RestoreFromTray();
        } else if (id == IDM_TRAY_STOP_SRV) {
            g_app.StopServer();
            g_app.RestoreFromTray();
        } else if (id == IDM_TRAY_EXIT) {
            g_app.HandleCloseRequest();
        } else if (id == IDC_LIST_HOSTS && code == LBN_SELCHANGE) {
            int sel = (int)SendMessageW(g_app.m_listHosts, LB_GETCURSEL, 0, 0);
            std::lock_guard<std::mutex> lock(g_app.m_hostsMutex);
            if (sel >= 0 && sel < (int)g_app.m_discoveredHosts.size()) {
                SetWindowTextA(g_app.m_editCliIp, g_app.m_discoveredHosts[sel].ip.c_str());
                SetWindowTextA(g_app.m_editCliPort, std::to_string(g_app.m_discoveredHosts[sel].port).c_str());
            }
        } else if (id == IDC_LIST_HOSTS && code == LBN_DBLCLK) {
            if (!g_app.m_clientRunning) g_app.ConnectToServer();
        }
        return 0;
    }

    case WM_CLIPBOARDUPDATE:
        g_app.BroadcastLocalClipboardChange();
        return 0;

    case WM_APP_UPDATE_UI:
        g_app.RefreshButtonVisualStates();
        return 0;

    case WM_APP_AUTO_MINIMIZE:
        ShowWindow(hwnd, SW_MINIMIZE);
        return 0;

    case WM_APP_CLIENT_LOST:
        g_app.DisconnectClient();
        return 0;

    case WM_APP_HOST_FOUND: {
        SendMessageW(g_app.m_listHosts, LB_RESETCONTENT, 0, 0);
        std::lock_guard<std::mutex> lock(g_app.m_hostsMutex);
        for (const auto& h : g_app.m_discoveredHosts) {
            std::ostringstream oss;
            oss << h.name << "  [" << h.ip << ":" << h.port << "]  (" << h.width << "x" << h.height << ")";
            std::string s = oss.str();
            std::wstring ws(s.begin(), s.end());
            SendMessageW(g_app.m_listHosts, LB_ADDSTRING, 0, (LPARAM)ws.c_str());
        }
        if (!g_app.m_discoveredHosts.empty()) {
            SendMessageW(g_app.m_listHosts, LB_SETCURSEL, 0, 0);
            SetWindowTextA(g_app.m_editCliIp, g_app.m_discoveredHosts[0].ip.c_str());
            SetWindowTextA(g_app.m_editCliPort, std::to_string(g_app.m_discoveredHosts[0].port).c_str());
        }
        return 0;
    }

    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_CLOSE) {
            g_app.HandleCloseRequest();
            return 0;
        }
        break;

    case WM_CLOSE:
        g_app.HandleCloseRequest();
        return 0;

    case WM_DESTROY:
        RemoveClipboardFormatListener(hwnd);
        g_app.RemoveTrayIcon();
        g_app.DisconnectClient();
        g_app.StopServer();
        g_app.m_mainCanvas.Destroy();
        if (g_app.m_hEditFont) DeleteObject(g_app.m_hEditFont);
        if (g_app.m_hListFont) DeleteObject(g_app.m_hListFont);
        if (g_app.m_hListFontBold) DeleteObject(g_app.m_hListFontBold);
        if (g_app.m_hDarkInputBrush) DeleteObject(g_app.m_hDarkInputBrush);
        if (g_app.m_hDarkListBrush)  DeleteObject(g_app.m_hDarkListBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    DisableBackgroundPowerThrottling();

    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    MFStartup(MF_VERSION);

    WNDCLASSEXW wcMain = { sizeof(WNDCLASSEXW) };
    wcMain.style = CS_HREDRAW | CS_VREDRAW;
    wcMain.lpfnWndProc = MainWndProc;
    wcMain.hInstance = hInstance;
    wcMain.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcMain.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcMain.hbrBackground = nullptr;
    wcMain.lpszClassName = L"RadminUltraRD_Main";
    RegisterClassExW(&wcMain);

    WNDCLASSEXW wcModal = { sizeof(WNDCLASSEXW) };
    wcModal.style = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW;
    wcModal.lpfnWndProc = ModalPinWndProc;
    wcModal.hInstance = hInstance;
    wcModal.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcModal.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcModal.hbrBackground = nullptr;
    wcModal.lpszClassName = L"RadminUltraRD_PinModal";
    RegisterClassExW(&wcModal);

    WNDCLASSEXW wcViewer = { sizeof(WNDCLASSEXW) };
    wcViewer.style = CS_HREDRAW | CS_VREDRAW;
    wcViewer.lpfnWndProc = ViewerWndProc;
    wcViewer.hInstance = hInstance;
    wcViewer.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcViewer.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcViewer.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wcViewer.lpszClassName = L"RadminUltraRD_Viewer";
    RegisterClassExW(&wcViewer);

    RECT workArea = {};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    int screenW = workArea.right - workArea.left;
    int screenH = workArea.bottom - workArea.top;

    UINT dpi = GetDpiForSystem();
    int initW = std::min(screenW - 40, MulDiv(980, dpi, 96));
    int initH = std::min(screenH - 40, MulDiv(540, dpi, 96));
    int initX = workArea.left + (screenW - initW) / 2;
    int initY = workArea.top + (screenH - initH) / 2;

    g_app.m_hwndViewer = CreateWindowExW(
        WS_EX_ACCEPTFILES, L"RadminUltraRD_Viewer", L"Radmin Ultra-Low Latency Viewer",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720,
        nullptr, nullptr, hInstance, nullptr);
    DragAcceptFiles(g_app.m_hwndViewer, TRUE);

    HWND hwndMain = CreateWindowExW(
        0, L"RadminUltraRD_Main",
        L"Radmin Ultra RD — Remote Desktop & File Transfer",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        initX, initY, initW, initH,
        nullptr, nullptr, hInstance, nullptr);

    g_app.m_hKeyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);
    g_app.m_framePacer.Initialize();

    ShowWindow(hwndMain, nCmdShow);
    UpdateWindow(hwndMain);

    HWND tabOrder[] = {
        g_app.m_editSrvName, g_app.m_editSrvPass, g_app.m_editSrvPort,
        g_app.m_listHosts, g_app.m_editCliIp, g_app.m_editCliPort, g_app.m_editCliPass
    };

    MSG msg = {};
    bool running = true;
    while (running) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                running = false;
                break;
            }
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_TAB) {
                HWND cur = GetFocus();
                for (int i = 0; i < (int)_countof(tabOrder); ++i) {
                    if (cur == tabOrder[i]) {
                        int step = (GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
                        int next = (i + step + (int)_countof(tabOrder)) % (int)_countof(tabOrder);
                        SetFocus(tabOrder[next]);
                        cur = nullptr;
                        break;
                    }
                }
                if (cur == nullptr) continue;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if (!running) break;

        bool visibleAndActive = (IsWindow(hwndMain) && IsWindowVisible(hwndMain) && !IsIconic(hwndMain));
        float dt = 0.0f;
        if (g_app.m_framePacer.WaitOrCheckFrameReady(visibleAndActive, dt)) {
            g_app.TickAndRenderUi(dt);
        }
    }

    if (g_app.m_hKeyboardHook) UnhookWindowsHookEx(g_app.m_hKeyboardHook);
    timeEndPeriod(1);
    MFShutdown();
    CoUninitialize();
    WSACleanup();
    return (int)msg.wParam;
}
