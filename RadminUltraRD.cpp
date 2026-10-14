// ============================================================================
// RadminUltraRD.cpp — Ultra-Low Latency Remote Desktop (Host + Client)
// Компиляция (x64 Native Tools Command Prompt for VS):
// cl.exe /O2 /Oi /EHsc /std:c++20 /DUNICODE /D_UNICODE RadminUltraRD.cpp /link /SUBSYSTEM:WINDOWS /OUT:RadminUltraRD.exe
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
#include <shellapi.h>
#include <mmsystem.h>
#include <commctrl.h>
#include <bcrypt.h>

#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <d3dcompiler.h>
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
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <map>
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
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "mf.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

using Microsoft::WRL::ComPtr;

// ============================================================================
// КОНСТАНТЫ И ПРОТОКОЛЫ СЕТИ
// ============================================================================
static constexpr uint16_t  DISCOVERY_UDP_PORT  = 26999;
static constexpr uint16_t  DEFAULT_STREAM_PORT = 27000;
static constexpr uint32_t  MAGIC_DISCOVERY     = 0x52444D4E; // 'RDMN'
static constexpr uint32_t  MAGIC_VIDEO         = 0x56494430; // 'VID0'
static constexpr uint32_t  MAGIC_CONTROL       = 0x4354524C; // 'CTRL'
static constexpr ULONG_PTR INJECTED_SIGNATURE  = 0x52444D4E;
static constexpr size_t    MAX_UDP_PAYLOAD     = 1340;       // Безопасно для MTU Radmin VPN
static constexpr size_t    MAX_CLIPBOARD_BYTES = 16 * 1024 * 1024;

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
    CTRL_RELEASE_ALL_KEYS = 10
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
    uint8_t  flags;        // 0x01 = IDR Keyframe
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
#pragma pack(pop)

// ============================================================================
// ТАЙМЕРЫ, ОТКЛЮЧЕНИЕ POWER THROTTLING, КРИПТОГРАФИЯ И СЕТЬ
// ============================================================================
static inline uint64_t NowMicros() {
    static LARGE_INTEGER freq = {};
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return static_cast<uint64_t>((counter.QuadPart * 1000000ULL) / freq.QuadPart);
}

static inline void MicroSpinWait(uint64_t delayUs) {
    uint64_t start = NowMicros();
    while (NowMicros() - start < delayUs) {
        YieldProcessor();
    }
}

// Гарантирует, что при сворачивании окна сервера Windows не снизит частоту кадров
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
                    BCryptFinishHash(hHash, outHash, 32, 0) == 0) {
                    ok = true;
                }
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        return ok;
    }

    static bool ComputeHMACSHA256(const uint8_t* key, size_t keyLen,
                                  const void* data, size_t dataLen,
                                  uint8_t outMac[32]) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0) {
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, (PUCHAR)key, (ULONG)keyLen, 0) == 0) {
                if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0) == 0 &&
                    BCryptFinishHash(hHash, outMac, 32, 0) == 0) {
                    ok = true;
                }
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
        return ok;
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
            for (size_t i = 0; i < chunk; ++i) {
                data[offset + i] ^= keystream[i];
            }
            offset += chunk;
        }
    }
};

static std::string DetectRadminVpnIP(std::vector<std::string>* outBroadcastAddrs = nullptr) {
    std::string radminIp;
    std::string fallbackLanIp = "127.0.0.1";

    if (outBroadcastAddrs) {
        outBroadcastAddrs->clear();
        outBroadcastAddrs->push_back("26.255.255.255");
        outBroadcastAddrs->push_back("255.255.255.255");
        outBroadcastAddrs->push_back("127.0.0.1");
    }

    ULONG bufLen = 16384;
    std::vector<uint8_t> buffer(bufLen);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    DWORD res = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     nullptr, addresses, &bufLen);
    if (res == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufLen);
        addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        res = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                   nullptr, addresses, &bufLen);
    }

    if (res == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES curr = addresses; curr != nullptr; curr = curr->Next) {
            if (curr->OperStatus != IfOperStatusUp || curr->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                continue;

            for (PIP_ADAPTER_UNICAST_ADDRESS ua = curr->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                if (!sin || sin->sin_family != AF_INET) continue;

                char ipStr[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr));
                uint32_t hostIp = ntohl(sin->sin_addr.s_addr);

                if ((hostIp >> 24) == 26) {
                    radminIp = ipStr;
                } else if (fallbackLanIp == "127.0.0.1") {
                    fallbackLanIp = ipStr;
                }

                if (outBroadcastAddrs && ua->OnLinkPrefixLength > 0 && ua->OnLinkPrefixLength < 32) {
                    uint32_t mask = (0xFFFFFFFFu << (32 - ua->OnLinkPrefixLength));
                    uint32_t bcast = (hostIp & mask) | (~mask);
                    in_addr bcastAddr;
                    bcastAddr.s_addr = htonl(bcast);
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
// ЗАХВАТ ЭКРАНА DXGI DESKTOP DUPLICATION + D3D11 GPU VIDEO PROCESSOR
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
            if (SUCCEEDED(targetAdapter->EnumOutputs(0, &targetOutput))) {
                break;
            }
            targetAdapter.Reset();
        }
        if (!targetAdapter || !targetOutput) return false;

        D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0 };
        D3D_FEATURE_LEVEL achievedLevel;

        UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
        HRESULT hr = D3D11CreateDevice(targetAdapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags,
                                       featureLevels, _countof(featureLevels), D3D11_SDK_VERSION,
                                       &m_device, &achievedLevel, &m_context);
        if (FAILED(hr)) {
            flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
            hr = D3D11CreateDevice(targetAdapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags,
                                   featureLevels, _countof(featureLevels), D3D11_SDK_VERSION,
                                   &m_device, &achievedLevel, &m_context);
            if (FAILED(hr)) return false;
        }

        ComPtr<ID3D10Multithread> mt;
        if (SUCCEEDED(m_device.As(&mt))) {
            mt->SetMultithreadProtected(TRUE);
        }

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
        if (!m_device) {
            if (!Initialize(m_maxEncodeW, m_maxEncodeH)) return false;
        }
        if (!m_dupl) {
            if (!InitDuplication()) return false;
            m_vpReady = InitVideoProcessor();
        }

        DXGI_OUTDUPL_FRAME_INFO frameInfo = {};
        ComPtr<IDXGIResource> desktopRes;
        UINT timeoutMs = (!m_hasCachedFrame) ? 80 : 6;
        HRESULT hr = m_dupl->AcquireNextFrame(timeoutMs, &frameInfo, &desktopRes);

        if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
            if (!m_hasCachedFrame) {
                SeedInitialDesktopTexture();
            } else if (!forceEvenOnTimeout) {
                return false;
            }
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

        if (m_vpReady && ConvertViaGpuVideoProcessor(outNv12)) {
            return true;
        }
        return ConvertViaStagingFallback(outNv12);
    }

    RECT GetDesktopRect() const { return m_desktopRect; }

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
        inViewDesc.Texture2D.MipSlice = 0;

        ComPtr<ID3D11VideoProcessorInputView> inView;
        if (FAILED(m_videoDevice->CreateVideoProcessorInputView(m_cachedDesktopTex.Get(), m_videoEnum.Get(), &inViewDesc, &inView)))
            return false;

        D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC outViewDesc = {};
        outViewDesc.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
        outViewDesc.Texture2D.MipSlice = 0;

        ComPtr<ID3D11VideoProcessorOutputView> outView;
        if (FAILED(m_videoDevice->CreateVideoProcessorOutputView(m_nv12GpuTex.Get(), m_videoEnum.Get(), &outViewDesc, &outView)))
            return false;

        // Явно задаем исходный и целевой прямоугольники для чистого аппаратного даунскейлинга
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
            for (uint32_t y = 0; y < m_encodeHeight; ++y) {
                memcpy(dstY + (size_t)y * m_encodeWidth, srcY + (size_t)y * mapped.RowPitch, m_encodeWidth);
            }
            for (uint32_t y = 0; y < m_encodeHeight / 2; ++y) {
                memcpy(dstUV + (size_t)y * m_encodeWidth, srcUV + (size_t)y * mapped.RowPitch, m_encodeWidth);
            }
        }

        m_context->Unmap(m_nv12StagingTex.Get(), 0);
        return true;
    }

    // Билинейный fallback с усреднением 2x2 при даунскейле высокого разрешения
    bool ConvertViaStagingFallback(std::vector<uint8_t>& outNv12) {
        if (!m_bgraStagingTex) return false;
        m_context->CopyResource(m_bgraStagingTex.Get(), m_cachedDesktopTex.Get());

        D3D11_MAPPED_SUBRESOURCE mapped = {};
        if (FAILED(m_context->Map(m_bgraStagingTex.Get(), 0, D3D11_MAP_READ, 0, &mapped)))
            return false;

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

                int yVal = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
                yOut[x] = (uint8_t)std::clamp(yVal, 0, 255);

                if ((y & 1) == 0 && (x & 1) == 0) {
                    int uVal = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                    int vVal = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                    uvOut[x]     = (uint8_t)std::clamp(uVal, 0, 255);
                    uvOut[x + 1] = (uint8_t)std::clamp(vVal, 0, 255);
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

        uint32_t targetW = m_desktopWidth;
        uint32_t targetH = m_desktopHeight;
        if (targetW > m_maxEncodeW || targetH > m_maxEncodeH) {
            double scaleW = (double)m_maxEncodeW / targetW;
            double scaleH = (double)m_maxEncodeH / targetH;
            double scale = std::min(scaleW, scaleH);
            targetW = (uint32_t)std::round(targetW * scale);
            targetH = (uint32_t)std::round(targetH * scale);
        }
        // Выравнивание по макроблокам H.264 (16x16) исключает искажение строк
        m_encodeWidth = std::max<uint32_t>(64, (targetW + 7) & ~15u);
        m_encodeHeight = std::max<uint32_t>(64, (targetH + 7) & ~15u);
        if (m_encodeWidth > m_maxEncodeW) m_encodeWidth = m_maxEncodeW & ~15u;
        if (m_encodeHeight > m_maxEncodeH) m_encodeHeight = m_maxEncodeH & ~15u;

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
            if (FAILED(m_device->CreateTexture2D(&desc, nullptr, &m_cachedDesktopTex)))
                return false;
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

        if (FAILED(m_device.As(&m_videoDevice))) return false;
        if (FAILED(m_context.As(&m_videoContext))) return false;

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
        if (FAILED(m_device->CreateTexture2D(&nv12Desc, nullptr, &m_nv12StagingTex))) return false;

        return true;
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
    uint32_t m_desktopWidth = 1920;
    uint32_t m_desktopHeight = 1080;
    uint32_t m_encodeWidth = 1920;
    uint32_t m_encodeHeight = 1080;
    uint32_t m_maxEncodeW = 1920;
    uint32_t m_maxEncodeH = 1080;
    bool     m_hasCachedFrame = false;
    bool     m_vpReady = false;
};

// ============================================================================
// КОДИРОВЩИК H.264 MEDIA FOUNDATION (ZERO-LATENCY + SPS/PPS INJECTION)
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

        HRESULT hr = CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_PPV_ARGS(&m_encoder));
        if (FAILED(hr)) return false;

        if (SUCCEEDED(m_encoder.As(&m_codecApi))) {
            VARIANT var = {};
            var.vt = VT_BOOL;
            var.boolVal = VARIANT_TRUE;
            m_codecApi->SetValue(&CODECAPI_AVLowLatencyMode, &var);

            VariantInit(&var);
            var.vt = VT_UI4;
            var.ulVal = 0; // Строго без B-кадров
            m_codecApi->SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &var);

            var.ulVal = eAVEncCommonRateControlMode_CBR;
            m_codecApi->SetValue(&CODECAPI_AVEncCommonRateControlMode, &var);

            var.ulVal = 10000000; // 10 Мбит/с — оптимальный баланс четкости и размера IDR для UDP
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
                DWORD allocSize = streamInfo.cbSize ? streamInfo.cbSize : (m_width * m_height);
                MFCreateMemoryBuffer(allocSize, &outBuf);
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
                if (SUCCEEDED(resultSample->GetUINT32(MFSampleExtension_CleanPoint, &cleanPoint)) && cleanPoint) {
                    outIsKeyFrame = true;
                }

                ComPtr<IMFMediaBuffer> contiguousBuf;
                if (SUCCEEDED(resultSample->ConvertToContiguousBuffer(&contiguousBuf))) {
                    BYTE* pData = nullptr;
                    DWORD cbLen = 0;
                    if (SUCCEEDED(contiguousBuf->Lock(&pData, nullptr, &cbLen))) {
                        if (ContainsIdrOrSpsNal(pData, cbLen)) {
                            outIsKeyFrame = true;
                        }
                        if (outIsKeyFrame && !m_spsPpsHeader.empty() && outBitStream.empty()) {
                            outBitStream.insert(outBitStream.end(), m_spsPpsHeader.begin(), m_spsPpsHeader.end());
                        }
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
    uint32_t             m_width = 0;
    uint32_t             m_height = 0;
    uint32_t             m_fps = 60;
    int64_t              m_pts = 0;
};

// ============================================================================
// ДЕКОДЕР H.264 MEDIA FOUNDATION (ТОЧНОЕ ИЗВЛЕЧЕНИЕ ПЛОСКОСТЕЙ NV12)
// ============================================================================
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

        HRESULT hr = CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_PPV_ARGS(&m_decoder));
        if (FAILED(hr)) return false;

        ComPtr<IMFAttributes> attr;
        if (SUCCEEDED(m_decoder->GetAttributes(&attr))) {
            attr->SetUINT32(CODECAPI_AVLowLatencyMode, TRUE);
        }
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

        HRESULT hr = m_decoder->ProcessInput(0, inSample.Get(), 0);
        if (FAILED(hr)) return false;

        bool gotFrame = false;
        while (true) {
            MFT_OUTPUT_STREAM_INFO streamInfo = {};
            m_decoder->GetOutputStreamInfo(0, &streamInfo);

            ComPtr<IMFSample> outSample;
            ComPtr<IMFMediaBuffer> outBuf;
            if (!(streamInfo.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES)) {
                DWORD allocSize = streamInfo.cbSize ? streamInfo.cbSize : (m_alignedWidth * m_alignedHeight * 2);
                MFCreateMemoryBuffer(allocSize, &outBuf);
                MFCreateSample(&outSample);
                outSample->AddBuffer(outBuf.Get());
            }

            MFT_OUTPUT_DATA_BUFFER outData = {};
            outData.pSample = outSample.Get();
            DWORD status = 0;
            hr = m_decoder->ProcessOutput(0, 1, &outData, &status);
            if (outData.pEvents) outData.pEvents->Release();

            if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
                NegotiateOutputType();
                continue;
            }
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT || FAILED(hr)) {
                break;
            }

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
            HRESULT hr = m_decoder->GetOutputAvailableType(0, i, &availType);
            if (FAILED(hr)) break;

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
                    if (SUCCEEDED(availType->GetUINT32(MF_MT_DEFAULT_STRIDE, &stride)) && stride > 0) {
                        m_stride = (uint32_t)std::abs((int32_t)stride);
                    } else {
                        m_stride = m_alignedWidth;
                    }
                    return true;
                }
            }
        }
        return false;
    }

    ComPtr<IMFTransform> m_decoder;
    uint32_t m_displayWidth = 1920;
    uint32_t m_displayHeight = 1080;
    uint32_t m_alignedWidth = 1920;
    uint32_t m_alignedHeight = 1088;
    uint32_t m_stride = 1920;
    int64_t  m_pts = 0;
};

// ============================================================================
// КЛИЕНТСКИЙ DIRECT3D 11 РЕНДЕРЕР С SUPERSAMPLED ШЕЙДЕРОМ (ДЛЯ HIGH->LOW RES)
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
    float r = y + 1.792741f * v;
    float g = y - 0.213248f * u - 0.532909f * v;
    float b = y + 2.112401f * u;
    return saturate(float3(r, g, b));
}

float4 PSMain(VSOut i) : SV_TARGET {
    // 5-точечный субпиксельный антиалиасинг при выводе высокого разрешения на малый экран
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

        HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                       levels, _countof(levels), D3D11_SDK_VERSION,
                                       &m_device, &achieved, &m_context);
        if (FAILED(hr)) return false;

        ComPtr<ID3D10Multithread> mt;
        if (SUCCEEDED(m_device.As(&mt))) {
            mt->SetMultithreadProtected(TRUE);
        }

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

        if (!CreateBackBufferRTV()) return false;
        if (!CompileShaders()) return false;

        return true;
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
        size_t neededSize = uvOffset + (size_t)frame.stride * (frame.displayHeight / 2);
        if (frame.data.size() < neededSize) return;

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

        float nx = ((float)clientX - vp.TopLeftX) / vp.Width;
        float ny = ((float)clientY - vp.TopLeftY) / vp.Height;

        outNormX = std::clamp(nx, 0.0f, 1.0f);
        outNormY = std::clamp(ny, 0.0f, 1.0f);
        return true;
    }

private:
    void ShutdownInternal() {
        m_srvY.Reset();
        m_srvUV.Reset();
        m_texY.Reset();
        m_texUV.Reset();
        m_sampler.Reset();
        m_vs.Reset();
        m_ps.Reset();
        m_rtv.Reset();
        m_swapChain.Reset();
        m_context.Reset();
        m_device.Reset();
        m_streamWidth = 0;
        m_streamHeight = 0;
    }

    D3D11_VIEWPORT CalculateLetterboxViewport() const {
        D3D11_VIEWPORT vp = {};
        vp.MinDepth = 0.0f;
        vp.MaxDepth = 1.0f;

        uint32_t sw = m_streamWidth ? m_streamWidth : 1920;
        uint32_t sh = m_streamHeight ? m_streamHeight : 1080;

        float winAspect = (float)m_winWidth / (float)std::max<uint32_t>(1, m_winHeight);
        float streamAspect = (float)sw / (float)std::max<uint32_t>(1, sh);

        if (winAspect > streamAspect) {
            vp.Height = (float)m_winHeight;
            vp.Width = vp.Height * streamAspect;
            vp.TopLeftX = ((float)m_winWidth - vp.Width) * 0.5f;
            vp.TopLeftY = 0.0f;
        } else {
            vp.Width = (float)m_winWidth;
            vp.Height = vp.Width / streamAspect;
            vp.TopLeftX = 0.0f;
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
                              "VSMain", "vs_5_0", D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &vsBlob, &errBlob)))
            return false;

        if (FAILED(D3DCompile(g_hlslShaderSource, strlen(g_hlslShaderSource), nullptr, nullptr, nullptr,
                              "PSMain", "ps_5_0", D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &psBlob, &errBlob)))
            return false;

        if (FAILED(m_device->CreateVertexShader(vsBlob->GetBufferPointer(), vsBlob->GetBufferSize(), nullptr, &m_vs)))
            return false;
        if (FAILED(m_device->CreatePixelShader(psBlob->GetBufferPointer(), psBlob->GetBufferSize(), nullptr, &m_ps)))
            return false;

        D3D11_SAMPLER_DESC sampDesc = {};
        sampDesc.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
        sampDesc.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
        sampDesc.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
        sampDesc.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
        sampDesc.MaxLOD = D3D11_FLOAT32_MAX;

        return SUCCEEDED(m_device->CreateSamplerState(&sampDesc, &m_sampler));
    }

    bool CreateStreamTextures(uint32_t width, uint32_t height) {
        m_srvY.Reset();
        m_srvUV.Reset();
        m_texY.Reset();
        m_texUV.Reset();

        D3D11_TEXTURE2D_DESC descY = {};
        descY.Width = width;
        descY.Height = height;
        descY.MipLevels = 1;
        descY.ArraySize = 1;
        descY.Format = DXGI_FORMAT_R8_UNORM;
        descY.SampleDesc.Count = 1;
        descY.Usage = D3D11_USAGE_DEFAULT;
        descY.BindFlags = D3D11_BIND_SHADER_RESOURCE;

        if (FAILED(m_device->CreateTexture2D(&descY, nullptr, &m_texY))) return false;
        if (FAILED(m_device->CreateShaderResourceView(m_texY.Get(), nullptr, &m_srvY))) return false;

        D3D11_TEXTURE2D_DESC descUV = descY;
        descUV.Width = width / 2;
        descUV.Height = height / 2;
        descUV.Format = DXGI_FORMAT_R8G8_UNORM;

        if (FAILED(m_device->CreateTexture2D(&descUV, nullptr, &m_texUV))) return false;
        if (FAILED(m_device->CreateShaderResourceView(m_texUV.Get(), nullptr, &m_srvUV))) return false;

        m_streamWidth = width;
        m_streamHeight = height;
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
    ComPtr<ID3D11Texture2D>             m_texY;
    ComPtr<ID3D11Texture2D>             m_texUV;
    ComPtr<ID3D11ShaderResourceView>    m_srvY;
    ComPtr<ID3D11ShaderResourceView>    m_srvUV;

    uint32_t m_winWidth = 1280;
    uint32_t m_winHeight = 720;
    uint32_t m_streamWidth = 0;
    uint32_t m_streamHeight = 0;
};

// ============================================================================
// ИНЪЕКЦИЯ ВВОДА (С ЗАЩИТОЙ ОТ ЗАЛИПАНИЯ КЛАВИШИ WIN) И БУФЕР ОБМЕНА
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

        if (ev.flags & MBTN_WHEEL_V) {
            inp.mi.dwFlags |= MOUSEEVENTF_WHEEL;
            inp.mi.mouseData = (DWORD)ev.wheelDelta;
        }
        if (ev.flags & MBTN_WHEEL_H) {
            inp.mi.dwFlags |= MOUSEEVENTF_HWHEEL;
            inp.mi.mouseData = (DWORD)ev.wheelDelta;
        }

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

        // Для клавиш Windows (VK_LWIN / VK_RWIN) обязательно используем виртуальный код + EXTENDEDKEY
        if (ev.vKey == VK_LWIN || ev.vKey == VK_RWIN) {
            inp.ki.dwFlags = KEYEVENTF_EXTENDEDKEY | (ev.isDown ? 0 : KEYEVENTF_KEYUP);
        } else {
            if (ev.scanCode != 0) {
                inp.ki.dwFlags = KEYEVENTF_SCANCODE;
            }
            if (ev.isExtended) {
                inp.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
            }
            if (!ev.isDown) {
                inp.ki.dwFlags |= KEYEVENTF_KEYUP;
            }
        }

        SendInput(1, &inp, sizeof(INPUT));
    }

    // Принудительный сброс всех зажатых клавиш и модификаторов (Win, Alt, Ctrl, Shift)
    void ReleaseAllHeldKeys() {
        std::lock_guard<std::mutex> lock(m_keyStateMutex);
        std::vector<INPUT> inputs;

        auto AddVkRelease = [&](WORD vk, WORD scan, bool ext) {
            INPUT inp = {};
            inp.type = INPUT_KEYBOARD;
            inp.ki.wVk = vk;
            inp.ki.wScan = scan;
            inp.ki.dwExtraInfo = INJECTED_SIGNATURE;
            if (vk == VK_LWIN || vk == VK_RWIN || scan == 0) {
                inp.ki.dwFlags = KEYEVENTF_KEYUP | (ext ? KEYEVENTF_EXTENDEDKEY : 0);
            } else {
                inp.ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP | (ext ? KEYEVENTF_EXTENDEDKEY : 0);
            }
            inputs.push_back(inp);
        };

        for (int vk = 1; vk < 256; ++vk) {
            if (m_heldVKeys[vk]) {
                AddVkRelease((WORD)vk, m_heldScans[vk], m_heldExt[vk]);
                m_heldVKeys[vk] = false;
            }
        }

        // Гарантированно отпускаем системные клавиши Windows и модификаторы
        AddVkRelease(VK_LWIN, 0x5B, true);
        AddVkRelease(VK_RWIN, 0x5C, true);
        AddVkRelease(VK_LSHIFT, (WORD)MapVirtualKeyW(VK_LSHIFT, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_RSHIFT, (WORD)MapVirtualKeyW(VK_RSHIFT, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_LCONTROL, (WORD)MapVirtualKeyW(VK_LCONTROL, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_RCONTROL, (WORD)MapVirtualKeyW(VK_RCONTROL, MAPVK_VK_TO_VSC), true);
        AddVkRelease(VK_LMENU, (WORD)MapVirtualKeyW(VK_LMENU, MAPVK_VK_TO_VSC), false);
        AddVkRelease(VK_RMENU, (WORD)MapVirtualKeyW(VK_RMENU, MAPVK_VK_TO_VSC), true);

        if (!inputs.empty()) {
            SendInput((UINT)inputs.size(), inputs.data(), sizeof(INPUT));
        }
    }

    bool CaptureClipboardIfChanged(HWND hwndOwner, uint8_t& outFormat, std::vector<uint8_t>& outData, uint8_t outHash[32]) {
        if (m_ignoreNextEvent.exchange(false)) return false;

        bool opened = false;
        for (int i = 0; i < 5; ++i) {
            if (OpenClipboard(hwndOwner)) { opened = true; break; }
            Sleep(5);
        }
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
        for (int i = 0; i < 5; ++i) {
            if (OpenClipboard(hwndOwner)) { opened = true; break; }
            Sleep(5);
        }
        if (!opened) return;

        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, data.size());
        if (hMem) {
            void* dst = GlobalLock(hMem);
            if (dst) {
                memcpy(dst, data.data(), data.size());
                GlobalUnlock(hMem);
                UINT winFmt = (format == CLIP_FORMAT_IMAGE_DIB) ? CF_DIB : CF_UNICODETEXT;
                if (!SetClipboardData(winFmt, hMem)) GlobalFree(hMem);
            } else {
                GlobalFree(hMem);
            }
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
// ГЛОБАЛЬНОЕ СОСТОЯНИЕ, АДАПТИВНЫЙ ИНТЕРФЕЙС И СИСТЕМНЫЙ ТРЕЙ
// ============================================================================
enum GuiControlIds : int {
    IDC_GRP_SERVER      = 100,
    IDC_LBL_SRV_NAME    = 101,
    IDC_EDIT_SRV_NAME   = 102,
    IDC_LBL_SRV_PASS    = 103,
    IDC_EDIT_SRV_PASS   = 104,
    IDC_LBL_SRV_PORT    = 105,
    IDC_EDIT_SRV_PORT   = 106,
    IDC_CHK_AUTO_MIN    = 107,
    IDC_BTN_SRV_TOGGLE  = 108,
    IDC_BTN_SRV_TRAY    = 109,
    IDC_LBL_SRV_STATUS  = 110,

    IDC_GRP_CLIENT      = 200,
    IDC_BTN_CLI_SCAN    = 201,
    IDC_LIST_HOSTS      = 202,
    IDC_LBL_CLI_IP      = 203,
    IDC_EDIT_CLI_IP     = 204,
    IDC_EDIT_CLI_PORT   = 205,
    IDC_LBL_CLI_PASS    = 206,
    IDC_EDIT_CLI_PASS   = 207,
    IDC_BTN_CLI_CONNECT = 208,
    IDC_LBL_CLI_STATUS  = 209,

    IDM_TRAY_RESTORE    = 301,
    IDM_TRAY_STOP_SRV   = 302,
    IDM_TRAY_EXIT       = 303
};

static constexpr UINT WM_APP_UPDATE_UI   = WM_APP + 10;
static constexpr UINT WM_APP_HOST_FOUND  = WM_APP + 11;
static constexpr UINT WM_APP_CLIENT_LOST = WM_APP + 12;
static constexpr UINT WM_APP_TRAY_ICON   = WM_APP + 13;

struct DiscoveredHostInfo {
    std::string name;
    std::string ip;
    uint16_t    port;
    uint32_t    width;
    uint32_t    height;
};

class RemoteDesktopApp {
public:
    HWND  m_hwndMain = nullptr;
    HWND  m_hwndViewer = nullptr;
    HFONT m_hFont = nullptr;
    HFONT m_hFontBold = nullptr;
    HHOOK m_hKeyboardHook = nullptr;
    bool  m_trayAdded = false;

    // Контролы Сервера
    HWND m_grpServer     = nullptr;
    HWND m_lblSrvName    = nullptr;
    HWND m_editSrvName   = nullptr;
    HWND m_lblSrvPass    = nullptr;
    HWND m_editSrvPass   = nullptr;
    HWND m_lblSrvPort    = nullptr;
    HWND m_editSrvPort   = nullptr;
    HWND m_chkAutoMin    = nullptr;
    HWND m_btnSrvToggle  = nullptr;
    HWND m_btnSrvTray    = nullptr;
    HWND m_lblSrvStatus  = nullptr;

    // Контролы Клиента
    HWND m_grpClient     = nullptr;
    HWND m_btnCliScan    = nullptr;
    HWND m_listHosts     = nullptr;
    HWND m_lblCliIp      = nullptr;
    HWND m_editCliIp     = nullptr;
    HWND m_editCliPort   = nullptr;
    HWND m_lblCliPass    = nullptr;
    HWND m_editCliPass   = nullptr;
    HWND m_btnCliConnect = nullptr;
    HWND m_lblCliStatus  = nullptr;

    // Сервер
    std::atomic<bool>     m_serverRunning{ false };
    std::atomic<bool>     m_clientAuthorized{ false };
    std::atomic<bool>     m_forceIdrNextFrame{ true };
    std::atomic<uint32_t> m_srvFps{ 0 };
    std::atomic<uint32_t> m_srvEncodeUs{ 0 };
    std::atomic<uint32_t> m_srvClientDecodeUs{ 0 };
    std::atomic<uint32_t> m_srvRttUs{ 0 };
    std::string           m_radminIp;
    std::string           m_connectedClientIp;
    uint16_t              m_serverPort = DEFAULT_STREAM_PORT;

    SOCKET                m_srvListenTcp = INVALID_SOCKET;
    SOCKET                m_srvClientTcp = INVALID_SOCKET;
    SOCKET                m_srvVideoUdp  = INVALID_SOCKET;
    SOCKET                m_srvDiscUdp   = INVALID_SOCKET;
    std::mutex            m_srvTcpSendMutex;
    std::mutex            m_srvClientUdpMutex;
    sockaddr_in           m_srvClientUdpAddr = {};
    bool                  m_hasClientUdpAddr = false;
    uint64_t              m_activeUdpToken = 0;
    uint8_t               m_srvSessionKey[32] = {};

    std::thread           m_srvAcceptThread;
    std::thread           m_srvDiscoveryThread;
    std::thread           m_srvCaptureThread;

    // Клиент
    std::atomic<bool>     m_clientRunning{ false };
    std::atomic<uint32_t> m_cliFps{ 0 };
    std::atomic<uint32_t> m_cliEncodeUs{ 0 };
    std::atomic<uint32_t> m_cliDecodeUs{ 0 };
    std::atomic<uint32_t> m_cliRttUs{ 0 };
    SOCKET                m_cliTcpSock = INVALID_SOCKET;
    SOCKET                m_cliUdpSock = INVALID_SOCKET;
    std::mutex            m_cliTcpSendMutex;
    uint8_t               m_cliSessionKey[32] = {};
    uint64_t              m_cliUdpToken = 0;
    uint64_t              m_lastIdrReqUs = 0;

    std::thread           m_cliTcpThread;
    std::thread           m_cliUdpThread;
    D3D11ClientRenderer   m_renderer;
    InputAndClipboardManager m_inputAndClip;

    std::mutex                      m_hostsMutex;
    std::vector<DiscoveredHostInfo> m_discoveredHosts;

    bool m_isViewerFullscreen = false;
    WINDOWPLACEMENT m_viewerPrevPlacement = { sizeof(WINDOWPLACEMENT) };

    // ========================================================================
    // СИСТЕМНЫЙ ТРЕЙ И СВОРАЧИВАНИЕ ПАНЕЛИ БЕЗ ОСТАНОВКИ ДОСТУПА
    // ========================================================================
    void ShowInTray(bool hideWindow) {
        if (!m_trayAdded) {
            NOTIFYICONDATAW nid = { sizeof(NOTIFYICONDATAW) };
            nid.hWnd = m_hwndMain;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_APP_TRAY_ICON;
            nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
            wcscpy_s(nid.szTip, L"Radmin Ultra RD (Фоновый режим активен)");
            Shell_NotifyIconW(NIM_ADD, &nid);
            m_trayAdded = true;
        }
        if (hideWindow) {
            ShowWindow(m_hwndMain, SW_HIDE);
        }
    }

    void RestoreFromTray() {
        ShowWindow(m_hwndMain, SW_RESTORE);
        ShowWindow(m_hwndMain, SW_SHOW);
        SetForegroundWindow(m_hwndMain);
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
    void StartServer() {
        if (m_serverRunning) return;

        char nameBuf[64] = {}, passBuf[128] = {}, portBuf[16] = {};
        GetWindowTextA(m_editSrvName, nameBuf, sizeof(nameBuf));
        GetWindowTextA(m_editSrvPass, passBuf, sizeof(passBuf));
        GetWindowTextA(m_editSrvPort, portBuf, sizeof(portBuf));

        m_serverPort = (uint16_t)std::atoi(portBuf);
        if (m_serverPort == 0) m_serverPort = DEFAULT_STREAM_PORT;
        m_radminIp = DetectRadminVpnIP();

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
            MessageBoxW(m_hwndMain, L"Не удалось занять порт сервера! Проверьте, не запущен ли другой экземпляр.", L"Ошибка", MB_ICONERROR);
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
        SetWindowTextW(m_btnSrvToggle, L"Остановить сервер");

        std::string serverName = nameBuf[0] ? nameBuf : "Radmin-Host";
        std::string serverPass = passBuf;

        m_srvDiscoveryThread = std::thread(&RemoteDesktopApp::ServerDiscoveryLoop, this, serverName);
        m_srvAcceptThread    = std::thread(&RemoteDesktopApp::ServerAcceptAndControlLoop, this, serverPass);
        m_srvCaptureThread   = std::thread(&RemoteDesktopApp::ServerCaptureAndEncodeLoop, this);

        UpdateStatusLabels();

        if (SendMessageW(m_chkAutoMin, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            ShowWindow(m_hwndMain, SW_MINIMIZE);
        }
    }

    void StopServer() {
        if (!m_serverRunning.exchange(false)) return;
        m_clientAuthorized = false;

        if (m_srvListenTcp != INVALID_SOCKET) { closesocket(m_srvListenTcp); m_srvListenTcp = INVALID_SOCKET; }
        if (m_srvClientTcp != INVALID_SOCKET) { closesocket(m_srvClientTcp); m_srvClientTcp = INVALID_SOCKET; }
        if (m_srvVideoUdp  != INVALID_SOCKET) { closesocket(m_srvVideoUdp);  m_srvVideoUdp  = INVALID_SOCKET; }
        if (m_srvDiscUdp   != INVALID_SOCKET) { closesocket(m_srvDiscUdp);   m_srvDiscUdp   = INVALID_SOCKET; }

        if (m_srvDiscoveryThread.joinable()) m_srvDiscoveryThread.join();
        if (m_srvAcceptThread.joinable())    m_srvAcceptThread.join();
        if (m_srvCaptureThread.joinable())   m_srvCaptureThread.join();

        m_inputAndClip.ReleaseAllHeldKeys();
        m_connectedClientIp.clear();
        SetWindowTextW(m_btnSrvToggle, L"Запустить сервер");
        UpdateStatusLabels();
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
            uint8_t pwdHash[32] = {};
            CryptoEngine::ComputeSHA256(pwdSalt.data(), pwdSalt.size(), pwdHash);

            uint8_t expectedHmac[32] = {};
            CryptoEngine::ComputeHMACSHA256(pwdHash, 32, chal.challenge, 32, expectedHmac);

            bool authOk = (memcmp(expectedHmac, resp.hmac, 32) == 0);

            AuthResultPayload resPayload = {};
            resPayload.authenticated = authOk ? 1 : 0;
            CryptoEngine::RandomBytes(reinterpret_cast<uint8_t*>(&resPayload.udpSessionToken), 8);
            if (resPayload.udpSessionToken == 0) resPayload.udpSessionToken = 1;

            if (authOk) {
                CryptoEngine::ComputeHMACSHA256(pwdHash, 32, chal.salt, 32, m_srvSessionKey);
                m_activeUdpToken = resPayload.udpSessionToken;

                char ipStr[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &cliAddr.sin_addr, ipStr, sizeof(ipStr));
                m_connectedClientIp = ipStr;

                {
                    std::lock_guard<std::mutex> lock(m_srvClientUdpMutex);
                    m_srvClientUdpAddr = cliAddr;
                    m_srvClientUdpAddr.sin_port = htons(resp.clientUdpPort);
                    m_hasClientUdpAddr = (resp.clientUdpPort != 0);
                }

                m_srvClientTcp = clientSock;
                m_forceIdrNextFrame = true;
                m_clientAuthorized = true;

                if (SendMessageW(m_chkAutoMin, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    ShowWindow(m_hwndMain, SW_MINIMIZE);
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

            bool isLoopbackTest = (m_connectedClientIp == "127.0.0.1" ||
                                   (m_clientRunning.load() && m_connectedClientIp == DetectRadminVpnIP()));

            while (m_serverRunning && m_clientAuthorized) {
                ControlHeader cHdr = {};
                if (!RecvAllTcp(clientSock, &cHdr, sizeof(cHdr)) || cHdr.magic != MAGIC_CONTROL) {
                    break;
                }

                RECT deskRect = { 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) };
                bool localSelfViewerActive = (m_clientRunning.load() && IsWindowVisible(m_hwndViewer));
                bool blockSelfInput = isLoopbackTest || localSelfViewerActive;

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
                } else if (cHdr.payloadSize > 0) {
                    std::vector<uint8_t> skip(std::min<uint32_t>(cHdr.payloadSize, MAX_CLIPBOARD_BYTES));
                    if (!RecvAllTcp(clientSock, skip.data(), skip.size())) break;
                }
            }

            m_inputAndClip.ReleaseAllHeldKeys();
            m_clientAuthorized = false;
            m_connectedClientIp.clear();
            closesocket(clientSock);
            m_srvClientTcp = INVALID_SOCKET;
            PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);
        }

        if (udpHandshakeListener.joinable()) udpHandshakeListener.join();
    }

    void ServerCaptureAndEncodeLoop() {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

        DxgiScreenCapturer capturer;
        capturer.Initialize(1920, 1080);

        LowLatencyH264Encoder encoder;
        bool encoderReady = false;

        std::vector<uint8_t> nv12Buffer;
        std::vector<uint8_t> h264Stream;
        uint32_t frameId = 1;
        uint32_t framesInSec = 0;
        uint64_t secTimer = NowMicros();
        uint64_t lastPingUs = 0;

        while (m_serverRunning) {
            if (!m_clientAuthorized) {
                Sleep(15);
                continue;
            }

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
            if (!encoderReady) {
                Sleep(10);
                continue;
            }

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

                        UdpVideoHeader* vHdr = reinterpret_cast<UdpVideoHeader*>(packetBuf);
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

                        // Микро-пейсинг пакетов для защиты буфера виртуального адаптера Radmin VPN от переполнения на IDR-кадрах
                        if ((idx & 15) == 15) {
                            MicroSpinWait(80);
                        }
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
        SendMessageW(m_listHosts, LB_RESETCONTENT, 0, 0);
        {
            std::lock_guard<std::mutex> lock(m_hostsMutex);
            m_discoveredHosts.clear();
        }

        std::thread([this]() {
            SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (s == INVALID_SOCKET) return;

            BOOL bcast = TRUE;
            setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char*)&bcast, sizeof(bcast));
            DWORD timeoutMs = 450;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
            DisableUdpConnReset(s);

            std::vector<std::string> bcastTargets;
            DetectRadminVpnIP(&bcastTargets);

            DiscoveryPacket req = {};
            req.magic = MAGIC_DISCOVERY;
            req.isResponse = 0;

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
                    if (!exists) {
                        PostMessageW(m_hwndMain, WM_APP_HOST_FOUND, 0, 0);
                    }
                } else if (r <= 0) {
                    break;
                }
            }
            closesocket(s);
        }).detach();
    }

    void ConnectToServer() {
        if (m_clientRunning) return;

        char ipBuf[64] = {}, portBuf[16] = {}, passBuf[128] = {};
        GetWindowTextA(m_editCliIp, ipBuf, sizeof(ipBuf));
        GetWindowTextA(m_editCliPort, portBuf, sizeof(portBuf));
        GetWindowTextA(m_editCliPass, passBuf, sizeof(passBuf));

        std::string hostIp = ipBuf;
        uint16_t port = (uint16_t)std::atoi(portBuf);
        if (port == 0) port = DEFAULT_STREAM_PORT;
        std::string password = passBuf;

        if (hostIp.empty()) {
            MessageBoxW(m_hwndMain, L"Выберите сервер из списка или введите IP-адрес Radmin VPN!", L"Внимание", MB_ICONWARNING);
            return;
        }

        SOCKET tcpSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL noDelay = TRUE;
        setsockopt(tcpSock, IPPROTO_TCP, TCP_NODELAY, (const char*)&noDelay, sizeof(noDelay));

        sockaddr_in srvAddr = {};
        srvAddr.sin_family = AF_INET;
        srvAddr.sin_port = htons(port);
        if (inet_pton(AF_INET, hostIp.c_str(), &srvAddr.sin_addr) <= 0) {
            closesocket(tcpSock);
            MessageBoxW(m_hwndMain, L"Некорректный формат IP-адреса!", L"Ошибка", MB_ICONERROR);
            return;
        }

        if (connect(tcpSock, (sockaddr*)&srvAddr, sizeof(srvAddr)) == SOCKET_ERROR) {
            closesocket(tcpSock);
            MessageBoxW(m_hwndMain, L"Не удалось подключиться к серверу по TCP!", L"Ошибка подключения", MB_ICONERROR);
            return;
        }

        SOCKET udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int rcvBuf = 8 * 1024 * 1024;
        setsockopt(udpSock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvBuf, sizeof(rcvBuf));
        DisableUdpConnReset(udpSock);

        sockaddr_in localUdp = {};
        localUdp.sin_family = AF_INET;
        localUdp.sin_addr.s_addr = INADDR_ANY;
        localUdp.sin_port = 0;
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
        pwdSalt.insert(pwdSalt.end(), chal.salt, chal.salt + 32);
        uint8_t pwdHash[32] = {};
        CryptoEngine::ComputeSHA256(pwdSalt.data(), pwdSalt.size(), pwdHash);

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
        m_cliUdpToken = resPayload.udpSessionToken;
        m_cliTcpSock = tcpSock;
        m_cliUdpSock = udpSock;

        // Адаптивное масштабирование окна вьювера под рабочий стол клиента с учетом пропорций сервера
        PositionViewerWindowAdaptively(chal.screenWidth, chal.screenHeight);
        ShowWindow(m_hwndViewer, SW_SHOW);
        SetForegroundWindow(m_hwndViewer);
        m_renderer.Initialize(m_hwndViewer);

        m_clientRunning = true;
        SetWindowTextW(m_btnCliConnect, L"Отключиться");

        m_cliTcpThread = std::thread(&RemoteDesktopApp::ClientTcpControlLoop, this);
        m_cliUdpThread = std::thread(&RemoteDesktopApp::ClientUdpVideoLoop, this, srvAddr);

        UpdateStatusLabels();
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
        if (winH > maxH) {
            winH = maxH;
            winW = (int)(winH * aspect);
        }

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
        ShowWindow(m_hwndViewer, SW_HIDE);
        SetWindowTextW(m_btnCliConnect, L"Подключиться");
        UpdateStatusLabels();
    }

    void ClientTcpControlLoop() {
        uint64_t lastPingSent = 0;

        while (m_clientRunning) {
            ControlHeader cHdr = {};
            if (!RecvAllTcp(m_cliTcpSock, &cHdr, sizeof(cHdr)) || cHdr.magic != MAGIC_CONTROL) {
                break;
            }

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
            } else if (cHdr.payloadSize > 0) {
                std::vector<uint8_t> skip(std::min<uint32_t>(cHdr.payloadSize, MAX_CLIPBOARD_BYTES));
                if (!RecvAllTcp(m_cliTcpSock, skip.data(), skip.size())) break;
            }
        }

        if (m_clientRunning) {
            PostMessageW(m_hwndMain, WM_APP_CLIENT_LOST, 0, 0);
        }
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
            uint16_t totalChunks = 0;
            uint16_t receivedChunks = 0;
            uint8_t  flags = 0;
            uint16_t width = 0;
            uint16_t height = 0;
            uint32_t encodeUs = 0;
            std::vector<bool> chunkMask;
            std::vector<uint8_t> buffer;
        } currentFrame;

        uint8_t recvBuf[2048];
        uint32_t expectedFrameId = 0;
        bool waitingForKeyframe = true; // Защита от разваливания изображения при потере UDP-пакетов
        uint32_t fpsCounter = 0;
        uint64_t fpsTimer = NowMicros();
        uint64_t lastHelloUs = NowMicros();

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
            const UdpVideoHeader* hdr = reinterpret_cast<const UdpVideoHeader*>(recvBuf);
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

                // Декодируем только непрерывную цепочку кадров от последнего IDR (исключает рассыпание квадратами)
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
                PostMessageW(m_hwndMain, WM_APP_UPDATE_UI, 0, 0);
            }
        }

        CoUninitialize();
    }

    void RequestServerKeyframe() {
        if (!m_clientRunning || m_cliTcpSock == INVALID_SOCKET) return;
        uint64_t now = NowMicros();
        if (now - m_lastIdrReqUs < 120000ULL) return; // Не чаще 1 раза в 120 мс
        m_lastIdrReqUs = now;

        ControlHeader hdr = { MAGIC_CONTROL, CTRL_REQ_IDR, 0 };
        std::lock_guard<std::mutex> lock(m_cliTcpSendMutex);
        SendAllTcp(m_cliTcpSock, &hdr, sizeof(hdr));
    }

    void SendClientMouseEvent(int clientX, int clientY, int wheelDelta, uint32_t buttonFlags) {
        if (!m_clientRunning || m_cliTcpSock == INVALID_SOCKET) return;
        float normX = 0.0f, normY = 0.0f;
        if (!m_renderer.MapWindowPointToNormalized(clientX, clientY, normX, normY)) return;

        MouseEventPayload ev = {};
        ev.normX = normX;
        ev.normY = normY;
        ev.wheelDelta = wheelDelta;
        ev.flags = buttonFlags;

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

        ClipboardHeaderPayload clipHdr = {};
        clipHdr.dataType = fmt;
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
            SetWindowPos(m_hwndViewer, HWND_TOP,
                         mi.rcMonitor.left, mi.rcMonitor.top,
                         mi.rcMonitor.right - mi.rcMonitor.left,
                         mi.rcMonitor.bottom - mi.rcMonitor.top,
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
    // АДАПТИВНАЯ КОМПОНОВКА ОКНА ПОДКЛЮЧЕНИЯ (РЕСАЙЗ + DPI SCALING)
    // ========================================================================
    void UpdateFontsForDpi(UINT dpi) {
        int fontHeight = -MulDiv(10, dpi, 72);
        HFONT newFont = CreateFontW(fontHeight, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT newBold = CreateFontW(fontHeight, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        HWND normalCtrls[] = {
            m_lblSrvName, m_editSrvName, m_lblSrvPass, m_editSrvPass,
            m_lblSrvPort, m_editSrvPort, m_chkAutoMin, m_btnSrvTray, m_lblSrvStatus,
            m_listHosts, m_lblCliIp, m_editCliIp, m_editCliPort,
            m_lblCliPass, m_editCliPass, m_lblCliStatus
        };
        HWND boldCtrls[] = {
            m_grpServer, m_btnSrvToggle, m_grpClient, m_btnCliScan, m_btnCliConnect
        };

        for (HWND h : normalCtrls) if (h) SendMessageW(h, WM_SETFONT, (WPARAM)newFont, TRUE);
        for (HWND h : boldCtrls)   if (h) SendMessageW(h, WM_SETFONT, (WPARAM)newBold, TRUE);

        if (m_hFont) DeleteObject(m_hFont);
        if (m_hFontBold) DeleteObject(m_hFontBold);
        m_hFont = newFont;
        m_hFontBold = newBold;
    }

    void RelayoutMainWindow() {
        if (!m_hwndMain || !m_grpServer) return;
        RECT rc = {};
        GetClientRect(m_hwndMain, &rc);
        int cw = rc.right - rc.left;
        int ch = rc.bottom - rc.top;
        if (cw <= 50 || ch <= 50) return;

        UINT dpi = GetDpiForWindow(m_hwndMain);
        auto S = [&](int v) { return MulDiv(v, dpi, 96); };

        int margin = S(12);
        int gap = S(12);
        int colW = (cw - margin * 2 - gap) / 2;
        int grpH = ch - margin * 2;

        int leftX = margin;
        int rightX = margin + colW + gap;
        int innerPad = S(14);
        int rowH = S(26);
        int btnH = S(34);
        int vStep = S(34);

        HDWP hdwp = BeginDeferWindowPos(22);
        auto Place = [&](HWND h, int x, int y, int w, int ht) {
            if (h) hdwp = DeferWindowPos(hdwp, h, nullptr, x, y, std::max(10, w), std::max(10, ht), SWP_NOZORDER | SWP_NOACTIVATE);
        };

        // Левая колонка: Сервер
        Place(m_grpServer, leftX, margin, colW, grpH);
        int sx = leftX + innerPad;
        int sw = colW - innerPad * 2;
        int lblW = std::min(S(155), sw / 2);
        int edtW = sw - lblW - S(6);
        int sy = margin + S(28);

        Place(m_lblSrvName,  sx, sy + S(3), lblW, rowH);
        Place(m_editSrvName, sx + lblW + S(6), sy, edtW, rowH);
        sy += vStep;

        Place(m_lblSrvPass,  sx, sy + S(3), lblW, rowH);
        Place(m_editSrvPass, sx + lblW + S(6), sy, edtW, rowH);
        sy += vStep;

        Place(m_lblSrvPort,  sx, sy + S(3), lblW, rowH);
        Place(m_editSrvPort, sx + lblW + S(6), sy, edtW, rowH);
        sy += vStep;

        Place(m_chkAutoMin, sx, sy, sw, S(24));
        sy += S(28);

        int halfBtnW = (sw - S(8)) / 2;
        Place(m_btnSrvToggle, sx, sy, halfBtnW, btnH);
        Place(m_btnSrvTray,   sx + halfBtnW + S(8), sy, sw - halfBtnW - S(8), btnH);
        sy += btnH + S(10);

        int srvStatusH = (margin + grpH) - sy - innerPad;
        Place(m_lblSrvStatus, sx, sy, sw, std::max(S(50), srvStatusH));

        // Правая колонка: Клиент
        Place(m_grpClient, rightX, margin, colW, grpH);
        int cx = rightX + innerPad;
        int clW = colW - innerPad * 2;
        int cy = margin + S(26);

        Place(m_btnCliScan, cx, cy, clW, S(30));
        cy += S(36);

        int bottomControlsH = vStep * 2 + btnH + S(60) + innerPad;
        int listH = std::max(S(65), (margin + grpH) - cy - bottomControlsH);
        Place(m_listHosts, cx, cy, clW, listH);
        cy += listH + S(8);

        int cliLblW = std::min(S(120), clW / 3);
        int portW = S(75);
        int ipW = clW - cliLblW - portW - S(12);
        Place(m_lblCliIp,    cx, cy + S(3), cliLblW, rowH);
        Place(m_editCliIp,   cx + cliLblW + S(6), cy, ipW, rowH);
        Place(m_editCliPort, cx + cliLblW + ipW + S(12), cy, portW, rowH);
        cy += vStep;

        Place(m_lblCliPass,  cx, cy + S(3), cliLblW, rowH);
        Place(m_editCliPass, cx + cliLblW + S(6), cy, clW - cliLblW - S(6), rowH);
        cy += vStep;

        Place(m_btnCliConnect, cx, cy, clW, btnH);
        cy += btnH + S(8);

        int cliStatusH = (margin + grpH) - cy - innerPad;
        Place(m_lblCliStatus, cx, cy, clW, std::max(S(40), cliStatusH));

        EndDeferWindowPos(hdwp);
        InvalidateRect(m_hwndMain, nullptr, TRUE);
    }

    void UpdateStatusLabels() {
        m_radminIp = DetectRadminVpnIP();

        std::wstringstream srvSs;
        srvSs << L"IP в Radmin VPN: " << std::wstring(m_radminIp.begin(), m_radminIp.end())
              << L" : " << m_serverPort << L"\r\n";
        if (!m_serverRunning) {
            srvSs << L"Статус: Сервер остановлен";
        } else if (!m_clientAuthorized) {
            srvSs << L"Статус: Ожидание подключения ( можно свернуть окно )\r\n"
                  << L"UDP Discovery: порт " << DISCOVERY_UDP_PORT;
        } else {
            srvSs << L"Статус: Активен клиент [" << std::wstring(m_connectedClientIp.begin(), m_connectedClientIp.end()) << L"]\r\n"
                  << L"FPS: " << m_srvFps.load()
                  << L" | Encode: " << std::fixed << std::setprecision(2) << (m_srvEncodeUs.load() / 1000.0) << L" мс"
                  << L" | Decode: " << (m_srvClientDecodeUs.load() / 1000.0) << L" мс"
                  << L" | RTT: " << (m_srvRttUs.load() / 1000.0) << L" мс";
        }
        SetWindowTextW(m_lblSrvStatus, srvSs.str().c_str());

        std::wstringstream cliSs;
        if (!m_clientRunning) {
            cliSs << L"Статус: Отключен. Нажмите «Поиск серверов» или введите IP.";
        } else {
            cliSs << L"Статус: Трансляция активна (Ctrl+Alt+F — полный экран)\r\n"
                  << L"FPS: " << m_cliFps.load()
                  << L" | Encode: " << std::fixed << std::setprecision(2) << (m_cliEncodeUs.load() / 1000.0) << L" мс"
                  << L" | Decode: " << (m_cliDecodeUs.load() / 1000.0) << L" мс"
                  << L" | RTT: " << (m_cliRttUs.load() / 1000.0) << L" мс";

            std::wstringstream titleSs;
            titleSs << L"Radmin Ultra-Low Latency Viewer — FPS: " << m_cliFps.load()
                    << L" | Encode: " << std::fixed << std::setprecision(1) << (m_cliEncodeUs.load() / 1000.0) << L"ms"
                    << L" | Decode: " << (m_cliDecodeUs.load() / 1000.0) << L"ms"
                    << L" | RTT: " << (m_cliRttUs.load() / 1000.0) << L"ms"
                    << L" | [Ctrl+Alt+F - Полный экран]";
            SetWindowTextW(m_hwndViewer, titleSs.str().c_str());
        }
        SetWindowTextW(m_lblCliStatus, cliSs.str().c_str());
    }
};

static RemoteDesktopApp g_app;

// ============================================================================
// ПЕРЕХВАТ КЛАВИШИ WINDOWS В АКТИВНОМ ОКНЕ ВЬЮВЕРА (ИСКЛЮЧАЕТ ЗАЛИПАНИЕ WIN)
// ============================================================================
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && g_app.m_clientRunning) {
        KBDLLHOOKSTRUCT* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        if (kb && kb->dwExtraInfo != INJECTED_SIGNATURE) {
            if ((kb->vkCode == VK_LWIN || kb->vkCode == VK_RWIN) &&
                GetForegroundWindow() == g_app.m_hwndViewer) {
                bool isDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
                g_app.SendClientKeyEvent((uint16_t)kb->scanCode, (uint16_t)kb->vkCode, isDown, true);
                return 1; // Подавляем локальное меню Пуск на клиенте, чтобы фокус не терялся
            }
        }
    }
    return CallNextHookEx(g_app.m_hKeyboardHook, nCode, wParam, lParam);
}

// ============================================================================
// ОКОННЫЕ ПРОЦЕДУРЫ WIN32
// ============================================================================
LRESULT CALLBACK ViewerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if ((msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) || (msg >= WM_KEYFIRST && msg <= WM_KEYLAST)) {
        if (GetMessageExtraInfo() == INJECTED_SIGNATURE) {
            return 0;
        }
    }

    switch (msg) {
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
            g_app.m_renderer.OnResize(LOWORD(lParam), HIWORD(lParam));
        }
        return 0;

    // При потере фокуса окном вьювера немедленно отпускаем Win/Alt/Ctrl/Shift на сервере
    case WM_KILLFOCUS:
        g_app.SendClientReleaseAllKeys();
        return 0;

    case WM_ACTIVATE:
        if (LOWORD(wParam) == WA_INACTIVE) {
            g_app.SendClientReleaseAllKeys();
        }
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
        uint16_t scanCode = (uint16_t)((lParam >> 16) & 0xFF);
        bool isExt = (lParam & (1 << 24)) != 0;
        g_app.SendClientKeyEvent(scanCode, (uint16_t)wParam, true, isExt);
        return 0;
    }

    case WM_KEYUP:
    case WM_SYSKEYUP: {
        uint16_t scanCode = (uint16_t)((lParam >> 16) & 0xFF);
        bool isExt = (lParam & (1 << 24)) != 0;
        g_app.SendClientKeyEvent(scanCode, (uint16_t)wParam, false, isExt);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_app.m_hwndMain = hwnd;
        HINSTANCE hInst = GetModuleHandleW(nullptr);

        auto MakeCtrl = [&](LPCWSTR cls, LPCWSTR txt, DWORD style, int id) {
            return CreateWindowExW(0, cls, txt, WS_CHILD | WS_VISIBLE | style,
                                   0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)id, hInst, nullptr);
        };

        // --- БЛОК 1: РЕЖИМ ХОСТА (СЕРВЕР) ---
        g_app.m_grpServer = MakeCtrl(L"BUTTON", L"[1] Создать сервер (Режим Хоста)", BS_GROUPBOX, IDC_GRP_SERVER);

        char compName[64] = "Radmin-PC";
        DWORD compLen = sizeof(compName);
        GetComputerNameA(compName, &compLen);
        std::wstring wCompName(compName, compName + strlen(compName));

        g_app.m_lblSrvName  = MakeCtrl(L"STATIC", L"Имя машины / сервера:", 0, IDC_LBL_SRV_NAME);
        g_app.m_editSrvName = MakeCtrl(L"EDIT", wCompName.c_str(), WS_BORDER | ES_AUTOHSCROLL, IDC_EDIT_SRV_NAME);

        g_app.m_lblSrvPass  = MakeCtrl(L"STATIC", L"Пароль доступа:", 0, IDC_LBL_SRV_PASS);
        g_app.m_editSrvPass = MakeCtrl(L"EDIT", L"12345", WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, IDC_EDIT_SRV_PASS);

        g_app.m_lblSrvPort  = MakeCtrl(L"STATIC", L"Порт (TCP + UDP):", 0, IDC_LBL_SRV_PORT);
        g_app.m_editSrvPort = MakeCtrl(L"EDIT", L"27000", WS_BORDER | ES_NUMBER, IDC_EDIT_SRV_PORT);

        g_app.m_chkAutoMin   = MakeCtrl(L"BUTTON", L"Сворачивать панель при подключении клиента", BS_AUTOCHECKBOX, IDC_CHK_AUTO_MIN);
        g_app.m_btnSrvToggle = MakeCtrl(L"BUTTON", L"Запустить сервер", BS_PUSHBUTTON, IDC_BTN_SRV_TOGGLE);
        g_app.m_btnSrvTray   = MakeCtrl(L"BUTTON", L"Свернуть в трей", BS_PUSHBUTTON, IDC_BTN_SRV_TRAY);
        g_app.m_lblSrvStatus = MakeCtrl(L"STATIC", L"", SS_LEFT, IDC_LBL_SRV_STATUS);

        // --- БЛОК 2: РЕЖИМ КЛИЕНТА ---
        g_app.m_grpClient     = MakeCtrl(L"BUTTON", L"[2] Подключиться к ПК (Режим Клиента)", BS_GROUPBOX, IDC_GRP_CLIENT);
        g_app.m_btnCliScan    = MakeCtrl(L"BUTTON", L"Поиск серверов в сети Radmin VPN", BS_PUSHBUTTON, IDC_BTN_CLI_SCAN);
        g_app.m_listHosts     = MakeCtrl(L"LISTBOX", L"", WS_BORDER | WS_VSCROLL | LBS_NOTIFY, IDC_LIST_HOSTS);
        g_app.m_lblCliIp      = MakeCtrl(L"STATIC", L"IP и порт хоста:", 0, IDC_LBL_CLI_IP);
        g_app.m_editCliIp     = MakeCtrl(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, IDC_EDIT_CLI_IP);
        g_app.m_editCliPort   = MakeCtrl(L"EDIT", L"27000", WS_BORDER | ES_NUMBER, IDC_EDIT_CLI_PORT);
        g_app.m_lblCliPass    = MakeCtrl(L"STATIC", L"Пароль сервера:", 0, IDC_LBL_CLI_PASS);
        g_app.m_editCliPass   = MakeCtrl(L"EDIT", L"12345", WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, IDC_EDIT_CLI_PASS);
        g_app.m_btnCliConnect = MakeCtrl(L"BUTTON", L"Подключиться", BS_PUSHBUTTON, IDC_BTN_CLI_CONNECT);
        g_app.m_lblCliStatus  = MakeCtrl(L"STATIC", L"", SS_LEFT, IDC_LBL_CLI_STATUS);

        g_app.UpdateFontsForDpi(GetDpiForWindow(hwnd));
        g_app.RelayoutMainWindow();
        g_app.ShowInTray(false);

        AddClipboardFormatListener(hwnd);
        g_app.UpdateStatusLabels();
        return 0;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        UINT dpi = GetDpiForWindow(hwnd);
        mmi->ptMinTrackSize.x = MulDiv(720, dpi, 96);
        mmi->ptMinTrackSize.y = MulDiv(360, dpi, 96);
        return 0;
    }

    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
            g_app.RelayoutMainWindow();
        }
        return 0;

    case WM_DPICHANGED: {
        UINT newDpi = HIWORD(wParam);
        g_app.UpdateFontsForDpi(newDpi);
        const RECT* suggested = reinterpret_cast<const RECT*>(lParam);
        SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                     suggested->right - suggested->left, suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        g_app.RelayoutMainWindow();
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
            if (g_app.m_serverRunning) {
                AppendMenuW(hMenu, MF_STRING, IDM_TRAY_STOP_SRV, L"Остановить сервер");
            }
            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"Выход");
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(hMenu);
        }
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);

        if (id == IDC_BTN_SRV_TOGGLE && code == BN_CLICKED) {
            if (!g_app.m_serverRunning) g_app.StartServer();
            else g_app.StopServer();
        } else if (id == IDC_BTN_SRV_TRAY && code == BN_CLICKED) {
            g_app.ShowInTray(true);
        } else if (id == IDM_TRAY_RESTORE) {
            g_app.RestoreFromTray();
        } else if (id == IDM_TRAY_STOP_SRV) {
            g_app.StopServer();
            g_app.RestoreFromTray();
        } else if (id == IDM_TRAY_EXIT) {
            DestroyWindow(hwnd);
        } else if (id == IDC_BTN_CLI_SCAN && code == BN_CLICKED) {
            g_app.ScanNetworkForServers();
        } else if (id == IDC_LIST_HOSTS && code == LBN_SELCHANGE) {
            int sel = (int)SendMessageW(g_app.m_listHosts, LB_GETCURSEL, 0, 0);
            std::lock_guard<std::mutex> lock(g_app.m_hostsMutex);
            if (sel >= 0 && sel < (int)g_app.m_discoveredHosts.size()) {
                SetWindowTextA(g_app.m_editCliIp, g_app.m_discoveredHosts[sel].ip.c_str());
                SetWindowTextA(g_app.m_editCliPort, std::to_string(g_app.m_discoveredHosts[sel].port).c_str());
            }
        } else if (id == IDC_BTN_CLI_CONNECT && code == BN_CLICKED) {
            if (!g_app.m_clientRunning) g_app.ConnectToServer();
            else g_app.DisconnectClient();
        }
        return 0;
    }

    case WM_CLIPBOARDUPDATE:
        g_app.BroadcastLocalClipboardChange();
        return 0;

    case WM_APP_UPDATE_UI:
        g_app.UpdateStatusLabels();
        return 0;

    case WM_APP_CLIENT_LOST:
        g_app.DisconnectClient();
        return 0;

    case WM_APP_HOST_FOUND: {
        SendMessageW(g_app.m_listHosts, LB_RESETCONTENT, 0, 0);
        std::lock_guard<std::mutex> lock(g_app.m_hostsMutex);
        for (const auto& h : g_app.m_discoveredHosts) {
            std::ostringstream oss;
            oss << h.name << " [" << h.ip << ":" << h.port << "] (" << h.width << "x" << h.height << ")";
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

    case WM_CLOSE:
        // Если сервер активен, сворачиваем панель на панель задач вместо обрыва сессии, либо спрашиваем подтверждение
        if (g_app.m_serverRunning && g_app.m_clientAuthorized) {
            ShowWindow(hwnd, SW_MINIMIZE);
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        RemoveClipboardFormatListener(hwnd);
        g_app.RemoveTrayIcon();
        g_app.DisconnectClient();
        g_app.StopServer();
        if (g_app.m_hFont) DeleteObject(g_app.m_hFont);
        if (g_app.m_hFontBold) DeleteObject(g_app.m_hFontBold);
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
    wcMain.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcMain.lpszClassName = L"RadminUltraRD_Main";
    RegisterClassExW(&wcMain);

    WNDCLASSEXW wcViewer = { sizeof(WNDCLASSEXW) };
    wcViewer.style = CS_HREDRAW | CS_VREDRAW;
    wcViewer.lpfnWndProc = ViewerWndProc;
    wcViewer.hInstance = hInstance;
    wcViewer.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcViewer.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcViewer.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wcViewer.lpszClassName = L"RadminUltraRD_Viewer";
    RegisterClassExW(&wcViewer);

    // Адаптивный расчет стартового размера главного окна относительно текущего монитора и DPI
    RECT workArea = {};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    int screenW = workArea.right - workArea.left;
    int screenH = workArea.bottom - workArea.top;

    UINT dpi = GetDpiForSystem();
    int initW = std::min(screenW - 40, MulDiv(880, dpi, 96));
    int initH = std::min(screenH - 40, MulDiv(420, dpi, 96));
    int initX = workArea.left + (screenW - initW) / 2;
    int initY = workArea.top + (screenH - initH) / 2;

    g_app.m_hwndViewer = CreateWindowExW(
        0, L"RadminUltraRD_Viewer", L"Radmin Ultra-Low Latency Viewer",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720,
        nullptr, nullptr, hInstance, nullptr);

    HWND hwndMain = CreateWindowExW(
        0, L"RadminUltraRD_Main",
        L"Radmin VPN Ultra-Low Latency Remote Desktop (DXGI + H.264 Zero-Latency + UDP)",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        initX, initY, initW, initH,
        nullptr, nullptr, hInstance, nullptr);

    g_app.m_hKeyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);

    ShowWindow(hwndMain, nCmdShow);
    UpdateWindow(hwndMain);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_app.m_hKeyboardHook) UnhookWindowsHookEx(g_app.m_hKeyboardHook);
    timeEndPeriod(1);
    MFShutdown();
    CoUninitialize();
    WSACleanup();
    return 0;
}
