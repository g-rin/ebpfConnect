#include <atomic>
#include <iostream>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fstream>
#include <getopt.h>
#include <iomanip>
#include <signal.h>
#include <stdio.h>
#include <sstream>
#include <string_view>
#include <unistd.h>
#include <unordered_map>

std::atomic<bool> Stopped {false};
perf_buffer* EventPipe = nullptr;
perf_buffer* ErrorPipe = nullptr;

void SigHandler(const int sig)
{
    Stopped.exchange(true);
}

struct Hook
{
    std::string name;
    bpf_program* prog {nullptr};
    bpf_link* link {nullptr};
};

bool PrintDebugMessages = false;

int LibBpfPrintCallback(
    enum libbpf_print_level level,
    const char *format,
    va_list args)
{
    size_t bufSize = 32*BUFSIZ;
    char buf[bufSize];
    const int sz = vsnprintf(buf, bufSize, format, args);

    if (sz > 0)
    {
        switch (level)
        {
        case LIBBPF_WARN:
            std::cerr << "[W]: " << std::string_view(buf, sz);
            break;

        case LIBBPF_INFO:
            std::cout << "[I]: " << std::string_view(buf, sz);
            break;

        case LIBBPF_DEBUG:
            if (PrintDebugMessages)
            {
                std::cout << "[D]: " << std::string_view(buf, sz);
            }

            break;
        }
    }

    return sz;
}

struct EbpfParameterHeader
{
    uint32_t id;
    uint16_t type;
    uint16_t size;
} __attribute__((__packed__));

struct EbpfParameter
{
    struct EbpfParameterHeader hdr;
    uint8_t data[0];
} __attribute__((__packed__));

struct EbpfEventHeader
{
    uint64_t timestamp;
    uint32_t count;
    uint16_t type;
    uint16_t size;
} __attribute__((__packed__));

struct EbpfEvent
{
    struct EbpfEventHeader hdr;
    uint8_t parameters[0];
} __attribute__((__packed__));

std::string GetHexDump(const void* data, const size_t dataSize)
{
    std::ostringstream ss;
    const char* p = reinterpret_cast<const char*>(data);
    for (size_t i = 0; i < dataSize; ++i, ++p)
    {
        if (i && (0 ==(i % 4)))
        {
            ss << "|";
        }

        ss << std::hex << std::setw(2) << std::setfill('0') << std::right;
        ss << (static_cast<int>(*p) & 0xFF);
    }
    return ss.str();
}

void PrintParameters(
    const EbpfParameter* const param,
    const uint16_t count)
{
    std::cout
        << "\n\t{id: " << param->hdr.id
        << ", type: " << param->hdr.type
        << ", size: " << param->hdr.size
        << ", data: " << GetHexDump(param->data, param->hdr.size) << "}";

    if (count > 1)
    {
        const EbpfParameter* const next =
            reinterpret_cast<const EbpfParameter*>(
                reinterpret_cast<const char*>(param)
                + sizeof(EbpfParameterHeader)
                + param->hdr.size);

        PrintParameters(next, count - 1);
    }
}

void EventReceivedCallback(
    void *ctx,
    int cpu,
    void *data,
    uint32_t size)
{
    const auto* event = reinterpret_cast<EbpfEvent*>(data);

    std::cout
        << "timestamp: " << event->hdr.timestamp
        << ", type: " << event->hdr.type
        << ", count: " << event->hdr.count
        << ", size: " << event->hdr.size;

    PrintParameters(
        reinterpret_cast<EbpfParameter*>(
            reinterpret_cast<char*>(data) + sizeof(EbpfEventHeader)),
        event->hdr.count);

    std::cout << std::endl;
}

void EventLostCallback(
    void* ctx,
    const int cpu,
    const unsigned long long count)
{
    std::cerr
        << __PRETTY_FUNCTION__
        << " [" << cpu << "] lost: " << count
        << std::endl;
}

void ErrorReceivedCallback(
    void *ctx,
    int cpu,
    void *data,
    uint32_t size)
{
    int32_t errorCode;

    if (size < sizeof(errorCode))
    {
        std::cout
            << "Error: "
            << std::string_view((char*)data, size)
            << std::endl;

        return;
    }

    errorCode = *(reinterpret_cast<uint32_t*>(data));
    const char* text = reinterpret_cast<char*>(data) + sizeof(errorCode);
    const auto textSize = strnlen(text, size - sizeof(errorCode));
    const std::string_view description(text, textSize);

    std::cout
        << "Error [0x" << GetHexDump(&errorCode, sizeof(errorCode)) << "]: "
        << description << std::endl;
}

void ErrorLostCallback(
    void* ctx,
    const int cpu,
    const unsigned long long count)
{
    std::cerr
        << __PRETTY_FUNCTION__
        << " [" << cpu << "] lost: " << count
        << std::endl;
}

std::string GetHookKey(const bpf_program* const hook)
{
    std::string name = bpf_program__name(hook);
    std::string_view view(name);

    using namespace std::literals::string_view_literals;
    const std::string_view onPrefix = "On"sv;

    if (0 == view.find(onPrefix))
    {
        view.remove_prefix(onPrefix.size());
    }

    bool isSyscallHook = false;
    const std::string_view enterSuffix = "Enter"sv;
    const std::string_view exitSuffix = "Exit"sv;

    if (view.npos != view.rfind(enterSuffix))
    {
        isSyscallHook = true;
        view.remove_suffix(enterSuffix.size());
    }
    else if (view.npos != view.rfind(exitSuffix))
    {
        isSyscallHook = true;
        view.remove_suffix(exitSuffix.size());
    }

    if (view.size() == name.size())
    {
        return name;
    }

    std::string key;

    if (isSyscallHook)
    {
        key = "Syscall";
    }

    key += view;

    return key;
}

int main(int argc, char** argv)
{
    if (SIG_ERR == signal(SIGINT, SigHandler))
    {
        std::cerr
            << " signal(SIGINT, SigHandler) failed: "
            << strerror(errno)
            << std::endl;

        return -1;
    }

    bpf_object_open_opts ebpfOpenOpts {};
    std::string ebpfObjectFile;
    int optionsIndex = 0;
    const char* shortOptions = "";

    option longOptions[] = {
        {"help", no_argument, 0, 'h'},
        {"btf", required_argument, 0, 'b'},
        {"obj", required_argument, 0, 'o'},
        {"debug", no_argument, 0, 'd'},
        {0, 0, 0, 0}};

    for (bool needNext = true; needNext;)
    {
        const int opt = getopt_long(
            argc,
            argv,
            shortOptions,
            longOptions,
            &optionsIndex);

        if (-1 == opt)
        {
            break;
        }

        switch (opt)
        {
        case -1:
            needNext = false;
            break;

        case 'o':
            ebpfObjectFile = optarg;
            break;

        case 'b':
            ebpfOpenOpts.btf_custom_path = optarg;

            std::cout
                << "Use BTF custom file: "
                << ebpfOpenOpts.btf_custom_path
                << std::endl;

            break;

        case 'd':
            PrintDebugMessages = true;
            break;

        case 'h':
            std::cout
                << "Usage: " << argv[0] << ":"
                << "\n\t--object <path>: path to an ebpf-object file."
                << "\n\t--btf <path>: [optional] path to an external BTF file."
                << "\n\t--help: print the message and exit."
                << std::endl;

            return 0;
        }
    }

    if (ebpfObjectFile.empty())
    {
        std::cerr << "eBPF object file was not specified." << std::endl;
    }

    libbpf_set_print(LibBpfPrintCallback);
    ebpfOpenOpts.sz = sizeof(ebpfOpenOpts);

    bpf_object* ebpfObj = bpf_object__open_file(
        ebpfObjectFile.c_str(),
        &ebpfOpenOpts);

    if (!ebpfObj)
    {
        std::cerr
            << "ERR: bpf_object__open_file("
            << ebpfObjectFile << ") failed: "
            << strerror(errno)
            << std::endl;

        return -errno;
    }

    if (bpf_object__load(ebpfObj))
    {
        std::cerr
            << "ERR: bpf_object__load("
            << ebpfObjectFile << ") failed: "
            << strerror(errno)
            << std::endl;

        bpf_object__close(ebpfObj);
        return -1;
    }

    if (const int eventPipeFd = bpf_object__find_map_fd_by_name(
            ebpfObj,
            "EbpfEventPipe");
        eventPipeFd > 0)
    {
        EventPipe = perf_buffer__new(
            eventPipeFd,
            64,
            EventReceivedCallback,
            EventLostCallback,
            nullptr, // ctx
            nullptr); // opts

        if (!EventPipe)
        {
            std::cerr
                << "ERR: perf_buffer__new() failed: "
                << strerror(errno)
                << std::endl;

            perf_buffer__free(EventPipe);
            bpf_object__close(ebpfObj);
            return -1;
        }
    }
    else
    {
        std::cerr << "ERR: couldn't find event pipe's map" << std::endl;
        bpf_object__close(ebpfObj);
        return 0;
    }

        if (const int errorPipeFd = bpf_object__find_map_fd_by_name(
            ebpfObj,
            "EbpfErrorPipe");
        errorPipeFd > 0)
    {
        ErrorPipe = perf_buffer__new(
            errorPipeFd,64,
            ErrorReceivedCallback,
            ErrorLostCallback,
            nullptr, // ctx
            nullptr); // opts

        if (!ErrorPipe)
        {
            std::cerr
                << "ERR: perf_buffer__new() failed: "
                << strerror(errno)
                << std::endl;

            perf_buffer__free(EventPipe);
            perf_buffer__free(ErrorPipe);
            bpf_object__close(ebpfObj);
            return -1;
        }
    }
    else
    {
        std::cerr << "ERR: couldn't find event pipe's map" << std::endl;
        bpf_object__close(ebpfObj);
        return 0;
    }

    for (bpf_program* prog = bpf_object__next_program(ebpfObj, nullptr);
         prog;
         prog = bpf_object__next_program(ebpfObj, prog))
    {
        std::cout << "Attach " << bpf_program__name(prog) << " to "
                  << bpf_program__section_name(prog) << " ... ";

        if (bpf_program__attach(prog))
        {
            std::cout << "success" << std::endl;
        }
        else
        {
            std::cout << "failed (" << strerror(errno) << ")" << std::endl;
            perf_buffer__free(EventPipe);
            perf_buffer__free(ErrorPipe);
            bpf_object__close(ebpfObj);
            return -1;
        }
    }


    while (!Stopped)
    {
        perf_buffer__poll(ErrorPipe, 100);
        perf_buffer__poll(EventPipe, 100);
    }

    perf_buffer__free(ErrorPipe);
    perf_buffer__free(EventPipe);
    bpf_object__close(ebpfObj);
    std::cout << "Good bye!" << std::endl;
    return 0;
}
