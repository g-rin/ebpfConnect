#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

enum
{
    EBPF_ERR__BEGIN = 0x100,

    EBPF_ERR_NO_EVENT,
    EBPF_ERR_NO_TASK,
    EBPF_ERR_NO_DATA,
    EBPF_ERR_NO_SPACE,
    EBPF_ERR_PROBE_READ_FAILED,
    EBPF_ERR_NO_PATH_BUFFER,
    EBPF_ERR_NO_MEMBER,

    EBPF_ERR__END,
};

enum
{
    EBPF_EVENT__BEGIN = 0x200,

    EBPF_EVENT_SYSCALL_CONNECT_ENTER = EBPF_EVENT__BEGIN,
    EBPF_EVENT_SYSCALL_CONNECT_EXIT,

    EBPF_EVENT_TCP_CONNECT_STATE,

    EBPF_EVENT__END
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} EbpfErrorPipe SEC(".maps");

__attribute__((always_inline))
static inline void SendError(
    void* ctx,
    const uint32_t errorCode,
    char* const msg,
    const size_t msgSize)
{
    char buf[128];

    if (msgSize > 124
        || bpf_probe_read(buf, sizeof(errorCode), &errorCode)
        || bpf_probe_read(buf + sizeof(errorCode), msgSize, msg)
        || bpf_perf_event_output(
            ctx,
            &EbpfErrorPipe,
            BPF_F_CURRENT_CPU,
            buf,
            msgSize + sizeof(errorCode)))
    {
        bpf_trace_printk(msg, msgSize);
    }
}

#define SEND_ERROR(ctx, description, errorCode)      \
    ({                                                  \
        char fmt[] = description"\0";                   \
        SendError(ctx, errorCode, fmt, sizeof(fmt));    \
    })

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
    uint16_t type;
    uint16_t count;
    uint16_t size;
} __attribute__((__packed__));

struct EbpfEvent
{
    struct EbpfEventHeader hdr;
    struct EbpfParameter parameters[0];
} __attribute__((__packed__));

#define EBPF_MAX_EVENT_SIZE 32768

__attribute__((always_inline))
static inline int AddParameter(
    struct EbpfEvent* const event,
    const uint32_t id,
    const uint16_t type,
    const uint16_t size,
    const void* const data)
{
    if (!event)
    {
        return -EBPF_ERR_NO_EVENT;
    }

    if (!data)
    {
        return -EBPF_ERR_NO_DATA;
    }

    static const size_t paramHeaderSize = sizeof(struct EbpfParameterHeader);
    static const size_t evHeaderSize = sizeof(struct EbpfEventHeader);
    const size_t parameterSize = paramHeaderSize + size;
    const size_t finalSize = evHeaderSize + event->hdr.size + parameterSize;

    if (finalSize >= EBPF_MAX_EVENT_SIZE)
    {
        return -EBPF_ERR_NO_SPACE;
    }

    void* end = (void*)(event + evHeaderSize + event->hdr.size);
    struct EbpfParameter* const param = (struct EbpfParameter*)(end);

    if (!param)
    {
        return -EBPF_ERR_NO_SPACE;
    }

    param->hdr.id = id;
    param->hdr.type = type;
    param->hdr.size = size;

    if (bpf_probe_read(&param->data[0], size, data))
    {
        return -EBPF_ERR_PROBE_READ_FAILED;
    }

    event->hdr.count++;
    event->hdr.size += parameterSize;

    if (event->hdr.size % 8)
    {
        event->hdr.size += 8 - (event->hdr.size % 8);
    }

    return 0;
}

enum
{
    tept_unknown,
    tept_int8,
    tept_uint8,
    tept_int16,
    tept_uint16,
    tept_int32,
    tept_uint32,
    tept_int64,
    tept_uint64,
    tept_rawData,
};

__attribute__((always_inline))
static inline int AddParameterU32(
    struct EbpfEvent* const event,
    const uint32_t id,
    const uint32_t value)
{
    return AddParameter(event,id,tept_uint32,(uint16_t)sizeof(value), &value);
}

__attribute__((always_inline))
static inline int AddParameterU64(
    struct EbpfEvent* const event,
    const uint32_t id,
    const uint64_t value)
{
    return AddParameter(event,id,tept_uint64,(uint16_t)sizeof(value),&value);
}

enum
{
    tepid_pid,
    tepid_tid,
    tepid_syscallId,
    tepid_socketFd,
    tepid_addressLength,
    tepid_socketAddress,
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, EBPF_MAX_EVENT_SIZE);
    __uint(max_entries, 1);
} EventStorage SEC(".maps");

__attribute__((always_inline))
static inline struct EbpfEvent* CreateEvent(
    void* ctx,
    const uint16_t type,
    const uint64_t pidTgid)
{
    const int id = 0;

    struct EbpfEvent* event =
        (struct EbpfEvent*)bpf_map_lookup_elem(&EventStorage, &id);

    if (!event)
    {
        SEND_ERROR(ctx, "Couldn't get a new event.", EBPF_ERR_NO_EVENT);
        return NULL;
    }

    event->hdr.timestamp = bpf_ktime_get_ns();
    event->hdr.type = type;
    event->hdr.count = 0;
    event->hdr.size = 0;

    if (pidTgid)
    {
        const uint64_t mask = 0xFFFFFFFF;
        const uint32_t pid = (pidTgid >> 32) & mask;
        uint32_t errorCode = AddParameterU32(event, tepid_pid, pid);

        if (errorCode)
        {
            SEND_ERROR(ctx, "Couldn't set 'pid'.", errorCode);
            return NULL;
        }

        const uint32_t tid = pidTgid & mask;
        errorCode = AddParameterU32(event, tepid_tid, tid);

        if (errorCode)
        {
            SEND_ERROR(ctx, "Couldn't set 'tid'.", errorCode);
            return NULL;
        }
    }

    return event;
}

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} EbpfEventPipe SEC(".maps");

__attribute__((always_inline))
static inline bool SendEvent(void* ctx, struct EbpfEvent* event)
{
    static const size_t evHeaderSize = sizeof(struct EbpfEventHeader);

    return !bpf_perf_event_output(
        ctx,
        &EbpfEventPipe,
        BPF_F_CURRENT_CPU,
        event,
        evHeaderSize + event->hdr.size);
}

SEC("tp/syscalls/sys_enter_connect")
int OnConnectEnter(struct trace_event_raw_sys_enter* ctx)
{
    const uint64_t pidTgid = bpf_get_current_pid_tgid();

    if (!pidTgid)
    {
        return 0;
    }

    struct EbpfEvent* event = CreateEvent(
        ctx,
        EBPF_EVENT_SYSCALL_CONNECT_ENTER,
        pidTgid);

    if (!event)
    {
        return 0;
    }

    uint32_t errorCode = AddParameterU32(
            event,
            tepid_syscallId,
            BPF_CORE_READ(ctx, id));

    if (errorCode)
    {
        SEND_ERROR(ctx, "connect (enter): 'syscall_nr'", errorCode);
        return 0;
    }

    errorCode = AddParameterU64(
            event,
            tepid_socketFd,
            BPF_CORE_READ(ctx, args[0]));

    if (errorCode)
    {
        SEND_ERROR(ctx, "connect (enter): 'fd'", errorCode);
        return 0;
    }

    const uint64_t addrlen = BPF_CORE_READ(ctx, args[2]);

    if ((0 == addrlen) || (addrlen > 0xFFFF))
    {
        SEND_ERROR(
            ctx,
            "connect (enter): read 'addrlen'",
            EBPF_ERR_PROBE_READ_FAILED);

        return 0;
    }

    errorCode = AddParameterU64(event, tepid_addressLength, addrlen);

    if (errorCode)
    {
        SEND_ERROR(ctx, "connect (enter): 'addrlen'", errorCode);
        return 0;
    }

    errorCode = AddParameter(
            event,
            tepid_socketAddress,
            tept_rawData,
            (const uint16_t) addrlen,
            (const void*) BPF_CORE_READ(ctx, args[1]));

    if (errorCode)
    {
        SEND_ERROR(ctx, "connect (enter): 'addr'", errorCode);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL v2";
