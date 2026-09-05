/*
 * Single-producer/single-consumer byte-frame ring shared between the Mantis
 * process (producer, writes from its XSK receive loop) and this Suricata
 * capture plugin (consumer, runs inside the suricata process).
 *
 * The backing memory is a memfd created by Mantis and inherited by the
 * suricata child process across fork+exec (same trick already used in
 * mantis/src/detection/suricata/engine.rs for the yaml config and suppress
 * file). Mantis passes the inherited fd number to the plugin via
 * --capture-plugin-args; the plugin mmaps that same fd and both sides then
 * see the same physical pages.
 *
 * This header has no Suricata dependencies on purpose: it is the single
 * source of truth for the wire layout and must be mirrored byte-for-byte
 * on the Rust side (repr(C) struct with the same field order/padding).
 *
 * Layout of the mmap'd region:
 *   [MantisRingHeader][slot 0][slot 1]...[slot capacity-1]
 * where each slot is `slot_size` bytes: a 4-byte little-endian length
 * prefix followed by up to (slot_size - 4) bytes of frame data.
 *
 * Invariants:
 *   - capacity MUST be a power of two (index wraparound uses a mask).
 *   - capacity and slot_size are set once by the producer before the
 *     consumer attaches and never change afterwards.
 *   - Exactly one producer and one consumer per ring. `head` is only ever
 *     written by the producer, `tail` only by the consumer; each side only
 *     reads the other's index.
 *   - On a full ring the producer drops the frame (no blocking, no
 *     overwrite) -- same drop-and-count policy as the current
 *     crossbeam bounded channel it replaces.
 */

#ifndef MANTIS_RING_H
#define MANTIS_RING_H

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/* Arbitrary sentinel written by the producer so the consumer can detect an
 * unmapped / zeroed / mismatched region instead of reading garbage as a
 * valid header. */
#define MANTIS_RING_MAGIC 0x4d414e544953524bULL

typedef struct MantisRingHeader_ {
    uint64_t magic;
    uint32_t capacity;  /* number of slots, power of two */
    uint32_t slot_size; /* bytes per slot, including the 4-byte length prefix */
    _Atomic uint32_t head; /* producer-owned: next slot index to write */
    uint8_t _pad0[60];     /* cacheline padding to keep head/tail apart */
    _Atomic uint32_t tail; /* consumer-owned: next slot index to read */
    uint8_t _pad1[60];
} MantisRingHeader;

static inline uint64_t MantisRingTotalSize(uint32_t capacity, uint32_t slot_size) {
    return (uint64_t)sizeof(MantisRingHeader) + (uint64_t)capacity * (uint64_t)slot_size;
}

static inline uint8_t *MantisRingSlotPtr(MantisRingHeader *hdr, uint32_t index) {
    uint8_t *base = (uint8_t *)hdr + sizeof(MantisRingHeader);
    return base + (uint64_t)(index & (hdr->capacity - 1)) * hdr->slot_size;
}

/* Consumer side. Returns 1 and fills `out`/`out_len` on success, 0 if the
 * ring is currently empty. `out` must be at least (hdr->slot_size - 4)
 * bytes; the caller (source.c) sizes it from hdr->slot_size once at
 * thread init, after validating the header. */
static inline int MantisRingPop(MantisRingHeader *hdr, uint8_t *out, uint32_t *out_len) {
    uint32_t tail = atomic_load_explicit(&hdr->tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&hdr->head, memory_order_acquire);
    if (tail == head) {
        return 0; /* empty */
    }

    uint8_t *slot = MantisRingSlotPtr(hdr, tail);
    uint32_t len;
    memcpy(&len, slot, sizeof(len));
    uint32_t max_len = hdr->slot_size - (uint32_t)sizeof(len);
    if (len > max_len) {
        len = max_len; /* defensive clamp; a well-behaved producer never triggers this */
    }
    memcpy(out, slot + sizeof(len), len);
    *out_len = len;

    atomic_store_explicit(&hdr->tail, tail + 1, memory_order_release);
    return 1;
}

/* Producer side. Returns 1 on success, 0 if the ring is full (caller
 * should drop the frame and count it, never block). */
static inline int MantisRingPush(MantisRingHeader *hdr, const uint8_t *data, uint32_t len) {
    uint32_t head = atomic_load_explicit(&hdr->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&hdr->tail, memory_order_acquire);
    if (head - tail >= hdr->capacity) {
        return 0; /* full */
    }

    uint32_t max_len = hdr->slot_size - (uint32_t)sizeof(uint32_t);
    if (len > max_len) {
        len = max_len; /* defensive clamp; callers should size slots for their MTU */
    }
    uint8_t *slot = MantisRingSlotPtr(hdr, head);
    memcpy(slot, &len, sizeof(len));
    memcpy(slot + sizeof(len), data, len);

    atomic_store_explicit(&hdr->head, head + 1, memory_order_release);
    return 1;
}

/* Sanity-check a freshly mmap'd header before trusting capacity/slot_size
 * to compute offsets. `mapped_size` is the fstat()'d size of the fd. */
static inline int MantisRingValidate(const MantisRingHeader *hdr, uint64_t mapped_size) {
    if (hdr->magic != MANTIS_RING_MAGIC) {
        return 0;
    }
    if (hdr->capacity == 0 || (hdr->capacity & (hdr->capacity - 1)) != 0) {
        return 0; /* not a power of two */
    }
    if (hdr->slot_size <= sizeof(uint32_t)) {
        return 0; /* no room for payload past the length prefix */
    }
    if (MantisRingTotalSize(hdr->capacity, hdr->slot_size) != mapped_size) {
        return 0; /* fd size doesn't match what the header claims */
    }
    return 1;
}

#endif /* MANTIS_RING_H */
