#ifndef __COMMON_H
#define __COMMON_H

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#ifndef DEBUG
#define DEBUG 1
#endif

#define JHASH_INITVAL   0xdeadbeef
#define MAX_BACKENDS 3

#endif /* __COMMON_H */
