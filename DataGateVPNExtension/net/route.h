//
//  route.h
//  DataGateVPNExtension
//
//  Stub header for net/route.h on iOS (not available in iOS SDK)
//

#ifndef NET_ROUTE_H
#define NET_ROUTE_H

#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
// iOS doesn't have net/route.h - provide minimal stub
// This file is only included when compiling Mac-specific code on iOS
// The actual MacGatewayInfo code should not be used on iOS
#define RTM_VERSION 1
#define RTM_GET 1
#define RTF_UP 0x1
#define RTA_DST 0x1
#define RTA_GATEWAY 0x2
#define RTA_IFP 0x4

// Define rt_metrics first since rt_msghdr uses it
struct rt_metrics {
    unsigned int rmx_locks;
    unsigned int rmx_mtu;
    unsigned int rmx_hopcount;
    unsigned int rmx_expire;
    unsigned int rmx_recvpipe;
    unsigned int rmx_sendpipe;
    unsigned int rmx_ssthresh;
    unsigned int rmx_rtt;
    unsigned int rmx_rttvar;
};

struct rt_msghdr {
    unsigned short rtm_msglen;
    unsigned char rtm_version;
    unsigned char rtm_type;
    unsigned short rtm_index;
    int rtm_flags;
    int rtm_addrs;
    int rtm_pid;
    int rtm_seq;
    int rtm_errno;
    int rtm_use;
    unsigned int rtm_inits;
    struct rt_metrics rtm_rmx;
};

#endif // TARGET_OS_IPHONE
#endif // __APPLE__

#endif // NET_ROUTE_H
