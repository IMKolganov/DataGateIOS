//
//  in6_var.h
//  DataGateVPNExtension
//
//  Stub header for netinet6/in6_var.h on iOS (not available in iOS SDK)
//

#ifndef NETINET6_IN6_VAR_H
#define NETINET6_IN6_VAR_H

#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
// iOS doesn't have netinet6/in6_var.h - provide minimal stub
// This file is only included when compiling Mac-specific code on iOS
// The actual MacGatewayInfo code should not be used on iOS

#include <netinet/in.h>

// Minimal stub definitions - actual implementation not needed on iOS
struct in6_ifreq {
    struct in6_addr ifr6_addr;
    uint32_t ifr6_prefixlen;
    int ifr6_ifindex;
};

#endif // TARGET_OS_IPHONE
#endif // __APPLE__

#endif // NETINET6_IN6_VAR_H
