//
//  IOSEntropySource.hpp
//  DataGateVPNExtension
//
//  Custom entropy source for OpenVPN3 using iOS SecRandomCopyBytes
//  This provides a reliable entropy source for Network Extensions
//

#ifndef IOS_ENTROPY_SOURCE_HPP
#define IOS_ENTROPY_SOURCE_HPP

#include <Security/SecRandom.h>
#include <openvpn/random/randapi.hpp>

namespace openvpn {

class IOSEntropySource : public StrongRandomAPI
{
public:
    OPENVPN_EXCEPTION(ios_entropy_error);
    
    typedef RCPtr<IOSEntropySource> Ptr;
    
    std::string name() const override
    {
        return "IOSEntropySource";
    }
    
    // Fill buffer with random bytes
    void rand_bytes(unsigned char *buf, size_t size) override
    {
        if (!rndbytes(buf, size))
            throw ios_entropy_error("rand_bytes failed");
    }
    
    // Like rand_bytes, but don't throw exception.
    // Return true on success, false on fail.
    bool rand_bytes_noexcept(unsigned char *buf, size_t size) override
    {
        return rndbytes(buf, size);
    }
    
private:
    bool rndbytes(unsigned char *buf, size_t size)
    {
        // SecRandomCopyBytes returns errSecSuccess (0) on success
        // Return true if successful, false otherwise
        return SecRandomCopyBytes(kSecRandomDefault, size, buf) == errSecSuccess;
    }
};

} // namespace openvpn

#endif /* IOS_ENTROPY_SOURCE_HPP */
