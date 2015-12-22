/*
** CryptoAuthEncAdData.h
**
**  Created on: Dec 20, 2015
**      Author: gv
*/

#ifndef CHLORIDE_CRYPTOAUTHENCADDATA_H_
#define CHLORIDE_CRYPTOAUTHENCADDATA_H_

#include <sodium/crypto_aead_aes256gcm.h>
#include <sodium/crypto_aead_chacha20poly1305.h>

#include "CryptoSecretKey.h"
#include "CryptoNonce.h"

namespace Crypto {
/*
 * Traits for defined Operations.
 */
template <> struct OperationTraits<Operation::AuthEncAdDataAes256Gcm> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_aead_aes256gcm_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_aead_aes256gcm_NPUBBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ crypto_aead_aes256gcm_ABYTES };
};
template <> struct OperationTraits<Operation::AuthEncAdDataChacha20Poly1305> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_aead_chacha20poly1305_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_aead_chacha20poly1305_NPUBBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ crypto_aead_chacha20poly1305_ABYTES };
};
template <> struct OperationTraits<Operation::AuthEncAdDataChacha20Poly1305Ietf> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_aead_chacha20poly1305_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_aead_chacha20poly1305_IETF_NPUBBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ crypto_aead_chacha20poly1305_ABYTES };
};

/*
 * AuthEncAdDataSealer.
 */
template <Operation O, std::size_t S = OperationTraits<O>::NonceDefaultSequentialSize> class AuthEncAdDataSealer {
    static_assert(OperationTraits<O>::AuthEncAdDataSize > 0, "Illegal AuthEncAdDataSealer type!");
public:
    constexpr static Operation 				Oper			{ O };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			PadSize			{ OperationTraits<Oper>::AuthEncAdDataSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;
    const SecretKeyBaseType&				secretKey;

    AuthEncAdDataSealer(const SecretKeyBaseType& sk_, NonceType& n_) noexcept
	: nonce		{ n_ }
	, secretKey	{ sk_ }
    {}
    AuthEncAdDataSealer(const AuthEncAdDataSealer&) = delete;
    AuthEncAdDataSealer(AuthEncAdDataSealer&&) = delete;

    AuthEncAdDataSealer& operator = (const AuthEncAdDataSealer&) = delete;
    AuthEncAdDataSealer& operator = (AuthEncAdDataSealer&&) = delete;

    std::string operator () (const std::string& message_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(), nullptr, 0);
    }
    std::string operator () (const std::string& message_, const std::string& data_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(),
		     reinterpret_cast<const unsigned char*>(&data_[0]), data_.length());
    }

private:
    std::string _oper(const unsigned char* mP_, std::size_t mN_, const unsigned char* dP_,std::size_t dN_)
    {
	std::string result(mN_ + PadSize, '\0');
	unsigned long long rl;
	switch(Oper) {
	case Operation::AuthEncAdDataChacha20Poly1305:
	    ::crypto_aead_chacha20poly1305_encrypt(reinterpret_cast<unsigned char*>(&result[0]), &rl, mP_, mN_,
						   dP_, dN_, nullptr, nonce.begin(), secretKey.begin());
	    break;
	case Operation::AuthEncAdDataChacha20Poly1305Ietf:
	    ::crypto_aead_chacha20poly1305_ietf_encrypt(reinterpret_cast<unsigned char*>(&result[0]), &rl, mP_, mN_,
							dP_, dN_, nullptr, nonce.begin(), secretKey.begin());
	    break;
	default:
	    throw Exception(Exception::ImplMsg);
	}
	result.resize(rl);
	++nonce;
	return result;
    }
};

template <std::size_t S> class AuthEncAdDataSealer<Operation::AuthEncAdDataAes256Gcm, S> {
public:
    constexpr static Operation 				Oper			{ Operation::AuthEncAdDataAes256Gcm };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			PadSize			{ OperationTraits<Oper>::AuthEncAdDataSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;

    AuthEncAdDataSealer(const SecretKeyBaseType& sk_, NonceType& n_) noexcept
	: nonce		{ n_ }
    {
	if(::sodium_mlock(_state, sizeof(::crypto_aead_aes256gcm_state)))
	    throw Exception(Exception::LockMsg);
	::crypto_aead_aes256gcm_beforenm(&_state, sk_.begin());
    }
    AuthEncAdDataSealer(const AuthEncAdDataSealer&) = delete;
    AuthEncAdDataSealer(AuthEncAdDataSealer&&) = delete;
    ~AuthEncAdDataSealer() noexcept
    {
	::sodium_munlock(_state, sizeof(::crypto_aead_aes256gcm_state));
    }

    AuthEncAdDataSealer& operator = (const AuthEncAdDataSealer&) = delete;
    AuthEncAdDataSealer& operator = (AuthEncAdDataSealer&&) = delete;

    std::string operator () (const std::string& message_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(), nullptr, 0);
    }
    std::string operator () (const std::string& message_, const std::string& data_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(),
		     reinterpret_cast<const unsigned char*>(&data_[0]), data_.length());
    }

private:
    ::crypto_aead_aes256gcm_state			_state;

    std::string _oper(const unsigned char* mP_, std::size_t mN_, const unsigned char* dP_,std::size_t dN_)
    {
	std::string result(mN_ + PadSize, '\0');
	unsigned long long rl;
	::crypto_aead_aes256gcm_encrypt_afternm(reinterpret_cast<unsigned char*>(&result[0]), &rl, mP_, mN_,
						dP_, dN_, nullptr, nonce.begin(), &_state);
	result.resize(rl);
	++nonce;
	return result;
    }
};

/*
 * AuthEncAdDataOpener.
 */
template <Operation O, std::size_t S = OperationTraits<O>::NonceDefaultSequentialSize> class AuthEncAdDataOpener {
    static_assert(OperationTraits<O>::AuthEncAdDataSize > 0, "Illegal AuthEncAdDataOpener type!");
public:
    constexpr static Operation 				Oper			{ O };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			PadSize			{ OperationTraits<Oper>::AuthEncAdDataSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;
    const SecretKeyBaseType&				secretKey;

    AuthEncAdDataOpener(const SecretKeyBaseType& sk_, NonceType& n_) noexcept
	: nonce		{ n_ }
	, secretKey	{ sk_ }
    {}
    AuthEncAdDataOpener(const AuthEncAdDataOpener&) = delete;
    AuthEncAdDataOpener(AuthEncAdDataOpener&&) = delete;

    AuthEncAdDataOpener& operator = (const AuthEncAdDataOpener&) = delete;
    AuthEncAdDataOpener& operator = (AuthEncAdDataOpener&&) = delete;

    std::string operator () (const std::string& message_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(), nullptr, 0);
    }
    std::string operator () (const std::string& message_, const std::string& data_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(),
		     reinterpret_cast<const unsigned char*>(&data_[0]), data_.length());
    }

private:
    std::string _oper(const unsigned char* mP_, std::size_t mN_, const unsigned char* dP_,std::size_t dN_)
    {
	std::string result(mN_ + PadSize, '\0');
	unsigned long long rl;
	switch(Oper) {
	case Operation::AuthEncAdDataChacha20Poly1305:
	    if(::crypto_aead_chacha20poly1305_decrypt(reinterpret_cast<unsigned char*>(&result[0]), &rl, nullptr, mP_, mN_,
						      dP_, dN_, nonce.begin(), secretKey.begin()))
		throw VerificationError();
	    break;
	case Operation::AuthEncAdDataChacha20Poly1305Ietf:
	    if(::crypto_aead_chacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char*>(&result[0]), &rl, nullptr, mP_, mN_,
							   dP_, dN_, nonce.begin(), secretKey.begin()))
		throw VerificationError();
	    break;
	default:
	    throw Exception(Exception::ImplMsg);
	}
	result.resize(rl);
	++nonce;
	return result;
    }
};

template <std::size_t S> class AuthEncAdDataOpener<Operation::AuthEncAdDataAes256Gcm, S> {
public:
    constexpr static Operation 				Oper			{ Operation::AuthEncAdDataAes256Gcm };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			PadSize			{ OperationTraits<Oper>::AuthEncAdDataSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;

    AuthEncAdDataOpener(const SecretKeyBaseType& sk_, NonceType& n_) noexcept
	: nonce		{ n_ }
    {
	if(::sodium_mlock(_state, sizeof(::crypto_aead_aes256gcm_state)))
	    throw Exception(Exception::LockMsg);
	::crypto_aead_aes256gcm_beforenm(&_state, sk_.begin());
    }
    AuthEncAdDataOpener(const AuthEncAdDataOpener&) = delete;
    AuthEncAdDataOpener(AuthEncAdDataOpener&&) = delete;
    ~AuthEncAdDataOpener() noexcept
    {
	::sodium_munlock(_state, sizeof(::crypto_aead_aes256gcm_state));
    }

    AuthEncAdDataOpener& operator = (const AuthEncAdDataOpener&) = delete;
    AuthEncAdDataOpener& operator = (AuthEncAdDataOpener&&) = delete;

    std::string operator () (const std::string& message_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(), nullptr, 0);
    }
    std::string operator () (const std::string& message_, const std::string& data_)
    {
	return _oper(reinterpret_cast<const unsigned char*>(&message_[0]), message_.length(),
		     reinterpret_cast<const unsigned char*>(&data_[0]), data_.length());
    }

private:
    ::crypto_aead_aes256gcm_state			_state;

    std::string _oper(const unsigned char* mP_, std::size_t mN_, const unsigned char* dP_,std::size_t dN_)
    {
	std::string result(mN_ + PadSize, '\0');
	unsigned long long rl;
	if(::crypto_aead_aes256gcm_decrypt_afternm(reinterpret_cast<unsigned char*>(&result[0]), &rl, nullptr, mP_, mN_,
						   dP_, dN_, nonce.begin(), &_state))
	    throw VerificationError();
	result.resize(rl);
	++nonce;
	return result;
    }
};

/*
 * Helper functions.
 */
inline bool Operation_AuthEncAdDataAes256Gcm_Available() noexcept
{
    return static_cast<bool>(::crypto_aead_aes256gcm_is_available());
}

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOAUTHENCADDATA_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
