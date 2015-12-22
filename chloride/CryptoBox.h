/*
** CryptoBox.h
**
**  Created on: Dec 12, 2015
**      Author: gv
*/

#ifndef CHLORIDE_CRYPTOBOX_H_
#define CHLORIDE_CRYPTOBOX_H_

#include <sodium/crypto_box_curve25519xsalsa20poly1305.h>
#include <sodium/crypto_secretbox_xsalsa20poly1305.h>

#include "CryptoPublicKey.h"
#include "CryptoNonce.h"

namespace Crypto {
/*
 * Traits for defined Operations.
 */
template <> struct OperationTraits<Operation::BoxCurve25519Xsalsa20Poly1305> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ true };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES };
    constexpr static std::size_t	SeedSize			{ crypto_box_curve25519xsalsa20poly1305_SEEDBYTES };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_box_curve25519xsalsa20poly1305_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 8 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
    constexpr static std::size_t	ClearPadSize			{ crypto_box_curve25519xsalsa20poly1305_ZEROBYTES };
    constexpr static std::size_t	CypherPadSize			{ crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES };
    constexpr static std::size_t	IntermediateSize		{ crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES };
};
template <> struct OperationTraits<Operation::SecretBoxXsalsa20Poly1305> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ true };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_secretbox_xsalsa20poly1305_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_secretbox_xsalsa20poly1305_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 8 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
    constexpr static std::size_t	ClearPadSize			{ crypto_secretbox_xsalsa20poly1305_ZEROBYTES };
    constexpr static std::size_t	CypherPadSize			{ crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES };
};

/*
 * BoxSealer.
 */
template <Operation O, std::size_t = OperationTraits<O>::NonceDefaultSequentialSize, typename = void> class BoxSealer {
    static_assert(OperationTraits<O>::HasBox || OperationTraits<O>::HasSecretBox, "Illegal BoxSealer type!");
};

template <Operation O, std::size_t S> class BoxSealer<O, S, typename std::enable_if<OperationTraits<O>::HasBox>::type> {
public:
    constexpr static Operation 				Oper			{ O };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			Size			{ OperationTraits<Oper>::IntermediateSize };
    constexpr static std::size_t			ClearPadSize		{ OperationTraits<Oper>::ClearPadSize };
    constexpr static std::size_t			CypherPadSize		{ OperationTraits<Oper>::CypherPadSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef PublicKey<Oper>					PublicKeyType;
    typedef KeyPair<Oper>					KeyPairType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;

    BoxSealer(const PublicKeyType& pk_, const SecretKeyBaseType& sk_, NonceType& n_)
	: nonce		{ n_ }
    {
	if(::sodium_mlock(_bytes, Size))
	    throw Exception(Exception::LockMsg);
	::crypto_box_curve25519xsalsa20poly1305_beforenm(_bytes, pk_.begin(), sk_.begin());
    }
    BoxSealer(const BoxSealer&) = delete;
    BoxSealer(BoxSealer&&) = delete;
    ~BoxSealer() noexcept					{ ::sodium_munlock(_bytes, Size); }

    BoxSealer& operator = (const BoxSealer&) = delete;
    BoxSealer& operator = (BoxSealer&&) = delete;

    std::string operator () (const std::string& message_)
    {
	std::string padded(ClearPadSize, '\0');
	padded+= message_;
	std::string result(padded.length(), '\0');
	::crypto_box_curve25519xsalsa20poly1305_afternm(reinterpret_cast<unsigned char*>(&result[0]),
							reinterpret_cast<unsigned char*>(&padded[0]),
							padded.length(), nonce.begin(), _bytes);
	++nonce;
	return result.substr(CypherPadSize);
    }

private:
    unsigned char					_bytes[Size];
};

template <Operation O, std::size_t S> class BoxSealer<O, S, typename std::enable_if<OperationTraits<O>::HasSecretBox>::type> {
public:
    constexpr static Operation 				Oper			{ O };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			ClearPadSize		{ OperationTraits<Oper>::ClearPadSize };
    constexpr static std::size_t			CypherPadSize		{ OperationTraits<Oper>::CypherPadSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;
    const SecretKeyBaseType&				secretKey;

    BoxSealer(const SecretKeyBaseType& sk_, NonceType& n_) noexcept
	: nonce		{ n_ }
	, secretKey	{ sk_ }
    {}
    BoxSealer(const BoxSealer&) = delete;
    BoxSealer(BoxSealer&&) = delete;

    BoxSealer& operator = (const BoxSealer&) = delete;
    BoxSealer& operator = (BoxSealer&&) = delete;

    std::string operator () (const std::string& message_)
    {
	std::string padded(ClearPadSize, '\0');
	padded+= message_;
	std::string result(padded.length(), '\0');
	::crypto_secretbox_xsalsa20poly1305(reinterpret_cast<unsigned char*>(&result[0]),
					    reinterpret_cast<unsigned char*>(&padded[0]),
					    padded.length(), nonce.begin(), secretKey.begin());
	++nonce;
	return result.substr(CypherPadSize);
    }
};

/*
 * BoxOpener.
 */
template <Operation O, std::size_t = OperationTraits<O>::NonceDefaultSequentialSize, typename = void> class BoxOpener {
    static_assert(OperationTraits<O>::HasBox || OperationTraits<O>::HasSecretBox, "Illegal BoxOpener type!");
};

template <Operation O, std::size_t S> class BoxOpener<O, S, typename std::enable_if<OperationTraits<O>::HasBox>::type> {
public:
    constexpr static Operation 				Oper			{ O };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			Size			{ OperationTraits<Oper>::IntermediateSize };
    constexpr static std::size_t			ClearPadSize		{ OperationTraits<Oper>::ClearPadSize };
    constexpr static std::size_t			CypherPadSize		{ OperationTraits<Oper>::CypherPadSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef PublicKey<Oper>					PublicKeyType;
    typedef KeyPair<Oper>					KeyPairType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;

    BoxOpener(const PublicKeyType& pk_, const SecretKeyBaseType& sk_, NonceType& n_)
	: nonce		{ n_ }
    {
	if(::sodium_mlock(_bytes, Size))
	    throw Exception(Exception::LockMsg);
	::crypto_box_curve25519xsalsa20poly1305_beforenm(_bytes, pk_.begin(), sk_.begin());
    }
    BoxOpener(const BoxOpener&) = delete;
    BoxOpener(BoxOpener&&) = delete;
    ~BoxOpener() noexcept					{ ::sodium_munlock(_bytes, Size); }

    BoxOpener& operator = (const BoxOpener&) = delete;
    BoxOpener& operator = (BoxOpener&&) = delete;

    std::string operator () (const std::string& cypher_)
    {
	std::string padded(CypherPadSize, '\0');
	padded+= cypher_;
	std::string result(padded.length(), '\0');
	if(::crypto_box_curve25519xsalsa20poly1305_open_afternm(reinterpret_cast<unsigned char*>(&result[0]),
								reinterpret_cast<unsigned char*>(&padded[0]),
								padded.length(), nonce.begin(), _bytes))
	    throw VerificationError();
	++nonce;
	return result.substr(ClearPadSize);
    }

private:
    unsigned char					_bytes[Size];
};

template <Operation O, std::size_t S> class BoxOpener<O, S, typename std::enable_if<OperationTraits<O>::HasSecretBox>::type> {
public:
    constexpr static Operation 				Oper			{ O };
    constexpr static std::size_t			NonceSequentialSize	{ S };
    constexpr static std::size_t			ClearPadSize		{ OperationTraits<Oper>::ClearPadSize };
    constexpr static std::size_t			CypherPadSize		{ OperationTraits<Oper>::CypherPadSize };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;
    const SecretKeyBaseType&				secretKey;

    BoxOpener(const SecretKeyBaseType& sk_, NonceType& n_) noexcept
	: nonce		{ n_ }
	, secretKey	{ sk_ }
    {}
    BoxOpener(const BoxOpener&) = delete;
    BoxOpener(BoxOpener&&) = delete;

    BoxOpener& operator = (const BoxOpener&) = delete;
    BoxOpener& operator = (BoxOpener&&) = delete;

    std::string operator () (const std::string& cypher_)
    {
	std::string padded(CypherPadSize, '\0');
	padded+= cypher_;
	std::string result(padded.length(), '\0');
	if(::crypto_secretbox_xsalsa20poly1305_open(reinterpret_cast<unsigned char*>(&result[0]),
						    reinterpret_cast<unsigned char*>(&padded[0]),
						    padded.length(), nonce.begin(), secretKey.begin()))
	    throw VerificationError();
	++nonce;
	return result.substr(ClearPadSize);
    }
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOBOX_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
