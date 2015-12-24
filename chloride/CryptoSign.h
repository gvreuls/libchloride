/*
** CryptoSign.h
**
**  Created on: Dec 12, 2015
**      Author: gv
**
** This file is part of libchloride.
** Copyright (C) 2015 Guy Vreuls
**
** Libchloride is free software: you can redistribute it and/or modify
** it under the terms of the GNU Lesser General Public License as
** published by the Free Software Foundation, either version 2.1 of
** the License, or (at your option) any later version.
**
** Libchloride is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU Lesser General Public License for more details.
**
** You should have received a copy of the GNU Lesser General Public
** License along with libchloride.  If not, see
** <http://www.gnu.org/licenses/>.
*/

#ifndef CHLORIDE_CRYPTOSIGN_H_
#define CHLORIDE_CRYPTOSIGN_H_

#include <sodium/crypto_sign_ed25519.h>

#include "CryptoBox.h"

namespace Crypto {
/*
 * Traits for defined Operations.
 */
template <> struct OperationTraits<Operation::SignEd25519> {
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
    constexpr static std::size_t	SecretKeySize			{ crypto_sign_ed25519_SECRETKEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ crypto_sign_ed25519_PUBLICKEYBYTES };
    constexpr static std::size_t	SeedSize			{ crypto_sign_ed25519_SEEDBYTES };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ crypto_sign_ed25519_BYTES };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};

/*
 * Signature.
 */
template <Operation O> class Signature {
    static_assert(OperationTraits<O>::SignatureSize > 0, "Illegal Signature type!");
public:
    constexpr static Operation				Oper		{ O };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::SignatureSize };

    typedef SecretKey<Oper>					SecretKeyType;
    typedef PublicKey<Oper>					PublicKeyType;
    typedef KeyPair<Oper>					KeyPairType;
    typedef Seed<Oper>						SeedType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    Signature() noexcept = default;
    explicit Signature(const unsigned char* raw_) noexcept	{ std::copy_n(raw_, Size, _bytes); }
    template <typename I> Signature(I begin_, I end_)
    {
	if(static_cast<std::size_t>(end_ - begin_) != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, _bytes);
    }
    explicit Signature(const std::string& s_)
	: Signature(s_.begin(), s_.end())
    {}
    Signature(const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) noexcept
    {
	unsigned long long sl;
	::crypto_sign_ed25519_detached(_bytes, &sl, p_, n_, sk_.begin());
    }
    Signature(const SecretKeyBaseType& sk_, const unsigned char* begin_, const unsigned char* end_) noexcept
	: Signature(sk_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}
    Signature(const SecretKeyBaseType& sk_, const std::string& s_) noexcept
	: Signature(sk_, reinterpret_cast<const unsigned char*>(&s_[0]), s_.length())
    {}

    bool operator == (const Signature& s_) const noexcept	{ return ::sodium_memcmp(_bytes, s_._bytes, Size) != 0; }
    bool operator != (const Signature& s_) const noexcept	{ return ::sodium_memcmp(_bytes, s_._bytes, Size) != 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

    void operator () (const PublicKeyType& pk_, const unsigned char* p_, std::size_t n_) const
    {
	if(::crypto_sign_ed25519_verify_detached(_bytes, p_, n_, pk_.begin()))
	    throw VerificationError();
    }
    void operator () (const PublicKeyType& pk_, const unsigned char* begin_, const unsigned char* end_) const
    {
	operator()(pk_, begin_, static_cast<std::size_t>(end_ - begin_));
    }
    void operator () (const PublicKeyType& pk_, const std::string& s_) const
    {
	operator()(pk_, reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
    }

private:
    unsigned char					_bytes[Size];
};

/*
 * All in one signing. Signing/verification happens in place because NaCl/Sodium wants it this way.
 */
inline void signSeal(const SecretKeyBase<OperationTraits<Operation::SignEd25519>::SecretKeySize>& sk_, std::string& message_)
{
    const std::size_t len { message_.length() };
    message_.resize(len + OperationTraits<Operation::Sign>::SignatureSize);
    unsigned long long rl;
    ::crypto_sign_ed25519(reinterpret_cast<unsigned char*>(&message_[0]), &rl,
			  reinterpret_cast<unsigned char*>(&message_[0]), len,
			  sk_.begin());
    message_.resize(rl);
}
inline void signOpen(const PublicKey<Operation::SignEd25519>& pk_, std::string& message_)
{
    if(message_.length() < OperationTraits<Operation::SignEd25519>::SignatureSize)
	throw VerificationError();
    unsigned long long rl;
    if(::crypto_sign_ed25519_open(reinterpret_cast<unsigned char*>(&message_[0]), &rl,
				  reinterpret_cast<unsigned char*>(&message_[0]), message_.length(),
				  pk_.begin()))
	throw VerificationError();
    message_.resize(rl);
}

/*
 * Helper functions.
 */
inline void extractKey(const SecretKey<Operation::SignEd25519>& sk_, PublicKey<Operation::SignEd25519>& pk_) noexcept
{
    ::crypto_sign_ed25519_sk_to_pk(pk_.begin(), sk_.begin());
}
inline void extractSeed(const SecretKey<Operation::SignEd25519>& sk_, Seed<Operation::SignEd25519>& s_) noexcept
{
    ::crypto_sign_ed25519_sk_to_seed(s_.begin(), sk_.begin());
}

inline void convertKeyPair(const KeyPair<Operation::SignEd25519>& signKeys_,
			   KeyPair<Operation::BoxCurve25519Xsalsa20Poly1305>& boxKeys_) noexcept
{
    ::crypto_sign_ed25519_pk_to_curve25519(boxKeys_.publicKey.begin(), signKeys_.publicKey.begin());
    ::crypto_sign_ed25519_sk_to_curve25519(boxKeys_.secretKey.begin(), signKeys_.secretKey.begin());
}

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOSIGN_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
