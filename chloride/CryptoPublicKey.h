/*
** CryptoPublicKey.h
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
** You should have received a copy of the Lesser GNU General Public
** License along with libchloride.  If not, see
** <http://www.gnu.org/licenses/>.
*/

#ifndef CHLORIDE_CRYPTOPUBLICKEY_H_
#define CHLORIDE_CRYPTOPUBLICKEY_H_

#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_box_curve25519xsalsa20poly1305.h>
#include <sodium/crypto_scalarmult_curve25519.h>

#include "CryptoSecretKey.h"

namespace Crypto {
/*
 * Public Key.
 */
template <Operation O> class PublicKey {
    static_assert(OperationTraits<O>::PublicKeySize > 0, "Illegal PublicKey type!");
public:
    constexpr static Operation 				Oper		{ O };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::PublicKeySize };

    PublicKey() noexcept = default;
    explicit PublicKey(unsigned char* raw_) noexcept		{ std::copy_n(raw_, Size, _bytes); }
    template <typename I> PublicKey(I begin_, I end_)
    {
	if(static_cast<std::size_t>(end_ - begin_) != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, _bytes);
    }
    explicit PublicKey(const std::string& s_)
	: PublicKey(s_.begin(), s_.end())
    {}

    bool operator == (const PublicKey& pk_) const noexcept	{ return ::sodium_memcmp(_bytes, pk_._bytes, Size) == 0; }
    bool operator != (const PublicKey& pk_) const noexcept	{ return ::sodium_memcmp(_bytes, pk_._bytes, Size) != 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

private:
    unsigned char					_bytes[Size];
};

/*
 * Public/secret key pair.
 */
template <Operation O> class KeyPair {
    static_assert(OperationTraits<O>::SecretKeySize > 0 && OperationTraits<O>::PublicKeySize > 0, "Illegal KeyPair type!");
public:
    constexpr static Operation 				Oper		{ O };

    typedef SecretKey<Oper>		SecretKeyType;
    typedef PublicKey<Oper>		PublicKeyType;
    typedef Seed<Oper>			SeedType;

    PublicKeyType					publicKey;
    SecretKeyType					secretKey;

    KeyPair() = default;
    KeyPair(Tag::GenerateTag)
    {
	switch(Oper) {
	case Operation::BoxCurve25519Xsalsa20Poly1305:
	    if(::crypto_box_curve25519xsalsa20poly1305_keypair(publicKey.begin(), secretKey.begin()))
		throw Exception(Exception::KeyGenMsg);
	    break;
	case Operation::SignEd25519:
	    if(::crypto_sign_ed25519_keypair(publicKey.begin(), secretKey.begin()))
		throw Exception(Exception::KeyGenMsg);
	    break;
	case Operation::DiffieHellmanCurve25519:
	    ::randombytes_buf(secretKey.begin(), SecretKeyType::Size);
	    if(::crypto_scalarmult_curve25519_base(publicKey.begin(), secretKey.begin()))
		throw Exception(Exception::KeyGenMsg);
	    break;
	default:
	    throw Exception(Exception::ImplMsg);
	}
    }
    KeyPair(const SeedType& s_)
    {
	switch(Oper) {
	case Operation::BoxCurve25519Xsalsa20Poly1305:
	    if(::crypto_box_curve25519xsalsa20poly1305_seed_keypair(publicKey.begin(), secretKey.begin(), s_.begin()))
		throw Exception(Exception::KeyGenMsg);
	    break;
	case Operation::SignEd25519:
	    if(::crypto_sign_ed25519_seed_keypair(publicKey.begin(), secretKey.begin(), s_.begin()))
		throw Exception(Exception::KeyGenMsg);
	    break;
	case Operation::DiffieHellmanCurve25519:
	    secretKey= s_;
	    if(::crypto_scalarmult_curve25519_base(publicKey.begin(), secretKey.begin()))
		throw Exception(Exception::KeyGenMsg);
	    break;
	default:
	    throw Exception(Exception::ImplMsg);
	}
    }
    KeyPair(const PublicKeyType& pk_, const SecretKeyType& sk_)
	: publicKey	{ pk_ }
	, secretKey	{ sk_ }
    {}
    KeyPair(const unsigned char* pk_, const unsigned char* sk_)
	: publicKey	{ pk_ }
	, secretKey	{ sk_ }
    {}
    template <typename I, typename J> KeyPair(I pbegin_, I pend_, J sbegin_, J send_)
	: publicKey	{ pbegin_, pend_ }
	, secretKey	{ sbegin_, send_ }
    {}
    KeyPair(const std::string& pk_, const std::string& sk_)
	: KeyPair(pk_.begin(), pk_.end(), sk_.begin(), sk_.end())
    {}
    KeyPair(const KeyPair&) = default;
    KeyPair(KeyPair&&) = delete;

    KeyPair& operator = (const KeyPair&) noexcept = default;
    KeyPair& operator = (KeyPair&&) = delete;

    bool operator == (const KeyPair& kp_) const noexcept
    {
	const bool publicEqual { publicKey == kp_.publicKey };
	const bool secretEqual { secretKey == kp_.secretKey };
	return publicEqual && secretEqual;
    }
    bool operator != (const KeyPair& kp_) const noexcept
    {
	const bool publicUnequal { publicKey != kp_.publicKey };
	const bool secretUnequal { secretKey != kp_.secretKey };
	return publicUnequal || secretUnequal;
    }

    void clear() noexcept
    {
	publicKey.clear();
	secretKey.clear();
    }
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOPUBLICKEY_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
