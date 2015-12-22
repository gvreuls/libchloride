/*
** CryptoDiffieHellman.h
**
**  Created on: Dec 13, 2015
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

#ifndef CHLORIDE_CRYPTODIFFIEHELLMAN_H_
#define CHLORIDE_CRYPTODIFFIEHELLMAN_H_

#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_generichash_blake2b.h>

#include "CryptoPublicKey.h"

namespace Crypto {
/*
 * Traits for defined Operations.
 */
template <> struct OperationTraits<Operation::DiffieHellmanCurve25519> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ true };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_scalarmult_curve25519_SCALARBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ crypto_scalarmult_curve25519_BYTES };
    constexpr static std::size_t	SeedSize			{ SecretKeySize };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
    constexpr static std::size_t	MaximumDiffieHellmanSize	{ crypto_generichash_blake2b_BYTES_MAX };
    constexpr static std::size_t	MinimumDiffieHellmanSize	{ crypto_generichash_blake2b_BYTES_MIN };
};

/*
 * DiffieHellman.
 */
template <Operation O, std::size_t S = OperationTraits<O>::SecretKeySize> class DiffieHellman: public SecretKeyBase<S> {
    static_assert(OperationTraits<O>::HasDiffieHellman, "Illegal DiffieHellman type!");
public:
    constexpr static Operation				Oper			{ O };
    constexpr static std::size_t			Size			{ S };
    constexpr static std::size_t			IntermediateSize	{ OperationTraits<Oper>::PublicKeySize };

    static_assert(   OperationTraits<Oper>::MinimumDiffieHellmanSize <= Size
		  && Size <= OperationTraits<Oper>::MaximumDiffieHellmanSize,
		  "Illegally sized DiffieHellman type!");

    typedef SecretKey<Oper>		SecretKeyType;
    typedef PublicKey<Oper>		PublicKeyType;
    typedef KeyPair<Oper>		KeyPairType;
    typedef Seed<Oper>			SeedType;

    DiffieHellman(const PublicKeyType& pk_, const KeyPairType& kp_)
	: SecretKeyBase<Size>()
    {
	_init<false>(pk_, kp_);
    }
    DiffieHellman(const PublicKeyType& pk_, const KeyPairType& kp_, Tag::SealerTag)
	: SecretKeyBase<Size>()
    {
	_init<true>(pk_, kp_);
    }

private:
    template <bool Sealer> void _init(const PublicKeyType& pk_, const KeyPairType& kp_)
    {
	unsigned char buffer[IntermediateSize];
	::crypto_scalarmult_curve25519(buffer, kp_.secretKey.begin(), pk_.begin());
	::crypto_generichash_blake2b_state state;
	::crypto_generichash_blake2b_init(&state, nullptr, 0, Size);
	::crypto_generichash_blake2b_update(&state, buffer, IntermediateSize);
	if(Sealer)
	{
	    ::crypto_generichash_blake2b_update(&state, pk_.begin(), pk_.Size);
	    ::crypto_generichash_blake2b_update(&state, kp_.publicKey.begin(), kp_.publicKey.Size);
	}
	else
	{
	    ::crypto_generichash_blake2b_update(&state, kp_.publicKey.begin(), kp_.publicKey.Size);
	    ::crypto_generichash_blake2b_update(&state, pk_.begin(), pk_.Size);
	}
	::crypto_generichash_blake2b_final(&state, SecretKeyBase<Size>::begin(), Size);
    }
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTODIFFIEHELLMAN_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
