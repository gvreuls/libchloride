/*
** CryptoStream.h
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

#ifndef CHLORIDE_CRYPTOSTREAM_H_
#define CHLORIDE_CRYPTOSTREAM_H_

#include <sodium/crypto_stream_aes128ctr.h>
#include <sodium/crypto_stream_salsa20.h>
#include <sodium/crypto_stream_salsa208.h>
#include <sodium/crypto_stream_salsa2012.h>
#include <sodium/crypto_stream_chacha20.h>
#include <sodium/crypto_stream_xsalsa20.h>

#include "CryptoSecretKey.h"
#include "CryptoNonce.h"

namespace Crypto {
/*
 * Traits for defined Operations.
 */
template <> struct OperationTraits<Operation::StreamAes128ctr> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ true };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_stream_aes128ctr_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_stream_aes128ctr_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::StreamSalsa20> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ true };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_stream_salsa20_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_stream_salsa20_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::StreamSalsa208> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ true };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_stream_salsa208_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_stream_salsa208_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::StreamSalsa2012> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ true };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_stream_salsa2012_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_stream_salsa2012_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::StreamChacha20> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ true };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_stream_chacha20_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_stream_chacha20_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ NonceSize / 2 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::StreamXsalsa20> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ true };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_stream_xsalsa20_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ crypto_stream_xsalsa20_NONCEBYTES };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 8 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};

/*
 * Streamer. Stream xoring happens in place because NaCl/sodium does it this way itself.
 */
constexpr std::size_t StreamerDefaultPadSize	{ 0x10000 };

template <Operation O, std::size_t S = StreamerDefaultPadSize, std::size_t NSS = OperationTraits<O>::NonceDefaultSequentialSize>
class Streamer {
    static_assert(OperationTraits<O>::HasStream, "Illegal Streamer type!");
public:
    constexpr static Operation				Oper			{ O };
    constexpr static std::size_t			NonceSequentialSize	{ NSS };
    constexpr static std::size_t			Size			{ S };

    typedef Nonce<Oper, NonceSequentialSize>			NonceType;
    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    NonceType&						nonce;
    const SecretKeyBaseType&				secretKey;

    Streamer(const SecretKeyBaseType& sk_, NonceType& n_) noexcept
	: nonce		{ n_ }
	, secretKey	{ sk_ }
	, _at		{ _bytes + Size }
    {}

    Streamer(const Streamer&) = delete;
    Streamer(Streamer&&) = delete;

    Streamer& operator = (const Streamer&) = delete;
    Streamer& operator = (Streamer&&) = delete;

    void operator () (std::string& messageOrCypher_)
    {
	auto i { messageOrCypher_.begin() };
	while(i != messageOrCypher_.end())
	{
	    for(const auto end { i +  std::min(messageOrCypher_.end() - i, _bytes + Size - _at) }; i != end; ++i, ++_at)
		*i^= *_at;
	    if(i != messageOrCypher_.end())
	    {
		switch(Oper) {
		case Operation::StreamAes128ctr:
		    ::crypto_stream_aes128ctr(reinterpret_cast<unsigned char*>(_bytes), Size, nonce.begin(), secretKey.begin());
		    break;
		case Operation::StreamSalsa20:
		    ::crypto_stream_salsa20(reinterpret_cast<unsigned char*>(_bytes), Size, nonce.begin(), secretKey.begin());
		    break;
		case Operation::StreamSalsa208:
		    ::crypto_stream_salsa208(reinterpret_cast<unsigned char*>(_bytes), Size, nonce.begin(), secretKey.begin());
		    break;
		case Operation::StreamSalsa2012:
		    ::crypto_stream_salsa2012(reinterpret_cast<unsigned char*>(_bytes), Size, nonce.begin(), secretKey.begin());
		    break;
		case Operation::StreamChacha20:
		    ::crypto_stream_chacha20(reinterpret_cast<unsigned char*>(_bytes), Size, nonce.begin(), secretKey.begin());
		    break;
		case Operation::StreamXsalsa20:
		    ::crypto_stream_xsalsa20(reinterpret_cast<unsigned char*>(_bytes), Size, nonce.begin(), secretKey.begin());
		    break;
		default:
		    throw Exception(Exception::ImplMsg);
		}
		_at= _bytes;
		++nonce;
	    }
	}
    }

private:
    char*						_at;
    char						_bytes[Size];
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOSTREAM_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
