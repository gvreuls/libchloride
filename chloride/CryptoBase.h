/*
** CryptoBase.h
**
**  Created on: Dec 9, 2015
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

#ifndef CHLORIDE_CRYPTOBASE_H_
#define CHLORIDE_CRYPTOBASE_H_

#include <sodium/version.h>
#if (SODIUM_LIBRARY_VERSION_MAJOR) < 7 || ((SODIUM_LIBRARY_VERSION_MAJOR) == 7 && (SODIUM_LIBRARY_VERSION_MINOR) < 6)
#error Chloride needs libsodium >= 7.6
#endif

#include "version.h"
#define CHLORIDE_QUOTE(name)		#name
#define CHLORIDE_STRINGIFY(macro)	CHLORIDE_QUOTE(macro)
#define CHLORIDE_VERSION		CHLORIDE_STRINGIFY(CHLORIDE_VERSION_MAJOR.CHLORIDE_VERSION_MINOR.CHLORIDE_VERSION_REVISION)

#include <sodium/core.h>
#include <sodium/utils.h>

#include <stdexcept>

namespace Crypto {
/*
 * Exceptions.
 */
class Exception: public std::runtime_error {
public:
    static const std::string	InitMsg;
    static const std::string	ImplMsg;
    static const std::string	SizeMsg;
    static const std::string	LockMsg;
    static const std::string	KeyGenMsg;
    static const std::string	OverflowMsg;
    static const std::string	FormatMsg;
    static const std::string	MemoryMsg;

    Exception(const std::string& what_) noexcept
	: std::runtime_error	{ what_ }
    {}
};
class VerificationError: public Exception {
public:
    static const std::string	VerifyMsg;

    VerificationError() noexcept
	: Exception		{ VerifyMsg }
    {}
};

/*
 * Tags.
 */
namespace Tag {
constexpr struct GenerateTag {}		Generate		{};
constexpr struct GenerateConstantTag {}	GenerateConstant	{};
constexpr struct SpecifyConstantTag {}	SpecifyConstant		{};
constexpr struct SealerTag {}		Sealer			{};
} // namespace Tag

/*
 * Supported cryptographic operations.
 */
enum class Operation {
    // All operations:							Defaults:
    HashSha256, HashSha512,						Hash =			HashSha512,
    ShortHashSipHash24,							ShortHash =		ShortHashSipHash24,
    GenericHashBlake2b,							GenericHash =		GenericHashBlake2b,
    PwHashScryptSalsa208Sha256,						PwHash =		PwHashScryptSalsa208Sha256,
    AuthHmacSha256, AuthHmacSha512, AuthHmacSha512256,			Auth =			AuthHmacSha512256,
    OneTimeAuthPoly1305, 						OneTimeAuth =		OneTimeAuthPoly1305,
    SignEd25519, 							Sign =			SignEd25519,
    BoxCurve25519Xsalsa20Poly1305,					Box =			BoxCurve25519Xsalsa20Poly1305,
    SecretBoxXsalsa20Poly1305,						SecretBox =		SecretBoxXsalsa20Poly1305,
    StreamAes128ctr, StreamSalsa20, StreamSalsa208, StreamSalsa2012,
	StreamChacha20, StreamXsalsa20,					Stream =		StreamXsalsa20,
    DiffieHellmanCurve25519,						DiffieHellman =		DiffieHellmanCurve25519,
    AuthEncAdDataAes256Gcm, AuthEncAdDataChacha20Poly1305,
	AuthEncAdDataChacha20Poly1305Ietf,				AuthEncAdData =		AuthEncAdDataChacha20Poly1305Ietf
};

/*
 * Traits for defined Operations.
 */
template <Operation O> struct OperationTraits {
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
    constexpr static std::size_t	SecretKeySize			{ 0 };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};

/*
 * Initialize.
 */
inline void init()
{
    if(::sodium_init())
	throw Exception(Exception::InitMsg);
}

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOBASE_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
