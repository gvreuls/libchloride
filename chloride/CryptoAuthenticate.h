/*
** CryptoAuth.h
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

#ifndef CHLORIDE_CRYPTOAUTHENTICATE_H_
#define CHLORIDE_CRYPTOAUTHENTICATE_H_

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_auth_hmacsha512.h>
#include <sodium/crypto_auth_hmacsha512256.h>
#include <sodium/crypto_onetimeauth_poly1305.h>

#include "CryptoSecretKey.h"

namespace Crypto {
/*
 * Traits for defined Operations.
 */
template <> struct OperationTraits<Operation::AuthHmacSha256> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_auth_hmacsha256_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ crypto_auth_hmacsha256_BYTES };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::AuthHmacSha512> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_auth_hmacsha512_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ crypto_auth_hmacsha512_BYTES };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::AuthHmacSha512256> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_auth_hmacsha512256_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ crypto_auth_hmacsha512256_BYTES };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::OneTimeAuthPoly1305> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_onetimeauth_poly1305_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ crypto_onetimeauth_poly1305_BYTES };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};

/*
 * Size-based base class.
 */
template <std::size_t S> class AuthenticatorBase {
public:
    constexpr static std::size_t			Size		{ S };

protected:
    AuthenticatorBase() noexcept = default;
    AuthenticatorBase(const unsigned char* raw_) noexcept    { std::copy_n(raw_, Size, _bytes); }
    template <typename I> AuthenticatorBase(I begin_, I end_)
    {
	if(static_cast<std::size_t>(end_ - begin_) != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, _bytes);
    }
    AuthenticatorBase(const std::string& s_)
	: AuthenticatorBase(s_.begin(), s_.end())
    {}

public:
    bool operator == (const AuthenticatorBase& ab_) const noexcept	{ return ::sodium_memcmp(_bytes, ab_._bytes, Size) != 0; }
    bool operator != (const AuthenticatorBase& ab_) const noexcept	{ return ::sodium_memcmp(_bytes, ab_._bytes, Size) != 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

private:
    unsigned char					_bytes[Size];
};

/*
 * Authenticator.
 */
template <Operation O> class Authenticator {
    static_assert(OperationTraits<O>::AuthenticatorSize > 0, "Illegal Authenticator type!");
};

template <> class Authenticator<Operation::AuthHmacSha256>
	: public AuthenticatorBase<OperationTraits<Operation::AuthHmacSha256>::AuthenticatorSize> {
public:
    constexpr static Operation				Oper		{ Operation::AuthHmacSha256 };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::AuthenticatorSize };

    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    class Builder {
	friend class Authenticator;

	::crypto_auth_hmacsha256_state			_state;

    public:
	Builder(const SecretKeyBaseType& sk_) noexcept
	{
	    ::crypto_auth_hmacsha256_init(&_state, sk_.begin(), sk_.Size);
	}

	Builder& operator () (const unsigned char* p_, std::size_t n_) noexcept
	{
	    ::crypto_auth_hmacsha256_update(&_state, p_, n_);
	    return *this;
	}
	Builder& operator () (const unsigned char* begin_, const unsigned char* end_) noexcept
	{
	    return operator()(begin_, static_cast<std::size_t>(end_ - begin_));
	}
	Builder& operator () (const std::string& s_) noexcept
	{
	    return operator()(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
	}
    };

    Authenticator() noexcept = default;
    explicit Authenticator(const unsigned char* raw_) noexcept
	: AuthenticatorBase<Size>(raw_)
    {}
    Authenticator(Builder& b_) noexcept
    {
	::crypto_auth_hmacsha256_final(&b_._state, AuthenticatorBase<Size>::begin());
    }
    template <typename I> Authenticator(I begin_, I end_)
	: AuthenticatorBase<Size>(begin_, end_)
    {}
    explicit Authenticator(const std::string& s_)
	: AuthenticatorBase(s_.begin(), s_.end())
    {}
    Authenticator(const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_auth_hmacsha256(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin());
    }
    Authenticator(const SecretKeyBaseType& sk_, unsigned char* begin_, unsigned char* end_) noexcept
	: Authenticator<Oper>(sk_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}

    Authenticator(const SecretKeyBaseType& sk_, const std::string& message_) noexcept
	: Authenticator<Oper>(sk_, reinterpret_cast<const unsigned char *>(&message_[0]), message_.length())
    {}

    void operator () (const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) const
    {
	if(::crypto_auth_hmacsha256_verify(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin()))
	    throw VerificationError();
    }
    void operator () (const SecretKeyBaseType& sk_, const unsigned char* begin_, const unsigned char* end_) const
    {
	operator()(sk_, begin_, static_cast<std::size_t>(end_ - begin_));
    }
    void operator () (const SecretKeyBaseType& sk_, const std::string& message_) const
    {
	operator()(sk_, reinterpret_cast<const unsigned char*>(&message_[0]), message_.length());
    }
};

template <> class Authenticator<Operation::AuthHmacSha512>
	: public AuthenticatorBase<OperationTraits<Operation::AuthHmacSha512>::AuthenticatorSize> {
public:
    constexpr static Operation				Oper		{ Operation::AuthHmacSha512 };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::AuthenticatorSize };

    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    class Builder {
	friend class Authenticator;

	::crypto_auth_hmacsha512_state			_state;

    public:
	Builder(const SecretKeyBaseType& sk_) noexcept
	{
	    ::crypto_auth_hmacsha512_init(&_state, sk_.begin(), sk_.Size);
	}

	Builder& operator () (const unsigned char* p_, std::size_t n_) noexcept
	{
	    ::crypto_auth_hmacsha512_update(&_state, p_, n_);
	    return *this;
	}
	Builder& operator () (const unsigned char* begin_, const unsigned char* end_) noexcept
	{
	    return operator()(begin_, static_cast<std::size_t>(end_ - begin_));
	}
	Builder& operator () (const std::string& s_) noexcept
	{
	    return operator()(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
	}
    };

    Authenticator() noexcept = default;
    explicit Authenticator(const unsigned char* raw_) noexcept
	: AuthenticatorBase<Size>(raw_)
    {}
    Authenticator(Builder& b_) noexcept
    {
	::crypto_auth_hmacsha512_final(&b_._state, AuthenticatorBase<Size>::begin());
    }
    template <typename I> Authenticator(I begin_, I end_)
	: AuthenticatorBase<Size>(begin_, end_)
    {}
    explicit Authenticator(const std::string& s_)
	: AuthenticatorBase(s_.begin(), s_.end())
    {}
    Authenticator(const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_auth_hmacsha512(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin());
    }
    Authenticator(const SecretKeyBaseType& sk_, unsigned char* begin_, unsigned char* end_) noexcept
	: Authenticator<Oper>(sk_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}

    Authenticator(const SecretKeyBaseType& sk_, const std::string& message_) noexcept
	: Authenticator<Oper>(sk_, reinterpret_cast<const unsigned char *>(&message_[0]), message_.length())
    {}

    void operator () (const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) const
    {
	if(::crypto_auth_hmacsha512_verify(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin()))
	    throw VerificationError();
    }
    void operator () (const SecretKeyBaseType& sk_, const unsigned char* begin_, const unsigned char* end_) const
    {
	operator()(sk_, begin_, static_cast<std::size_t>(end_ - begin_));
    }
    void operator () (const SecretKeyBaseType& sk_, const std::string& message_) const
    {
	operator()(sk_, reinterpret_cast<const unsigned char*>(&message_[0]), message_.length());
    }
};

template <> class Authenticator<Operation::AuthHmacSha512256>
	: public AuthenticatorBase<OperationTraits<Operation::AuthHmacSha512256>::AuthenticatorSize> {
public:
    constexpr static Operation				Oper		{ Operation::AuthHmacSha512256 };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::AuthenticatorSize };

    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    class Builder {
	friend class Authenticator;

	::crypto_auth_hmacsha512256_state		_state;

    public:
	Builder(const SecretKeyBaseType& sk_) noexcept
	{
	    ::crypto_auth_hmacsha512256_init(&_state, sk_.begin(), sk_.Size);
	}

	Builder& operator () (const unsigned char* p_, std::size_t n_) noexcept
	{
	    ::crypto_auth_hmacsha512256_update(&_state, p_, n_);
	    return *this;
	}
	Builder& operator () (const unsigned char* begin_, const unsigned char* end_) noexcept
	{
	    return operator()(begin_, static_cast<std::size_t>(end_ - begin_));
	}
	Builder& operator () (const std::string& s_) noexcept
	{
	    return operator()(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
	}
    };

    Authenticator() noexcept = default;
    explicit Authenticator(const unsigned char* raw_) noexcept
	: AuthenticatorBase<Size>(raw_)
    {}
    Authenticator(Builder& b_) noexcept
    {
	::crypto_auth_hmacsha512256_final(&b_._state, AuthenticatorBase<Size>::begin());
    }
    template <typename I> Authenticator(I begin_, I end_)
	: AuthenticatorBase<Size>(begin_, end_)
    {}
    explicit Authenticator(const std::string& s_)
	: AuthenticatorBase(s_.begin(), s_.end())
    {}
    Authenticator(const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_auth_hmacsha512256(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin());
    }
    Authenticator(const SecretKeyBaseType& sk_, unsigned char* begin_, unsigned char* end_) noexcept
	: Authenticator<Oper>(sk_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}

    Authenticator(const SecretKeyBaseType& sk_, const std::string& message_) noexcept
	: Authenticator<Oper>(sk_, reinterpret_cast<const unsigned char *>(&message_[0]), message_.length())
    {}

    void operator () (const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) const
    {
	if(::crypto_auth_hmacsha512256_verify(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin()))
	    throw VerificationError();
    }
    void operator () (const SecretKeyBaseType& sk_, const unsigned char* begin_, const unsigned char* end_) const
    {
	operator()(sk_, begin_, static_cast<std::size_t>(end_ - begin_));
    }
    void operator () (const SecretKeyBaseType& sk_, const std::string& message_) const
    {
	operator()(sk_, reinterpret_cast<const unsigned char*>(&message_[0]), message_.length());
    }
};

template <> class Authenticator<Operation::OneTimeAuthPoly1305>
	: public AuthenticatorBase<OperationTraits<Operation::OneTimeAuthPoly1305>::AuthenticatorSize> {
public:
    constexpr static Operation				Oper		{ Operation::OneTimeAuthPoly1305 };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::AuthenticatorSize };

    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    class Builder {
	friend class Authenticator;

	::crypto_onetimeauth_poly1305_state		_state;

    public:
	Builder(const SecretKeyBaseType& sk_) noexcept
	{
	    ::crypto_onetimeauth_poly1305_init(&_state, sk_.begin());
	}

	Builder& operator () (const unsigned char* p_, std::size_t n_) noexcept
	{
	    ::crypto_onetimeauth_poly1305_update(&_state, p_, n_);
	    return *this;
	}
	Builder& operator () (const unsigned char* begin_, const unsigned char* end_) noexcept
	{
	    return operator()(begin_, static_cast<std::size_t>(end_ - begin_));
	}
	Builder& operator () (const std::string& s_) noexcept
	{
	    return operator()(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
	}
    };

    Authenticator() noexcept = default;
    explicit Authenticator(const unsigned char* raw_) noexcept
	: AuthenticatorBase<Size>(raw_)
    {}
    Authenticator(Builder& b_) noexcept
    {
	::crypto_onetimeauth_poly1305_final(&b_._state, AuthenticatorBase<Size>::begin());
    }
    template <typename I> Authenticator(I begin_, I end_)
	: AuthenticatorBase<Size>(begin_, end_)
    {}
    explicit Authenticator(const std::string& s_)
	: AuthenticatorBase(s_.begin(), s_.end())
    {}
    Authenticator(const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_onetimeauth_poly1305(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin());
    }
    Authenticator(const SecretKeyBaseType& sk_, unsigned char* begin_, unsigned char* end_) noexcept
	: Authenticator<Oper>(sk_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}

    Authenticator(const SecretKeyBaseType& sk_, const std::string& message_) noexcept
	: Authenticator<Oper>(sk_, reinterpret_cast<const unsigned char *>(&message_[0]), message_.length())
    {}

    void operator () (const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) const
    {
	if(::crypto_onetimeauth_poly1305_verify(AuthenticatorBase<Size>::begin(), p_, n_, sk_.begin()))
	    throw VerificationError();
    }
    void operator () (const SecretKeyBaseType& sk_, const unsigned char* begin_, const unsigned char* end_) const
    {
	operator()(sk_, begin_, static_cast<std::size_t>(end_ - begin_));
    }
    void operator () (const SecretKeyType& sk_, const std::string& message_) const
    {
	operator()(sk_, reinterpret_cast<const unsigned char*>(&message_[0]), message_.length());
    }
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOAUTHENTICATE_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
