/*
** CryptoSecretKey.h
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

#ifndef CHLORIDE_CRYPTOSECRETKEY_H_
#define CHLORIDE_CRYPTOSECRETKEY_H_

#include "CryptoSeed.h"

namespace Crypto {
/*
 * Size-based Key base class.
 */
template <std::size_t S> class SecretKeyBase {
public:
    constexpr static std::size_t			Size		{ S };

protected:
    SecretKeyBase()
    {
	if(::sodium_mlock(_bytes, Size))
	    throw Exception(Exception::LockMsg);
    }
    SecretKeyBase(const SecretKeyBase& skb_)
	: _bytes	{ skb_._bytes }
    {
	if(::sodium_mlock(_bytes, Size))
	    throw Exception(Exception::LockMsg);
    }
    explicit SecretKeyBase(unsigned char* raw_)
	: SecretKeyBase()
    {
	std::copy_n(raw_, Size, _bytes);
    }
    SecretKeyBase(std::initializer_list<unsigned char> il_)
	: SecretKeyBase()
    {
	if(il_.size() != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(il_.begin(), il_.end(), _bytes);
    }
    template <typename I> SecretKeyBase(I begin_, I end_)
	: SecretKeyBase()
    {
	if(static_cast<std::size_t>(end_ - begin_) != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, _bytes);
    }

public:
    SecretKeyBase(SecretKeyBase&&) = delete;
    ~SecretKeyBase()						{ ::sodium_munlock(_bytes, Size); }

    SecretKeyBase& operator = (const SecretKeyBase&) = default;
    SecretKeyBase& operator = (SecretKeyBase&&) = delete;

    bool operator == (const SecretKeyBase& skb_) const noexcept	{ return ::sodium_memcmp(_bytes, skb_._bytes, Size) == 0; }
    bool operator != (const SecretKeyBase& skb_) const noexcept	{ return ::sodium_memcmp(_bytes, skb_._bytes, Size) != 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

private:
    unsigned char					_bytes[Size];
};

template <std::size_t> class HashBase;

/*
 * Secret/private Key.
 */
template <Operation O> class SecretKey: public SecretKeyBase<OperationTraits<O>::SecretKeySize> {
    static_assert(OperationTraits<O>::SecretKeySize > 0 && OperationTraits<O>::MinimumSecretKeySize == 0,
		  "Illegal SecretKey type!");
public:
    constexpr static Operation 				Oper		{ O };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::SecretKeySize };

    SecretKey()
	: SecretKeyBase<Size>()
    {}
    SecretKey(const SecretKey&) = default;
    SecretKey(Tag::GenerateTag)
	: SecretKeyBase<Size>()
    {
	::randombytes_buf(SecretKeyBase<Size>::begin(), Size);
    }
    explicit SecretKey(unsigned char* raw_)
	: SecretKeyBase<Size>(raw_)
    {}
    template <std::size_t HS, typename std::enable_if<SecretKey::Size == HS>::type* = nullptr>
    SecretKey(HashBase<HS>& h_)
	: SecretKeyBase<Size>(h_.begin(), h_.end())
    {
	h_.clear();
    }
    SecretKey(std::initializer_list<unsigned char> il_)
	: SecretKeyBase<Size>(il_)
    {}
    template <typename I> SecretKey(I begin_, I end_)
	: SecretKeyBase<Size>(begin_, end_)
    {}
    explicit SecretKey(std::string& s_)
	: SecretKeyBase<Size>(s_.begin(), s_.end())
    {
	s_.clear();
    }

    SecretKey& operator = (const SecretKey&) = default;
};

/*
 * Sized Secret/private Key.
 */
template <Operation O, std::size_t S> class SizedSecretKey: public SecretKeyBase<S> {
    static_assert(   OperationTraits<O>::SecretKeySize > OperationTraits<O>::MinimumSecretKeySize
		  && OperationTraits<O>::MinimumSecretKeySize > 0,
		  "Illegal SizedSecretKey type!");
    static_assert(OperationTraits<O>::MinimumSecretKeySize <= S && S <= OperationTraits<O>::SecretKeySize,
		  "Illegally sized SizedSecretKey type!");
public:
    constexpr static Operation 				Oper		{ O };
    constexpr static std::size_t			Size		{ S };

    SizedSecretKey()
	: SecretKeyBase<Size>()
    {}
    SizedSecretKey(const SizedSecretKey&) = default;
    SizedSecretKey(Tag::GenerateTag)
	: SecretKeyBase<Size>()
    {
	::randombytes_buf(SecretKeyBase<Size>::begin(), Size);
    }
    explicit SizedSecretKey(unsigned char* raw_)
	: SecretKeyBase<Size>(raw_)
    {}
    template <std::size_t HS, typename std::enable_if<SizedSecretKey::Size == HS>::type* = nullptr>
    SizedSecretKey(HashBase<HS>& h_)
	: SecretKeyBase<Size>(h_.begin(), h_.end())
    {
	h_.clear();
    }
    SizedSecretKey(std::initializer_list<unsigned char> il_)
	: SecretKeyBase<Size>(il_)
    {}
   template <typename I> SizedSecretKey(I begin_, I end_)
	: SecretKeyBase<Size>(begin_, end_)
    {}
    explicit SizedSecretKey(std::string& s_)
	: SecretKeyBase<Size>(s_.begin(), s_.end())
    {
	s_.clear();
    }

    SizedSecretKey& operator = (const SizedSecretKey&) = default;
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOSECRETKEY_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
