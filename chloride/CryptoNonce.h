/*
** CryptoNonce.h
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

#ifndef CHLORIDE_CRYPTONONCE_H_
#define CHLORIDE_CRYPTONONCE_H_

#include <sodium/randombytes.h>

#include <algorithm>

#include "CryptoBase.h"

namespace Crypto {
/*
 * Nonce.
 */
template <Operation O, std::size_t S = OperationTraits<O>::NonceDefaultSequentialSize> class Nonce {
    static_assert(OperationTraits<O>::NonceSize > 0, "Illegal Nonce type!");
public:
    constexpr static Operation				Oper		{ O };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::NonceSize };
    constexpr static std::size_t			SequentialSize	{ S };
    constexpr static std::size_t			ConstantSize	{ Size - SequentialSize };

    static_assert(SequentialSize > 0, "Nonce sequential size too small!");
    static_assert(SequentialSize < Size && ConstantSize >= 4, "Nonce sequential size too big!");

    Nonce() noexcept = default;
    Nonce(Tag::GenerateTag) noexcept				{ ::randombytes_buf(_bytes, Size); }
    Nonce(Tag::GenerateConstantTag) noexcept
    {
	::randombytes_buf(constantBegin(), ConstantSize);
	::sodium_memzero(sequentialBegin(), SequentialSize);
    }
    explicit Nonce(unsigned char* raw_) noexcept		{ std::copy_n(raw_, Size, _bytes); }
    Nonce(unsigned char* raw_, Tag::SpecifyConstantTag) noexcept
    {
	std::copy_n(raw_, ConstantSize, constantBegin());
	::sodium_memzero(sequentialBegin(), SequentialSize);
    }
    template <typename I> Nonce(I begin_, I end_)
    {
	if(static_cast<std::size_t>(end_ - begin_) != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, _bytes);
    }
    template <typename I> Nonce(I begin_, I end_, Tag::SpecifyConstantTag)
    {
	if(static_cast<std::size_t>(end_ - begin_) != ConstantSize)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, constantBegin());
	::sodium_memzero(sequentialBegin(), SequentialSize);
    }
    explicit Nonce(const std::string& s_)
	: Nonce(s_.begin(), s_.end())
    {}
    Nonce(const std::string& s_, Tag::SpecifyConstantTag)
	: Nonce(s_.begin(), s_.end(), Tag::SpecifyConstant)
    {}

    Nonce& operator ++ ()
    {
	const auto msb { sequentialBegin()[SequentialSize - 1] };
	::sodium_increment(sequentialBegin(), SequentialSize);
	if(sequentialBegin()[SequentialSize - 1] < msb)
	    throw Exception(Exception::OverflowMsg);
	return *this;
    }

    Nonce& operator () (bool flag_) noexcept
    {
	if(static_cast<bool>(*constantBegin() & 1) != flag_)
	    *constantBegin()^= 1;
	return *this;
    }

    bool operator == (const Nonce& n_) const noexcept		{ return ::sodium_compare(_bytes, n_._bytes, Size) == 0; }
    bool operator != (const Nonce& n_) const noexcept		{ return ::sodium_compare(_bytes, n_._bytes, Size) != 0; }
    bool operator <  (const Nonce& n_) const noexcept		{ return ::sodium_compare(_bytes, n_._bytes, Size) < 0; }
    bool operator <= (const Nonce& n_) const noexcept		{ return ::sodium_compare(_bytes, n_._bytes, Size) <= 0; }
    bool operator >  (const Nonce& n_) const noexcept		{ return ::sodium_compare(_bytes, n_._bytes, Size) > 0; }
    bool operator >= (const Nonce& n_) const noexcept		{ return ::sodium_compare(_bytes, n_._bytes, Size) >= 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    const unsigned char* constantBegin() const noexcept		{ return _bytes; }
    unsigned char* constantBegin() noexcept			{ return _bytes; }

    const unsigned char* constantEnd() const noexcept		{ return _bytes + ConstantSize; }
    unsigned char* constantEnd() noexcept			{ return _bytes + ConstantSize; }

    const unsigned char* sequentialBegin() const noexcept	{ return _bytes + ConstantSize; }
    unsigned char* sequentialBegin() noexcept			{ return _bytes + ConstantSize; }

    const unsigned char* sequentialEnd() const noexcept		{ return _bytes + Size; }
    unsigned char* sequentialEnd() noexcept			{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

private:
    unsigned char					_bytes[Size];
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTONONCE_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
