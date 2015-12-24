/*
** CryptoSalt.h
**
**  Created on: Dec 16, 2015
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

#ifndef CHLORIDE_CRYPTOSALT_H_
#define CHLORIDE_CRYPTOSALT_H_

#include <sodium/randombytes.h>

#include <algorithm>
#include <type_traits>
#include <initializer_list>

#include "CryptoBase.h"

namespace Crypto {

template <std::size_t> class HashBase;

/*
 * Salt.
 */
template <Operation O> class Salt {
    static_assert(OperationTraits<O>::SaltSize > 0, "Illegal Salt type!");
public:
    constexpr static Operation				Oper		{ O };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::SaltSize };

    Salt() noexcept = default;
    Salt(Tag::GenerateTag) noexcept				{ ::randombytes_buf(_bytes, Size); }
    explicit Salt(const unsigned char* raw_) noexcept		{ std::copy_n(raw_, Size, _bytes); }
    template <std::size_t HS, typename std::enable_if<Salt::Size == HS>::type* = nullptr>
    Salt(const HashBase<HS>& h_)
	: Salt(h_.begin())
    {}
    Salt(std::initializer_list<unsigned char> il_)
    {
	if(il_.size() != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(il_.begin(), il_.end(), _bytes);
    }
    template <typename I> Salt(I begin_, I end_)
    {
	if(static_cast<std::size_t>(end_ - begin_) != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, _bytes);
    }
    explicit Salt(const std::string& s_)
	: Salt(s_.begin(), s_.end())
    {}

    bool operator == (const Salt& s_) const noexcept		{ return ::sodium_memcmp(_bytes, s_._bytes, Size) == 0; }
    bool operator != (const Salt& s_) const noexcept		{ return ::sodium_memcmp(_bytes, s_._bytes, Size) != 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

private:
    unsigned char					_bytes[Size];
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOSALT_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
