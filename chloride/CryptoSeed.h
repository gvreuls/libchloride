/*
** CryptoSeed.h
**
**  Created on: Dec 12, 2015
**      Author: gv
*/

#ifndef CHLORIDE_CRYPTOSEED_H_
#define CHLORIDE_CRYPTOSEED_H_

#include <sodium/randombytes.h>

#include <algorithm>
#include <type_traits>
#include <initializer_list>

#include "CryptoBase.h"

namespace Crypto {

template <std::size_t> class HashBase;

/*
 * Random/Hashed Seed.
 */
template <Operation O> class Seed {
    static_assert(OperationTraits<O>::SeedSize > 0, "Illegal Seed type!");
public:
    constexpr static Operation				Oper		{ O };
    constexpr static std::size_t			Size		{ OperationTraits<Oper>::SeedSize };

    Seed() noexcept = default;
    Seed(Tag::GenerateTag) noexcept				{ ::randombytes_buf(_bytes, Size); }
    explicit Seed(const unsigned char* raw_) noexcept		{ std::copy_n(raw_, Size, _bytes); }
    template <std::size_t HS, typename std::enable_if<Seed::Size == HS>::type* = nullptr>
    Seed(const HashBase<HS>& h_)
	: Seed(h_.begin())
    {}
    Seed(std::initializer_list<unsigned char> il_)
    {
	if(il_.size() != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(il_.begin(), il_.end(), _bytes);
    }
    template <typename I> Seed(I begin_, I end_)
    {
	if(static_cast<std::size_t>(end_ - begin_) != Size)
	    throw Exception(Exception::SizeMsg);
	std::copy(begin_, end_, _bytes);
    }
    explicit Seed(const std::string& s_)
	: Seed(s_.begin(), s_.end())
    {}

    bool operator == (const Seed& s_) const noexcept		{ return ::sodium_memcmp(_bytes, s_._bytes, Size) == 0; }
    bool operator != (const Seed& s_) const noexcept		{ return ::sodium_memcmp(_bytes, s_._bytes, Size) != 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

private:
    unsigned char					_bytes[Size];
};

} // namespace Crypto

#endif /* CHLORIDE_CRYPTOSEED_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
