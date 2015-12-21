/*
** CryptoEncode.h
**
**  Created on: Dec 13, 2015
**      Author: gv
*/

#ifndef CRYPTOENCODE_H_
#define CRYPTOENCODE_H_

#include <algorithm>

#include "CryptoBase.h"

namespace Crypto {
namespace Encode {
/*
 * Encode::binToHex.
 */
inline std::string binToHex(const unsigned char* p_, std::size_t n_)
{
    std::string result(n_ + n_ + 1, '\0');
    ::sodium_bin2hex(&result[0], result.length(), p_, n_);
    result.pop_back();
    return result;
}
inline std::string binToHex(const unsigned char* begin_, const unsigned char* end_)
{
    return binToHex(begin_, end_ - begin_);
}
inline std::string binToHex(const std::string& s_)
{
    return binToHex(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
}

/*
 * Encode::hexToBin versions for filling data structures, throw on wrong output size and non-hex input.
 */
inline void hexToBin(const char* inP_, std::size_t inN_, unsigned char* outP_, std::size_t outN_,
		     const char* ignoreChars_ = nullptr)
{
    std::size_t outSize;
    if(::sodium_hex2bin(outP_, outN_, inP_, inN_, ignoreChars_, &outSize, nullptr))
	throw Exception(Exception::FormatMsg);
    if(outSize != outN_)
	throw Exception(Exception::SizeMsg);
}
inline void hexToBin(const char* inBegin_, const char* inEnd_, unsigned char* outBegin_, unsigned char* outEnd_,
		     const char* ignoreChars_ = nullptr)
{
    hexToBin(inBegin_, inEnd_ - inBegin_, outBegin_, outEnd_ - outBegin_, ignoreChars_);
}
inline void hexToBin(const std::string& in_, unsigned char* outBegin_, unsigned char* outEnd_,
		     const char* ignoreChars_ = nullptr)
{
    hexToBin(&in_[0], in_.length(), outBegin_, outEnd_ - outBegin_, ignoreChars_);
}
/*
 * Encode::hexToBin, string versions only throw on out-of-memory condition and non-hex input.
 */
inline std::string hexToBin(const char* p_,  std::size_t n_, const char* ignoreChars_ = nullptr)
{
    std::size_t outSize;
    std::string result(n_ / 2, '\0');
    if(::sodium_hex2bin(reinterpret_cast<unsigned char*>(&result[0]), result.length(), p_, n_, ignoreChars_, &outSize, nullptr))
	throw Exception(Exception::FormatMsg);
    result.resize(outSize);
    return result;
}
inline std::string hexToBin(const char* begin_,  const char* end_, const char* ignoreChars_ = nullptr)
{
    return hexToBin(begin_, end_ - begin_, ignoreChars_);
}
inline std::string hexToBin(const std::string& s_, const char* ignoreChars_ = nullptr)
{
    return hexToBin(&s_[0], s_.length(), ignoreChars_);
}

/*
 * Z85 Encoding.
 */
constexpr inline bool isSafeZ85BinSize(std::size_t binSize_) noexcept			{ return binSize_ % 4 == 0; }
constexpr inline bool isSafeZ85StringSize(std::size_t stringSize_) noexcept		{ return stringSize_ % 5 == 0; }

constexpr inline std::size_t safeZ85BinToStringSize(std::size_t binSize_) noexcept	{ return (binSize_ * 5) / 4; }
constexpr inline std::size_t safeZ85StringToBinSize(std::size_t stringSize_) noexcept	{ return (stringSize_ * 4) / 5; }

constexpr inline std::size_t z85PadSize(std::size_t binSize_) noexcept			{ return 4 - (binSize_ % 4); }

constexpr inline std::size_t z85BinToStringSize(std::size_t binSize_) noexcept
								{ return safeZ85BinToStringSize(binSize_ + z85PadSize(binSize_)); }

/*
 * Encode::safeBinToZ85. These versions only work with safe in- and output lengths,
 * check with isSafeZ85StringSize().
 */
std::string safeBinToZ85(const unsigned char* p_, std::size_t n_);
std::string safeBinToZ85(const unsigned char* begin_, const unsigned char* end_);
inline std::string safeBinToZ85(const std::string& s_)
{
    return safeBinToZ85(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
}

/*
 * Encode::safeZ85ToBin versions for filling data structures, throw on wrong in/output size and non-Z85 input.
 */
void safeZ85ToBin(const char* inP_, std::size_t inN_, unsigned char* outP_, std::size_t outN_);
void safeZ85ToBin(const char* inBegin_, const char* inEnd_, unsigned char* outBegin_, unsigned char* outEnd_);
inline void safeZ85ToBin(const std::string& in_, unsigned char* outBegin_, unsigned char* outEnd_)
{
    safeZ85ToBin(&in_[0], &in_[in_.length()], outBegin_, outEnd_);
}
/*
 * Encode::safeZ85ToBin, string versions only throw on out-of-memory condition, wrong input size and non-Z85 input.
 */
std::string safeZ85ToBin(const char* p_, std::size_t n_);
std::string safeZ85ToBin(const char* begin_, const char* end_);
inline std::string safeZ85ToBin(const std::string& s_)
{
    return safeZ85ToBin(&s_[0], s_.length());
}

/*
 * Encode::binToZ85. These versions work with any input length by applying padding.
 */
std::string binToZ85(const unsigned char* p_, std::size_t n_);
inline std::string binToZ85(const unsigned char* begin_, const unsigned char* end_) noexcept
{
    return binToZ85(begin_, end_ - begin_);
}
inline std::string binToZ85(const std::string& s_) noexcept
{
    return binToZ85(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length());
}

/*
 * Encode::z85ToBin, string versions only throw on out-of-memory condition, wrong input size and non-Z85 input.
 */
std::string z85ToBin(const char* p_, std::size_t n_);
inline std::string z85ToBin(const char* begin_, const char* end_)
{
    return z85ToBin(begin_, end_ - begin_);
}
inline std::string z85ToBin(const std::string& s_)
{
    return z85ToBin(&s_[0], s_.length());
}
/*
 * Encode::z85ToBin versions for filling data structures, throw on wrong output size and non-Z85 input.
 */
void z85ToBin(const char* inP_, std::size_t inN_, unsigned char* outP_, std::size_t outN_);
void z85ToBin(const char* inBegin_, const char* inEnd_, unsigned char* outBegin_, unsigned char* outEnd_);
inline void z85ToBin(const std::string& in_, unsigned char* outBegin_, unsigned char* outEnd_)
{
    z85ToBin(&in_[0], &in_[in_.length()], outBegin_, outEnd_);
}

/*
 * Encode::smartBinToZ85. These versions determine at compile time whether to use the safe or padded versions.
 */
template <std::size_t S> inline std::string smartBinToZ85(const unsigned char* p_, std::size_t n_)
{
    return isSafeZ85BinSize(S) ? safeBinToZ85(p_, n_) : binToZ85(p_, n_);
}
template <std::size_t S> inline std::string smartBinToZ85(const unsigned char* begin_, const unsigned char* end_)
{
    return isSafeZ85BinSize(S) ? safeBinToZ85(begin_, end_) : binToZ85(begin_, end_);
}
template <std::size_t S> inline std::string smartBinToZ85(const std::string& s_)
{
    return isSafeZ85BinSize(S) ? safeBinToZ85(s_) : binToZ85(s_);
}
/*
 * Encode::smartZ85ToBin. These versions determine at compile time whether to use the safe or padded versions.
 */
template <std::size_t S> inline void smartZ85ToBin(const char* inP_, std::size_t inN_, unsigned char* outP_, std::size_t outN_)
{
    if(isSafeZ85BinSize(S))
	safeZ85ToBin(inP_, inN_, outP_, outN_);
    else
	z85ToBin(inP_, inN_, outP_, outN_);
}
template <std::size_t S> inline void smartZ85ToBin(const char* inBegin_, const char* inEnd_,
						   unsigned char* outBegin_, unsigned char* outEnd_)
{
    if(isSafeZ85BinSize(S))
	safeZ85ToBin(inBegin_, inEnd_, outBegin_, outEnd_);
    else
	z85ToBin(inBegin_, inEnd_, outBegin_, outEnd_);
}
template <std::size_t S> inline void smartZ85ToBin(const std::string& in_, unsigned char* outBegin_, unsigned char* outEnd_)
{
    if(isSafeZ85BinSize(S))
	safeZ85ToBin(in_, outBegin_, outEnd_);
    else
	z85ToBin(in_, outBegin_, outEnd_);
}
template <std::size_t S> inline std::string smartZ85ToBin(const char* p_, std::size_t n_)
{
    return isSafeZ85BinSize(S) ? safeZ85ToBin(p_, n_) : z85ToBin(p_, n_);
}
template <std::size_t S> inline std::string smartZ85ToBin(const char* begin_, const char* end_)
{
    return isSafeZ85BinSize(S) ? safeZ85ToBin(begin_, end_) : z85ToBin(begin_, end_);
}
template <std::size_t S> std::string smartZ85ToBin(const std::string& s_)
{
    return isSafeZ85BinSize(S) ? safeZ85ToBin(s_) : z85ToBin(s_);
}

} // namespace Encode
} // namespace Crypto

#endif /* CRYPTOENCODE_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
