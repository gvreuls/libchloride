/*
** CryptoEncode.cpp
**
**  Created on: Dec 14, 2015
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

#include "chloride/CryptoEncode.h"

namespace Crypto {
namespace Encode {
namespace Z85 {
constexpr unsigned long long	DivMagic		{ 3233857729 };

constexpr inline unsigned long magicDiv(unsigned long number_) noexcept
{
    return static_cast<unsigned long>((DivMagic * number_) >> 32) >> 6;
}

static const char		Base85[] {
    "0123456789"
    "abcdefghij"
    "klmnopqrst"
    "uvwxyzABCD"
    "EFGHIJKLMN"
    "OPQRSTUVWX"
    "YZ.-:+=^!/"
    "*?&<>()[]{"
    "}@%$#"
};
static const unsigned char	Base256[] {
    0xFF, 0x44, 0xFF, 0x54, 0x53, 0x52, 0x48, 0xFF,
    0x4B, 0x4C, 0x46, 0x41, 0xFF, 0x3F, 0x3E, 0x45,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x40, 0xFF, 0x49, 0x42, 0x4A, 0x47,
    0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
    0x3B, 0x3C, 0x3D, 0x4D, 0xFF, 0x4E, 0x43, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x4F, 0xFF, 0x50, 0xFF, 0xFF
};

inline void encode_tuple(const unsigned char* in_, char* out_) noexcept
{
    const unsigned long value0 {   (static_cast<unsigned long>(in_[0]) << 24)
				 | (static_cast<unsigned long>(in_[1]) << 16)
				 | (static_cast<unsigned long>(in_[2]) << 8)
				 | in_[3] };
    const unsigned long value1 { magicDiv(value0) }; out_[4]= Base85[value0 - value1 * 85];
    const unsigned long value2 { magicDiv(value1) }; out_[3]= Base85[value1 - value2 * 85];
    const unsigned long value3 { magicDiv(value2) }; out_[2]= Base85[value2 - value3 * 85];
    const unsigned long value4 { magicDiv(value3) }; out_[1]= Base85[value3 - value4 * 85];
    out_[0]= Base85[value4];
}

inline unsigned long byteValue(unsigned char in_)
{
    if(32 > in_ || in_ >= (96 + 32))
	throw Exception(Exception::FormatMsg);
    const unsigned long result { Base256[in_ - 32] };
    if(result == 0xFF)
	throw Exception(Exception::FormatMsg);
    return result;
}

inline void decode_tuple(const char* in_, unsigned char* out_)
{
    const unsigned long value { (((byteValue(in_[0]) * 85 + byteValue(in_[1]))
						     * 85 + byteValue(in_[2]))
						     * 85 + byteValue(in_[3]))
						     * 85 + byteValue(in_[4]) };
    out_[0]= static_cast<unsigned char>(value >> 24),
    out_[1]= static_cast<unsigned char>(value >> 16),
    out_[2]= static_cast<unsigned char>(value >> 8),
    out_[3]= static_cast<unsigned char>(value);
}
} // namespace Z85

std::string safeBinToZ85(const unsigned char* p_, std::size_t n_)
{
    std::string result(safeZ85BinToStringSize(n_), '\0');
    const unsigned char* const end { p_ + n_ };
    for(char *r { &result[0] }; p_ < end; p_+= 4, r+= 5)
	Z85::encode_tuple(p_, r);
    return result;
}
std::string safeBinToZ85(const unsigned char* begin_, const unsigned char* end_)
{
    const std::size_t size { static_cast<std::size_t>(end_ - begin_) };
    std::string result(safeZ85BinToStringSize(size), '\0');
    for(char *r { &result[0] }; begin_ < end_; begin_+= 4, r+= 5)
	Z85::encode_tuple(begin_, r);
    return result;
}

void safeZ85ToBin(const char* inP_, std::size_t inN_, unsigned char* outP_, std::size_t outN_)
{
    const std::size_t outSize { safeZ85StringToBinSize(inN_) };
    if(!isSafeZ85StringSize(inN_) || outSize != outN_)
	throw Exception(Exception::SizeMsg);
    const char* const end { inP_ + inN_ };
    for(; inP_ < end; inP_+= 5, outP_+= 4)
	Z85::decode_tuple(inP_, outP_);
}
void safeZ85ToBin(const char* inBegin_, const char* inEnd_, unsigned char* outBegin_, unsigned char* outEnd_)
{
    const std::size_t inN { static_cast<std::size_t>(inEnd_ - inBegin_) };
    const std::size_t outN { static_cast<std::size_t>(outEnd_ - outBegin_) };
    const std::size_t outSize { safeZ85StringToBinSize(inN) };
    if(!isSafeZ85StringSize(inN) || outSize != outN)
	throw Exception(Exception::SizeMsg);
    for(; inBegin_ < inEnd_; inBegin_+= 5, outBegin_+= 4)
	Z85::decode_tuple(inBegin_, outBegin_);
}

std::string safeZ85ToBin(const char* p_, std::size_t n_)
{
    if(!isSafeZ85StringSize(n_))
	throw Exception(Exception::SizeMsg);
    std::string result(safeZ85StringToBinSize(n_), '\0');
    const char* const end { p_ + n_ };
    for(unsigned char *r { reinterpret_cast<unsigned char*>(&result[0]) }; p_ < end; p_+= 5, r+= 4)
	Z85::decode_tuple(p_, r);
    return result;
}
std::string safeZ85ToBin(const char* begin_, const char* end_)
{
    const std::size_t size { static_cast<std::size_t>(end_ - begin_) };
    if(!isSafeZ85StringSize(size))
	throw Exception(Exception::SizeMsg);
    std::string result(safeZ85StringToBinSize(size), '\0');
    for(unsigned char *r { reinterpret_cast<unsigned char*>(&result[0]) }; begin_ < end_; begin_+= 5, r+= 4)
	Z85::decode_tuple(begin_, r);
    return result;
}

std::string binToZ85(const unsigned char* p_, std::size_t n_)
{
    const std::size_t padSize { z85PadSize(n_) };
    std::string padded(n_ + padSize, '\0');
    std::copy_n(p_, n_, padded.begin());
    padded.back()= static_cast<char>(padSize + '0');
    return safeBinToZ85(padded);
}

std::string z85ToBin(const char* p_, std::size_t n_)
{
    if(!isSafeZ85StringSize(n_))
	throw Exception(Exception::SizeMsg);
    std::string result { safeZ85ToBin(p_, n_) };
    const std::size_t padSize { static_cast<std::size_t>(result.back() - '0') };
    result.resize(result.length() - padSize);
    return result;
}

void z85ToBin(const char* inP_, std::size_t inN_, unsigned char* outP_, std::size_t outN_)
{
    const std::size_t outSize { safeZ85StringToBinSize(inN_) };
    if(!isSafeZ85StringSize(inN_) || (outSize - 4) > outN_)
	throw Exception(Exception::SizeMsg);
    inN_-= 5;
    const char* const end { inP_ + inN_ };
    for(; inP_ < end; inP_+= 5, outP_+= 4)
	Z85::decode_tuple(inP_, outP_);
    unsigned char tuple[4];
    Z85::decode_tuple(inP_, tuple);
    const std::size_t padSize { static_cast<std::size_t>(tuple[3] - '0') };
    if((outSize - padSize) != outN_)
	throw Exception(Exception::SizeMsg);
    if(padSize < 4)
	std::copy_n(tuple, padSize, outP_);
}
void z85ToBin(const char* inBegin_, const char* inEnd_, unsigned char* outBegin_, unsigned char* outEnd_)
{
    const std::size_t inN { static_cast<std::size_t>(inEnd_ - inBegin_) };
    const std::size_t outN { static_cast<std::size_t>(outEnd_ - outBegin_) };
    const std::size_t outSize { safeZ85StringToBinSize(inN) };
    if(!isSafeZ85StringSize(inN) || (outSize - 4) > outN)
	throw Exception(Exception::SizeMsg);
    inEnd_-= 5;
    for(; inBegin_ < inEnd_; inBegin_+= 5, outBegin_+= 4)
	Z85::decode_tuple(inBegin_, outBegin_);
    unsigned char tuple[4];
    Z85::decode_tuple(inBegin_, tuple);
    const std::size_t padSize { static_cast<std::size_t>(tuple[3] - '0') };
    if((outSize - padSize) != outN)
	throw Exception(Exception::SizeMsg);
    if(padSize < 4)
	std::copy_n(tuple, padSize, outBegin_);
}

} // namespace Encode
} // namespace Crypto

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
