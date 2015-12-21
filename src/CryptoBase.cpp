/*
** CryptoBase.cpp
**
**  Created on: Dec 9, 2015
**      Author: gv
*/

#include "../chloride/CryptoBase.h"

namespace Crypto {

const std::string	Exception::InitMsg		{ "crypto can\'t initialize libsodium!" };
const std::string	Exception::ImplMsg	{ "crypto implementation error, this should have been caught by a static_assert!" };
const std::string	Exception::SizeMsg		{ "crypto wrong size" };
const std::string	Exception::LockMsg		{ "crypto can\'t lock memory" };
const std::string	Exception::KeyGenMsg		{ "crypto can\'t generate key pair" };
const std::string	Exception::OverflowMsg		{ "crypto overflow incrementing nonce" };
const std::string	Exception::FormatMsg		{ "crypto input format error" };
const std::string	Exception::MemoryMsg		{ "crypto out of memory" };
const std::string	VerificationError::VerifyMsg	{ "crypto verification error" };

} // namespace Crypto

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
