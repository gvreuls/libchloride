/*
** CryptoBase.cpp
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

#include "chloride/CryptoBase.h"

namespace Crypto {

const std::string	Exception::InitMsg		{ "crypto can\'t initialize libsodium!" };
const std::string	Exception::ImplMsg	{ "crypto implementation error, this should have been caught by a static_assert!" };
const std::string	Exception::SizeMsg		{ "crypto wrong size" };
const std::string	Exception::LockMsg		{ "crypto can\'t set memory properties" };
const std::string	Exception::KeyGenMsg		{ "crypto can\'t generate key pair" };
const std::string	Exception::OverflowMsg		{ "crypto overflow incrementing nonce" };
const std::string	Exception::FormatMsg		{ "crypto input format error" };
const std::string	Exception::MemoryMsg		{ "crypto not enough memory" };
const std::string	VerificationError::VerifyMsg	{ "crypto verification error" };

} // namespace Crypto

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
