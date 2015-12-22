/*
** CryptoMemory.h
**
**  Created on: Dec 21, 2015
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

#ifndef CHLORIDE_CRYPTOMEMORY_H_
#define CHLORIDE_CRYPTOMEMORY_H_

#include <new>
#include <memory>

#include "CryptoBase.h"

namespace Crypto {
namespace Memory {
/*
 * operator new tag.
 */
constexpr struct AllocateTag {}	Allocate	{};	// Tag deliberately independent of CryptoBase.h.

constexpr std::size_t		AlignmentShift	{ 6 };
constexpr std::size_t		Alignment	{ 1 << AlignmentShift };

} // namespace Memory
} //namespace Crypto

inline void* operator new (std::size_t size_, Crypto::Memory::AllocateTag, std::nothrow_t) noexcept
{
    return ::sodium_malloc(
	size_ > 0 ? ((size_ + Crypto::Memory::Alignment - 1) >> Crypto::Memory::AlignmentShift) << Crypto::Memory::AlignmentShift
		  : Crypto::Memory::Alignment);
}
inline void* operator new (std::size_t size_, Crypto::Memory::AllocateTag)
{
    void* result { operator new(size_, Crypto::Memory::Allocate, std::nothrow) };
    if(result == nullptr)
	throw std::bad_alloc();
    return result;
}

inline void operator delete (void* pointer_, Crypto::Memory::AllocateTag) noexcept
{
    ::sodium_free(pointer_);
}

inline void* operator new[] (std::size_t size_, Crypto::Memory::AllocateTag, std::nothrow_t) noexcept
{
    return operator new(size_, Crypto::Memory::Allocate, std::nothrow);
}
inline void* operator new[] (std::size_t size_, Crypto::Memory::AllocateTag)
{
    return operator new(size_, Crypto::Memory::Allocate);
}

inline void operator delete[] (void* pointer_, Crypto::Memory::AllocateTag) noexcept
{
    operator delete(pointer_, Crypto::Memory::Allocate);
}

namespace Crypto {
namespace Memory {
/*
 * Smart pointer helper.
 */
struct Free {
    void operator () (void* pointer_) const noexcept		{ operator delete(pointer_, Crypto::Memory::Allocate); }
};

/*
 * Memory access/protection.
 */
enum class Access { None, Read, ReadWrite };

template <Access A> inline void access(void* pointer_)
{
    switch(A) {
    case Access::ReadWrite:
	if(::sodium_mprotect_readwrite(pointer_))
	    throw Exception(Exception::LockMsg);
	break;
    case Access::Read:
	if(::sodium_mprotect_readonly(pointer_))
	    throw Exception(Exception::LockMsg);
	break;
    default:
	if(::sodium_mprotect_noaccess(pointer_))
	    throw Exception(Exception::LockMsg);
    }
}
template <Access A, typename T> inline void access(std::shared_ptr<T>& sp_)			{ access<A>(sp_.get()); }
template <Access A, typename T, typename D> inline void access(std::unique_ptr<T, D>& up_)	{ access<A>(up_.get()); }

} // namespace Memory
} //namespace Crypto

#endif /* CHLORIDE_CRYPTOMEMORY_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
