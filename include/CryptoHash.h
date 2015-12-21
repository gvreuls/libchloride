/*
** CryptoHash.h
**
**  Created on: Dec 12, 2015
**      Author: gv
*/

#ifndef CRYPTOHASH_H_
#define CRYPTOHASH_H_

#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_shorthash_siphash24.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>

#include "CryptoSalt.h"
#include "CryptoSecretKey.h"

namespace Crypto {
/*
 * Traits for defined Operations.
 */
template <> struct OperationTraits<Operation::HashSha256> {
    constexpr static bool		HasHash				{ true };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ crypto_hash_sha256_BYTES };
    constexpr static std::size_t	SecretKeySize			{ 0 };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::HashSha512> {
    constexpr static bool		HasHash				{ true };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ crypto_hash_sha512_BYTES };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ 0 };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::ShortHashSipHash24> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ true };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ crypto_shorthash_siphash24_BYTES };
    constexpr static std::size_t	MinimumHashSize			{ 0 };
    constexpr static std::size_t	SecretKeySize			{ crypto_shorthash_siphash24_KEYBYTES };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ 0 };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::GenericHashBlake2b> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ true };
    constexpr static bool		HasPwHash			{ false };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ crypto_generichash_blake2b_BYTES_MAX };
    constexpr static std::size_t	MinimumHashSize			{ crypto_generichash_blake2b_BYTES_MIN };
    constexpr static std::size_t	SecretKeySize			{ crypto_generichash_blake2b_KEYBYTES_MAX };
    constexpr static std::size_t	MinimumSecretKeySize		{ crypto_generichash_blake2b_KEYBYTES_MIN };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ crypto_generichash_blake2b_PERSONALBYTES };
    constexpr static std::size_t	SaltSize			{ crypto_generichash_blake2b_SALTBYTES };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
};
template <> struct OperationTraits<Operation::PwHashScryptSalsa208Sha256> {
    constexpr static bool		HasHash				{ false };
    constexpr static bool		HasShortHash			{ false };
    constexpr static bool		HasGenericHash			{ false };
    constexpr static bool		HasPwHash			{ true };
    constexpr static bool		HasBox				{ false };
    constexpr static bool		HasSecretBox			{ false };
    constexpr static bool		HasStream			{ false };
    constexpr static bool		HasDiffieHellman		{ false };
    constexpr static std::size_t	HashSize			{ 128 };
    constexpr static std::size_t	MinimumHashSize			{ 8 };
    constexpr static std::size_t	SecretKeySize			{ 0 };
    constexpr static std::size_t	MinimumSecretKeySize		{ 0 };
    constexpr static std::size_t	PublicKeySize			{ 0 };
    constexpr static std::size_t	SeedSize			{ 0 };
    constexpr static std::size_t	SaltSize			{ crypto_pwhash_scryptsalsa208sha256_SALTBYTES };
    constexpr static std::size_t	NonceSize			{ 0 };
    constexpr static std::size_t	NonceDefaultSequentialSize	{ 0 };
    constexpr static std::size_t	AuthenticatorSize		{ 0 };
    constexpr static std::size_t	SignatureSize			{ 0 };
    constexpr static std::size_t	AuthEncAdDataSize		{ 0 };
    constexpr static std::size_t	StaticHashSize			{ crypto_pwhash_scryptsalsa208sha256_STRBYTES };
    constexpr static std::size_t	DefaultStaticOpsLimit		{ crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE };
    constexpr static std::size_t	DefaultStaticMemLimit		{ crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE };
    constexpr static std::size_t	DefaultSizedOpsLimit		{ crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE };
    constexpr static std::size_t	DefaultSizedMemLimit		{ crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE };
};

/*
 * Size-based Hash base class.
 */
template <std::size_t S> class HashBase {
public:
    constexpr static std::size_t			Size			{ S };

protected:
    HashBase() noexcept = default;
    HashBase(const unsigned char* raw_) noexcept		{ std::copy_n(raw_, Size, _bytes); }

public:
    bool operator == (const HashBase& hb_) const noexcept	{ return ::sodium_memcmp(_bytes, hb_._bytes, Size) == 0; }
    bool operator != (const HashBase& hb_) const noexcept	{ return ::sodium_memcmp(_bytes, hb_._bytes, Size) != 0; }

    const unsigned char* begin() const noexcept			{ return _bytes; }
    unsigned char* begin() noexcept				{ return _bytes; }

    const unsigned char* end() const noexcept			{ return _bytes + Size; }
    unsigned char* end() noexcept				{ return _bytes + Size; }

    void clear() noexcept					{ ::sodium_memzero(_bytes, Size); }

private:
    unsigned char					_bytes[Size];
};

/*
 * Hash.
 */
template <Operation O> class Hash {
    static_assert(OperationTraits<O>::HashSize > 0 && OperationTraits<O>::MinimumHashSize == 0, "Illegal Hash type!");
};

template<> class Hash<Operation::HashSha256>: public HashBase<OperationTraits<Operation::HashSha256>::HashSize> {
public:
    const static Operation				Oper			{ Operation::HashSha256 };
    constexpr static std::size_t			Size			{ OperationTraits<Oper>::HashSize };

    class Builder {
	friend class Hash;

	::crypto_hash_sha256_state			_state;

    public:
	Builder() noexcept			{ ::crypto_hash_sha256_init(&_state); }

	Builder& operator () (const unsigned char* p_, std::size_t n_) noexcept
	{
	    ::crypto_hash_sha256_update(&_state, p_, n_);
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

    Hash() noexcept = default;
    explicit Hash(const unsigned char* raw_) noexcept
	: HashBase<Size>(raw_)
    {}
    Hash(Builder& b_) noexcept
    {
	::crypto_hash_sha256_final(&b_._state, HashBase<Size>::begin());
    }
    Hash(const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_hash_sha256(HashBase<Size>::begin(), p_, n_);
    }
    Hash(const unsigned char* begin_, const unsigned char* end_) noexcept
	: Hash<Oper>(begin_, static_cast<std::size_t>(end_ - begin_))
    {}
    Hash(const std::string& s_) noexcept
	: Hash<Oper>(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length())
    {}
};

template<> class Hash<Operation::HashSha512>: public HashBase<OperationTraits<Operation::HashSha512>::HashSize> {
public:
    const static Operation				Oper			{ Operation::HashSha512 };
    constexpr static std::size_t			Size			{ OperationTraits<Oper>::HashSize };

    class Builder {
	friend class Hash;

	::crypto_hash_sha512_state			_state;

    public:
	Builder() noexcept			{ ::crypto_hash_sha512_init(&_state); }

	Builder& operator () (const unsigned char* p_, std::size_t n_) noexcept
	{
	    ::crypto_hash_sha512_update(&_state, p_, n_);
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

    Hash() noexcept = default;
    explicit Hash(const unsigned char* raw_) noexcept
	: HashBase<Size>(raw_)
    {}
    Hash(Builder& b_) noexcept
    {
	::crypto_hash_sha512_final(&b_._state, HashBase<Size>::begin());
    }
    Hash(const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_hash_sha512(HashBase<Size>::begin(), p_, n_);
    }
    Hash(const unsigned char* begin_, const unsigned char* end_) noexcept
	: Hash<Oper>(begin_, static_cast<std::size_t>(end_ - begin_))
    {}
    Hash(const std::string& s_) noexcept
	: Hash<Oper>(reinterpret_cast<const unsigned char*>(&s_[0]), s_.length())
    {}
};

template<> class Hash<Operation::ShortHashSipHash24>: public HashBase<OperationTraits<Operation::ShortHashSipHash24>::HashSize> {
public:
    constexpr static Operation				Oper			{ Operation::ShortHashSipHash24 };
    constexpr static std::size_t			Size			{ OperationTraits<Oper>::HashSize };

    typedef SecretKey<Oper>					SecretKeyType;
    typedef SecretKeyBase<OperationTraits<Oper>::SecretKeySize>	SecretKeyBaseType;

    Hash() noexcept = default;
    explicit Hash(const unsigned char* raw_) noexcept
	: HashBase<Size>(raw_)
    {}
    Hash(const SecretKeyBaseType& sk_, const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_shorthash_siphash24(HashBase<Size>::begin(), p_, n_, sk_.begin());
    }
    Hash(const SecretKeyBaseType& sk_, const unsigned char* begin_, const unsigned char* end_) noexcept
	: Hash<Oper>(sk_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}
    Hash(const SecretKeyBaseType& sk_, const std::string& s_) noexcept
	: Hash<Oper>(sk_, reinterpret_cast<const unsigned char*>(&s_[0]), s_.length())
    {}
};

/*
 * SizedHash.
 */
template <Operation O, std::size_t Size> class SizedHash {
    static_assert(OperationTraits<O>::HashSize > 0 && OperationTraits<O>::MinimumHashSize > 0, "Illegal SizedHash type!");
};

template <std::size_t S> class SizedHash<Operation::GenericHashBlake2b, S>: public HashBase<S> {
public:
    const static Operation				Oper			{ Operation::GenericHashBlake2b };
    constexpr static std::size_t			Size			{ S };
    constexpr static std::size_t			MinimumSecretKeySize	{ OperationTraits<Oper>::MinimumSecretKeySize };
    constexpr static std::size_t			MaximumSecretKeySize	{ OperationTraits<Oper>::SecretKeySize };

    static_assert(OperationTraits<Oper>::MinimumHashSize <= Size && Size <= OperationTraits<Oper>::HashSize,
		  "Illegally sized SizedHash type!");

    typedef Salt<Oper>		SaltType;
    typedef Seed<Oper>		SeedType;

    class Builder {
	friend class SizedHash;

	::crypto_generichash_blake2b_state		_state;

    public:
	Builder() noexcept
	{
	    ::crypto_generichash_blake2b_init(&_state, nullptr, 0, Size);
	}
	template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
							  && KS <= MaximumSecretKeySize>::type* = nullptr>
	Builder(const SecretKeyBase<KS>& k_) noexcept
	{
	    ::crypto_generichash_blake2b_init(&_state, k_.begin(), KS, Size);
	}
	template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
							  && KS <= MaximumSecretKeySize>::type* = nullptr>
	Builder(const SecretKeyBase<KS>& k_, const SaltType& st_, const SeedType& personal_) noexcept
	{
	    ::crypto_generichash_blake2b_init_salt_personal(&_state, k_.begin(), KS, Size, st_.begin(), personal_.begin());
	}

	Builder& operator () (const unsigned char* p_, std::size_t n_) noexcept
	{
	    ::crypto_generichash_blake2b_update(&_state, p_, n_);
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

    SizedHash() noexcept = default;
    explicit SizedHash(const unsigned char* raw_) noexcept
	: HashBase<Size>(raw_)
    {}
    SizedHash(Builder& b_) noexcept
    {
	::crypto_generichash_blake2b_final(&b_._state, SizedHash::begin(), Size);
    }
    template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
						      && KS <= MaximumSecretKeySize>::type* = nullptr>
    SizedHash(const SecretKeyBase<KS>& k_, const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_generichash_blake2b(HashBase<Size>::begin(), Size, p_, n_, k_.begin(), KS);
    }
    template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
						      && KS <= MaximumSecretKeySize>::type* = nullptr>
    SizedHash(const SecretKeyBase<KS>& k_, const unsigned char* begin_, const unsigned char* end_) noexcept
	: SizedHash<Oper, Size>(k_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}
    template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
						      && KS <= MaximumSecretKeySize>::type* = nullptr>
    SizedHash(const SecretKeyBase<KS>& k_, const std::string& s_) noexcept
	: SizedHash<Oper, Size>(k_, reinterpret_cast<const unsigned char*>(&s_[0]), s_.length())
    {}
    template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
						      && KS <= MaximumSecretKeySize>::type* = nullptr>
    SizedHash(const SecretKeyBase<KS>& k_, const SaltType& st_, const SeedType& personal_,
	      const unsigned char* p_, std::size_t n_) noexcept
    {
	::crypto_generichash_blake2b_salt_personal(HashBase<Size>::begin(), Size, p_, n_,
						   k_.begin(), KS, st_.begin(), personal_.begin());
    }
    template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
						      && KS <= MaximumSecretKeySize>::type* = nullptr>
    SizedHash(const SecretKeyBase<KS>& k_, const SaltType& st_, const SeedType& personal_,
	      const unsigned char* begin_, const unsigned char* end_) noexcept
	: SizedHash<Oper, Size>(k_, st_, personal_, begin_, static_cast<std::size_t>(end_ - begin_))
    {}
    template <std::size_t KS, typename std::enable_if<   MinimumSecretKeySize <= KS
						      && KS <= MaximumSecretKeySize>::type* = nullptr>
    SizedHash(const SecretKeyBase<KS>& k_, const SaltType& st_, const SeedType& personal_,
	      const std::string& s_) noexcept
	: SizedHash<Oper, Size>(k_, st_, personal_, reinterpret_cast<const unsigned char*>(&s_[0]), s_.length())
    {}
};

/*
 * PwHashScryptSalsa208Sha256 has both Hash and SizedHash functionality.
 */
template <> class Hash<Operation::PwHashScryptSalsa208Sha256>
	: public HashBase<OperationTraits<Operation::PwHashScryptSalsa208Sha256>::StaticHashSize> {
public:
    constexpr static Operation				Oper			{ Operation::PwHashScryptSalsa208Sha256 };
    constexpr static std::size_t			Size			{ OperationTraits<Oper>::StaticHashSize };
    constexpr static std::size_t			DefaultOpsLimit		{ OperationTraits<Oper>::DefaultStaticOpsLimit };
    constexpr static std::size_t			DefaultMemLimit		{ OperationTraits<Oper>::DefaultStaticMemLimit };

    Hash() noexcept = default;
    explicit Hash(const unsigned char* raw_) noexcept
	: HashBase<Size>(raw_)
    {}
    Hash(const char* pw_, std::size_t pwLen_,
	 std::size_t opsLimit_ = DefaultOpsLimit, std::size_t memLimit_ = DefaultMemLimit)
    {
	if(::crypto_pwhash_scryptsalsa208sha256_str(reinterpret_cast<char*>(HashBase<Size>::begin()),
						    pw_, pwLen_, opsLimit_, memLimit_))
	    throw Exception(Exception::MemoryMsg);
    }
    Hash(const char* pwBegin_, const char* pwEnd_,
	 std::size_t opsLimit_ = DefaultOpsLimit, std::size_t memLimit_ = DefaultMemLimit)
	: Hash<Oper>(pwBegin_, static_cast<std::size_t>(pwEnd_ - pwBegin_), opsLimit_, memLimit_)
    {}
    Hash(std::string& pw_,
	 std::size_t opsLimit_ = DefaultOpsLimit, std::size_t memLimit_ = DefaultMemLimit)
	: Hash<Oper>(&pw_[0], pw_.length(), opsLimit_, memLimit_)
    {
	pw_.clear();
    }

    operator const char* () const noexcept		{ return reinterpret_cast<const char*>(HashBase<Size>::begin()); }

    void operator () (const char* pw_, std::size_t pwLen_) const
    {
	if(::crypto_pwhash_scryptsalsa208sha256_str_verify(reinterpret_cast<const char*>(HashBase<Size>::begin()), pw_, pwLen_))
	    throw VerificationError();
    }
    void operator () (const char* pwBegin_, const char* pwEnd_)	const
							{ operator()(pwBegin_, static_cast<std::size_t>(pwEnd_ - pwBegin_)); }
    void operator () (const std::string& pw_) const	{ operator()(&pw_[0], pw_.length()); }
};

template <std::size_t S> class SizedHash<Operation::PwHashScryptSalsa208Sha256, S>: public HashBase<S> {
public:
    const static Operation				Oper			{ Operation::PwHashScryptSalsa208Sha256 };
    constexpr static std::size_t			Size			{ S };
    constexpr static std::size_t			DefaultOpsLimit		{ OperationTraits<Oper>::DefaultSizedOpsLimit };
    constexpr static std::size_t			DefaultMemLimit		{ OperationTraits<Oper>::DefaultSizedMemLimit };

    static_assert(OperationTraits<Oper>::MinimumHashSize <= Size && Size <= OperationTraits<Oper>::HashSize,
		  "Illegally sized SizedHash type!");

    typedef Salt<Oper>		SaltType;

    SizedHash() noexcept = default;
    explicit SizedHash(const unsigned char* raw_) noexcept
	: HashBase<Size>(raw_)
    {}
    SizedHash(const SaltType& st_, const char* pw_, std::size_t pwLen_,
	      std::size_t opsLimit_ = DefaultOpsLimit, std::size_t memLimit_ = DefaultMemLimit)
    {
	if(::crypto_pwhash_scryptsalsa208sha256(HashBase<Size>::begin(), Size, pw_, pwLen_, st_.begin(), opsLimit_, memLimit_))
	    throw Exception(Exception::MemoryMsg);
    }
    SizedHash(const SaltType& st_, const char* pwBegin_, const char* pwEnd_,
	      std::size_t opsLimit_ = DefaultOpsLimit, std::size_t memLimit_ = DefaultMemLimit)
	: SizedHash<Oper, Size>(st_, pwBegin_, static_cast<std::size_t>(pwEnd_ - pwBegin_), opsLimit_, memLimit_)
    {}
    SizedHash(const SaltType& st_, std::string& pw_,
	      std::size_t opsLimit_ = DefaultOpsLimit, std::size_t memLimit_ = DefaultMemLimit)
	: SizedHash<Oper, Size>(st_, &pw_[0], pw_.length(), opsLimit_, memLimit_)
    {
	pw_.clear();
    }
};

} // namespace Crypto

#endif /* CRYPTOHASH_H_ */

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
