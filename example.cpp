/*
** Example.cpp
**
**  Created on: Dec 22, 2015
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

#include <cstring>
#include <iostream>

#include <chloride.h>

int main(int, char* argv[])
{
    try {
	Crypto::init();
	std::cout << "Demonstrating libchloride v" << CHLORIDE_VERSION << '\n';

	// Authentication.
	std::string text { "This is but a small demonstration of the Crypto interface." };
	Crypto::SecretKey<Crypto::Operation::Auth>	authKey { Crypto::Tag::Generate };
	Crypto::Authenticator<Crypto::Operation::Auth>	authenticate { authKey, text };
	std::cout << '\"' << text << "\" $> \"" << Crypto::Encode::binToZ85(authenticate.begin(), authenticate.end()) << "\"\n";
	authenticate(authKey, text);
	text+= '.';

	// Signing.
	Crypto::KeyPair<Crypto::Operation::Sign> 	signingKeys { Crypto::Tag::Generate };
	std::cout << '\"' << text << "\" $$> ";
	signSeal(signingKeys.secretKey, text);
	std::cout << '\"' << Crypto::Encode::binToZ85(text) << "\" -> ";
	signOpen(signingKeys.publicKey, text);
	std::cout << '\"' << text << "\"\n";
	Crypto::Signature<Crypto::Operation::Sign>	signature { signingKeys.secretKey, text };
	signature(signingKeys.publicKey, text);
	text+= '.';

	// Public key boxing/unboxing.
	Crypto::KeyPair<Crypto::Operation::Box> 	sealKeys;
	Crypto::convertKeyPair(signingKeys, sealKeys);
	Crypto::KeyPair<Crypto::Operation::Box>		openKeys { Crypto::Tag::Generate };
	Crypto::Nonce<Crypto::Operation::Box> 		sealNonce { Crypto::Tag::GenerateConstant };
	Crypto::Nonce<Crypto::Operation::Box>		openNonce { sealNonce };
	Crypto::BoxSealer<Crypto::Operation::Box>	boxSeal { openKeys.publicKey, sealKeys.secretKey, sealNonce };
	Crypto::BoxOpener<Crypto::Operation::Box>	boxOpen { sealKeys.publicKey, openKeys.secretKey, openNonce };
	std::cout << '\"' << text << "\" -> ";
	std::string cypher { boxSeal(text) };
	cypher= Crypto::Encode::binToZ85(cypher);
	std::cout << '\"' << cypher << "\" -> ";
	cypher= Crypto::Encode::z85ToBin(cypher);
	text= boxOpen(cypher);
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Secret key boxing/unboxing protected by secure password in read-only memory.
	std::unique_ptr<char[], Crypto::Memory::Free>	password { new(Crypto::Memory::Allocate) char[Crypto::Memory::Alignment] };
	std::strncpy(password.get(), "Correct Horse Battery Staple", Crypto::Memory::Alignment);
	Crypto::Memory::access<Crypto::Memory::Access::Read>(password);
	std::string pw { password.get() };
	Crypto::Memory::access<Crypto::Memory::Access::None>(password);
	Crypto::Salt<Crypto::Operation::PwHash>		secretPwSalt {
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	Crypto::SizedHash<Crypto::Operation::PwHash, Crypto::SecretKey<Crypto::Operation::SecretBox>::Size>
							secretPwHash { secretPwSalt, pw };
	Crypto::SecretKey<Crypto::Operation::SecretBox>	secretKey { secretPwHash };
	Crypto::Nonce<Crypto::Operation::SecretBox> 	secretSealNonce { Crypto::Tag::GenerateConstant };
	Crypto::Nonce<Crypto::Operation::SecretBox>	secretOpenNonce { secretSealNonce };
	Crypto::BoxSealer<Crypto::Operation::SecretBox>	secretBoxSeal { secretKey, secretSealNonce };
	Crypto::BoxOpener<Crypto::Operation::SecretBox>	secretBoxOpen { secretKey, secretOpenNonce };
	std::cout << '\"' << text << "\" -> ";
	cypher= secretBoxSeal(text);
	cypher= Crypto::Encode::binToZ85(cypher);
	std::cout << '\"' << cypher << "\" -> ";
	cypher= Crypto::Encode::z85ToBin(cypher);
	text= secretBoxOpen(cypher);
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Streaming with Diffie Hellman shared secret key.
	Crypto::KeyPair<Crypto::Operation::DiffieHellman> streamSealKeys { Crypto::Tag::Generate };
	Crypto::KeyPair<Crypto::Operation::DiffieHellman> streamOpenKeys { Crypto::Tag::Generate };
 	Crypto::DiffieHellman<Crypto::Operation::DiffieHellman> streamSealSecret { streamOpenKeys.publicKey, streamSealKeys,
 										   Crypto::Tag::Sealer };
 	Crypto::DiffieHellman<Crypto::Operation::DiffieHellman> streamOpenSecret { streamSealKeys.publicKey, streamOpenKeys };
 	// Test with large nonce sequential size.
	Crypto::Nonce<Crypto::Operation::Stream, 12> 	streamSealNonce { Crypto::Tag::GenerateConstant };
	streamSealNonce(true);
	Crypto::Nonce<Crypto::Operation::Stream, 12> 	streamOpenNonce { streamSealNonce };
	// Stream with very short pad to test pad updating.
	Crypto::Streamer<Crypto::Operation::Stream, 5, 12> streamSeal { streamSealSecret, streamSealNonce };
	Crypto::Streamer<Crypto::Operation::Stream, 5, 12> streamOpen { streamOpenSecret, streamOpenNonce };
	std::cout << '\"' << text << "\" -> ";
	streamSeal(text);
	text= Crypto::Encode::binToZ85(text);
	std::cout << '\"' << text << "\" -> ";
	text= Crypto::Encode::z85ToBin(text);
	streamOpen(text);
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Authenticated encryption with additional data.
	std::cout << "Aes256Gcm is";
	if(!Crypto::Operation_AuthEncAdDataAes256Gcm_Available())
	    std::cout << "n\'t";
	std::cout << " available.\n";
	Crypto::SecretKey<Crypto::Operation::AuthEncAdData> aeadKey { Crypto::Tag::Generate };
	Crypto::Nonce<Crypto::Operation::AuthEncAdData> aeadSealNonce { Crypto::Tag::GenerateConstant };
	Crypto::Nonce<Crypto::Operation::AuthEncAdData> aeadOpenNonce { aeadSealNonce };
	Crypto::AuthEncAdDataSealer<Crypto::Operation::AuthEncAdData> aeadSeal { aeadKey, aeadSealNonce };
	Crypto::AuthEncAdDataOpener<Crypto::Operation::AuthEncAdData> aeadOpen { aeadKey, aeadOpenNonce };
	Crypto::Memory::access<Crypto::Memory::Access::Read>(password);
	pw= password.get();
	Crypto::Memory::access<Crypto::Memory::Access::None>(password);
	std::cout << '\"' << text << "\" + \"" << pw << "\" -> ";
	cypher= Crypto::Encode::binToZ85(aeadSeal(text, pw));
	std::cout << '\"' << cypher << "\" -> ";
	text= aeadOpen(Crypto::Encode::z85ToBin(cypher), pw);
	pw.clear();
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Short hashing with Z85 encoding.
	Crypto::SecretKey<Crypto::Operation::ShortHash>	hashKey {
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	Crypto::Hash<Crypto::Operation::ShortHash>	hash { hashKey, text };
	cypher= Crypto::Encode::smartBinToZ85<Crypto::Hash<Crypto::Operation::ShortHash>::Size>(hash.begin(), hash.end());
	std::cout << "#\"" << cypher << "\"\n";
	Crypto::Hash<Crypto::Operation::ShortHash>	inHash;
	Crypto::Encode::smartZ85ToBin<Crypto::Hash<Crypto::Operation::ShortHash>::Size>(cypher, inHash.begin(), inHash.end());
	if(hash != inHash)
	    throw "Hashing or encoding error";

	// More Z85 encoding.
	unsigned char field[] { "01234567890123456789" };
	std::cout << '\"' << field << "\" -> ";
	cypher= Crypto::Encode::smartBinToZ85<sizeof(field)>(field, sizeof(field));
	std::cout << '\"' << cypher << "\" -> ";
	Crypto::Encode::smartZ85ToBin<sizeof(field)>(cypher, field, field + sizeof(field));
	std::cout << '\"' << field << "\"\n";

	// Generic hashing with multi-part builder.
	Crypto::SizedSecretKey<Crypto::Operation::GenericHash, sizeof(field)> genHashKey { field };
	Crypto::SizedHash<Crypto::Operation::GenericHash, 24>::Builder genHashBuild { genHashKey };
	Crypto::Memory::access<Crypto::Memory::Access::Read>(password);
	pw= password.get();
	Crypto::Memory::access<Crypto::Memory::Access::None>(password);
	genHashBuild(text)(cypher)(pw);
	std::cout << '\"' << text << "\" + \"" << cypher << "\" + \"" << pw << "\" = ";
	pw.clear();
	Crypto::SizedHash<Crypto::Operation::GenericHash, 24> genHash { genHashBuild };
	cypher= Crypto::Encode::smartBinToZ85<genHash.Size>(genHash.begin(), genHash.end());
	std::cout << "#\"" << cypher << "\"\n";
	text+= '.';

	// Password hashing.
	Crypto::Memory::access<Crypto::Memory::Access::Read>(password);
	pw= password.get();
	Crypto::Memory::access<Crypto::Memory::Access::None>(password);
	std::cout << '\"' << pw << "\" -> " << std::flush;
	Crypto::Hash<Crypto::Operation::PwHash> 	checkPassword { pw };
	std::cout << "#\"" << checkPassword << '\"'<< std::endl;
	Crypto::Memory::access<Crypto::Memory::Access::Read>(password);
	pw= password.get();
	Crypto::Memory::access<Crypto::Memory::Access::None>(password);
	checkPassword(pw);

	std::cout << "Bye.\n";
    }
    catch(Crypto::VerificationError& e)
    {
	std::cerr << argv[0] << " verification failure\n";
	return 1;
    }
    catch(Crypto::Exception& e)
    {
	std::cerr << argv[0] << " fatal cryptographic exception " << e.what() << '\n';
	return 1;
    }
    catch(std::exception& e)
    {
	std::cerr << argv[0] << " fatal exception: " << e.what() << '\n';
	return 1;
    }
    catch(const char* e)
    {
	std::cerr << argv[0] << " fatal error: " << e << '\n';
	return 1;
    }
    catch(...)
    {
	std::cerr << argv[0] << " unknown fatal exception\n";
	return 1;
    }
    return 0;
}

/* vi:set nojs noet ts=8 sts=4 sw=4 cindent: */
