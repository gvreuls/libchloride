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
** You should have received a copy of the GNU Lesser General Public
** License along with libchloride.  If not, see
** <http://www.gnu.org/licenses/>.
*/

#include <cstring>
#include <iostream>

#include <chloride.h>

// Define shorthand aliases:	shorthand	long type			default parameters
typedef Crypto::Operation	COp;
template <COp O> using		COpTraits =	Crypto::OperationTraits<O>;
template <COp O> using 		CAuth =		Crypto::Authenticator<O>;
template <COp O, std::size_t S =						COpTraits<O>::NonceDefaultSequentialSize>
		 using		CAeadOpener =	Crypto::AuthEncAdDataOpener<O, S>;
template <COp O, std::size_t S =						COpTraits<O>::NonceDefaultSequentialSize>
		 using		CAeadSealer =	Crypto::AuthEncAdDataSealer<O, S>;
template <COp O, std::size_t S = 						COpTraits<O>::NonceDefaultSequentialSize>
		 using		CBoxOpener =	Crypto::BoxOpener<O, S>;
template <COp O, std::size_t S = 						COpTraits<O>::NonceDefaultSequentialSize>
		 using		CBoxSealer =	Crypto::BoxSealer<O, S>;
template <COp O, std::size_t S = 						COpTraits<O>::SecretKeySize>
		 using		CDifHel =	Crypto::DiffieHellman<O, S>;
namespace			CEnc =		Crypto::Encode;
template <COp O> using		CHash =		Crypto::Hash<O>;
template <COp O> using		CKeyPair =	Crypto::KeyPair<O>;
namespace			CMem =		Crypto::Memory;
typedef CMem::Access		CMemAcc;
template <COp O, std::size_t S = 						COpTraits<O>::NonceDefaultSequentialSize>
		 using		CNonce =	Crypto::Nonce<O, S>;
template <COp O> using		CPubKey =	Crypto::PublicKey<O>;
template <COp O> using 		CSalt =		Crypto::Salt<O>;
template <COp O> using 		CSeed =		Crypto::Seed<O>;
template <COp O> using 		CSecKey =	Crypto::SecretKey<O>;
template <COp O> using 		CSign =		Crypto::Signature<O>;
template <COp O, std::size_t S = 						Crypto::StreamerDefaultPadSize,
		 std::size_t NSS =						COpTraits<O>::NonceDefaultSequentialSize>
		 using		CStreamer =	Crypto::Streamer<O, S, NSS>;
template <COp O, std::size_t S>
		 using		CSzHash =	Crypto::SizedHash<O, S>;
template <COp O, std::size_t S>
		 using		CSzSecKey =	Crypto::SizedSecretKey<O, S>;
namespace			CTag =		Crypto::Tag;

int main(int, char* argv[])
{
    try {
	Crypto::init();
	std::cout << "Demonstrating libchloride v"
		  << CHLORIDE_VERSION << '\n';

	// Secret key authentication.
	std::string 			text 		{ "This is but a small demonstration of the Crypto interface." };
	CSecKey<COp::Auth>		authKey 	{ CTag::Generate };		// generate SecretKey
	CAuth<COp::Auth>		authenticate 	{ authKey, text };		// authenticate text
	std::cout << "Authenticating \"" << text << "\" -> \""
		  << CEnc::binToZ85(authenticate.begin(),
				    authenticate.end())
		  << "\": ";
	try {
	    authenticate(authKey, text);						// verify authentication
	    std::cout << "authentication succeeded.\n";
	}
	catch(Crypto::VerificationError&)
	{
	    std::cout << "authentication failed!\n";
	    throw;
	}
	text+= '.';

	// Public key signing.
	CKeyPair<COp::Sign> 		signingKeys 	{ CTag::Generate };		// generate KeyPair
	std::cout << "Signing \"" << text << "\" -> ";
	signSeal(signingKeys.secretKey, text);						// sign text
	std::cout << '\"' << CEnc::binToZ85(text) << "\": ";
	try {
	    signOpen(signingKeys.publicKey, text);					// decrypt signed text.
	    std::cout << "message authentic.\n";
	}
	catch(Crypto::VerificationError&)
	{
	    std::cout << "message forged!\n";
	    throw;
	}
	std::cout << "Verifying signature: ";
	CSign<COp::Sign>		signature	{ signingKeys.secretKey,
							  text };			// stand-alone signature
	try {
	    signature(signingKeys.publicKey, text);					// check signature
	    std::cout << "signature authentic.\n";
	}
	catch(Crypto::VerificationError&)
	{
	    std::cout << "signature forged!\n";
	    throw;
	}
	text+= '.';

	// Public key boxing/unboxing.
	CKeyPair<COp::Box> 		sealKeys;
	Crypto::convertKeyPair(signingKeys, sealKeys);					// convert sender KeyPair
	CKeyPair<COp::Box>		openKeys 	{ CTag::Generate };		// generate receiver KeyPair
	CNonce<COp::Box> 		sealNonce 	{ CTag::GenerateConstant };	// generate sender Nonce
	CNonce<COp::Box>		openNonce 	{ sealNonce };			// copy sender Nonce to receiver
	CBoxSealer<COp::Box>		boxSeal 	{ openKeys.publicKey,
							  sealKeys.secretKey,
							  sealNonce };			// sender boxer
	CBoxOpener<COp::Box>		boxOpen 	{ sealKeys.publicKey,
							  openKeys.secretKey,
							  openNonce };			// receiver unboxer
	std::cout << "Public boxing \""
		  << text << "\" -> ";
	std::string 			cipher		{ CEnc::binToZ85(boxSeal(text)) };	// sender box
	std::cout << '\"' << cipher << "\"\n"
		  << "Public unboxing \""
		  << cipher << "\" -> ";
	text= boxOpen(CEnc::z85ToBin(cipher));						// receiver unbox
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Secret key boxing/unboxing protected by secure password in read-only memory.
	std::unique_ptr<char[], CMem::Free>
					password	{ new(CMem::Allocate) char[CMem::Alignment] };	// allocate protected memory
	std::strncpy(password.get(),
		     "Correct Horse Battery Staple",
		     CMem::Alignment);							// copy password into it
	CMem::access<CMemAcc::Read>(password);						// set read-only access to password
	std::string			pw		{ password.get() };
	CMem::access<CMemAcc::None>(password);						// set no access to password
	CSalt<COp::PwHash>		secretPwSalt {					// initialize salt for password hash
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	CSzHash<COp::PwHash, CSecKey<COp::SecretBox>::Size>
					secretPwHash 	{ secretPwSalt, pw };		// create salted password hash sized
	CSecKey<COp::SecretBox>		secretKey 	{ secretPwHash };		// to initialize a SecretKey
	CNonce<COp::SecretBox> 		secretSealNonce	{ CTag::GenerateConstant };	// generate sender Nonce
	CNonce<COp::SecretBox>		secretOpenNonce	{ secretSealNonce };		// copy sender Nonce to receiver
	CBoxSealer<COp::SecretBox>	secretBoxSeal	{ secretKey, secretSealNonce };	// sender boxer
	CBoxOpener<COp::SecretBox>	secretBoxOpen	{ secretKey, secretOpenNonce };	// receiver unboxer
	std::cout << "Secret boxing \""
		  << text << "\" -> ";
	cipher= CEnc::binToZ85(secretBoxSeal(text));					// sender box
	std::cout << '\"' << cipher << "\"\n"
		  << "Secret unboxing \""
		  << cipher << "\" -> ";
	text= secretBoxOpen(CEnc::z85ToBin(cipher));					// receiver unbox
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Streaming with Diffie Hellman shared secret key.
	CKeyPair<COp::DiffieHellman>	streamSealKeys	{ CTag::Generate };		// generate sender KeyPair
	CKeyPair<COp::DiffieHellman>	streamOpenKeys	{ CTag::Generate };		// generate receiver KeyPair
 	CDifHel<COp::DiffieHellman>	streamSealSecret{ streamOpenKeys.publicKey,
 							  streamSealKeys, CTag::Sealer };	// compute secret for sender
 	CDifHel<COp::DiffieHellman>	streamOpenSecret{ streamSealKeys.publicKey,
 							  streamOpenKeys };		// compute secret for receiver
 	// Test with large Nonce sequential size.
	CNonce<COp::Stream, 12> 	streamSealNonce	{ CTag::GenerateConstant };	// generate sender Nonce
	streamSealNonce(true);								// mark sender Nonce
	CNonce<COp::Stream, 12> 	streamOpenNonce	{ streamSealNonce };		// copy sender Nonce to receiver
	// Stream with very short pad to test pad updating.
	CStreamer<COp::Stream, 5, 12>	streamSeal	{ streamSealSecret,
							  streamSealNonce };		// initialize sender stream
	CStreamer<COp::Stream, 5, 12>	streamOpen	{ streamOpenSecret,
							  streamOpenNonce };		// initialize receiver stream.
	std::cout << "Encrypting stream \""
		  << text << "\" -> ";
	streamSeal(text);								// encrypt stream
	text= CEnc::binToZ85(text);
	std::cout << '\"' << text << "\"\n"
		  << "Decrypting stream \""
		  << text << "\" -> ";
	text= CEnc::z85ToBin(text);
	streamOpen(text);								// decrypt stream
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Authenticated encryption with additional data.
	std::cout << "Aes256Gcm is";
	if(!Crypto::Operation_AuthEncAdDataAes256Gcm_Available())
	    std::cout << "n\'t";
	std::cout << " available.\n";
	CSecKey<COp::AuthEncAdData>	aeadKey		{ CTag::Generate };		// generate SecretKey
	CNonce<COp::AuthEncAdData>	aeadSealNonce	{ CTag::GenerateConstant };	// generate sender Nonce
	CNonce<COp::AuthEncAdData>	aeadOpenNonce	{ aeadSealNonce };		// copy sender Nonce to receiver
	CAeadSealer<COp::AuthEncAdData>	aeadSeal	{ aeadKey, aeadSealNonce };	// initialize sender encryption
	CAeadOpener<COp::AuthEncAdData>	aeadOpen	{ aeadKey, aeadOpenNonce };	// initialize receiver decryption
	CMem::access<CMemAcc::Read>(password);
	pw= password.get();
	CMem::access<CMemAcc::None>(password);
	std::cout << "Encrypting secret + data \""
		  << text << "\" + \"" << pw << "\" -> ";
	cipher= CEnc::binToZ85(aeadSeal(text, pw));					// encrypt
	std::cout << '\"' << cipher << "\"\n"
		  << "Decrypting secret + data \""
		  << cipher  << "\" + \"" << pw << "\" -> ";
	text= aeadOpen(CEnc::z85ToBin(cipher), pw);					// decrypt
	pw.clear();
	std::cout << '\"' << text << "\"\n";
	text+= '.';

	// Short hashing with Z85 encoding.
	CSecKey<COp::ShortHash>		hashKey {					// initialize SecretKey
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	CHash<COp::ShortHash>		hash		{ hashKey, text };		// hash text
	cipher= CEnc::smartBinToZ85<CHash<COp::ShortHash>::Size>(hash.begin(),
								 hash.end());		// encode
	std::cout << "ShortHash \"" << text
		  << "\" = \"" << cipher << "\"\n";
	CHash<COp::ShortHash>		inHash;
	CEnc::smartZ85ToBin<CHash<COp::ShortHash>::Size>(cipher, inHash.begin(),
							 inHash.end());			// decode straight into object
	if(hash != inHash)
	    throw "encoding error!";

	// More Z85 encoding.
	unsigned char 			field[]		{ "01234567890123456789" };
	cipher= CEnc::smartBinToZ85<sizeof(field)>(field, sizeof(field));		// encode
	CEnc::smartZ85ToBin<sizeof(field)>(cipher, field, field + sizeof(field));	// decode straight into array

	// Generic hashing with multi-part builder.
	CSzSecKey<COp::GenericHash, sizeof(field)>
					genHashKey	{ field };			// hash array into SizedSecretKey
	CSzHash<COp::GenericHash, 24>::Builder
					genHashBuild	{ genHashKey };			// initialize builder with SizedSecretKey
	CMem::access<CMemAcc::Read>(password);
	pw= password.get();
	CMem::access<CMemAcc::None>(password);
	genHashBuild(text)(cipher)(pw);							// hash 3 pieces of data
	std::cout << "Hashing (multi-part) \"" << text << "\" + \""
		  << cipher << "\" + \"" << pw << "\" = ";
	pw.clear();
	CSzHash<COp::GenericHash, 24>	genHash		{ genHashBuild };
	cipher= CEnc::smartBinToZ85<genHash.Size>(genHash.begin(), genHash.end());
	std::cout << '\"' << cipher << "\"\n";
	text+= '.';

	// Password hashing.
	CMem::access<CMemAcc::Read>(password);
	pw= password.get();
	CMem::access<CMemAcc::None>(password);
	std::cout << "Hashing password \""
		  << pw << "\" -> " << std::flush;
	CHash<COp::PwHash> 		checkPassword	{ pw };				// generate password hash
	std::cout << '\"' << checkPassword
		  << '\"' << std::endl;
	CMem::access<CMemAcc::Read>(password);
	pw= password.get();
	CMem::access<CMemAcc::None>(password);
	std::cout << "Checking password: ";
	try {
	    checkPassword(pw);								// check password against hash
	    std::cout << "password correct.\n";
	}
	catch(Crypto::VerificationError&)
	{
	    std::cout << "password incorrect!\n";
	    throw;
	}

	std::cout << "Bye.\n";
    }
    catch(Crypto::VerificationError&)
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
