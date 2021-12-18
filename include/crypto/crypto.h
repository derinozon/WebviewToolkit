#include <stdio.h>
#include <string.h>

#include "aes.h"
#include "base64.h"
#include "bcrypt.h"

namespace WVTK::Crypto {

	
	void WriteBcrypt (const char* pwd, FILE* file, int work = 4) {
		char salt[BCRYPT_HASHSIZE];
		char hash[BCRYPT_HASHSIZE];
		
		bcrypt_gensalt(work, salt);
		bcrypt_hashpw(pwd, salt, hash);
		
		
		fwrite(hash, 1, BCRYPT_HASHSIZE, file);
	}
	std::string Bcrypt_Encrypt (const char* pwd, int work = 4) {
		char salt[BCRYPT_HASHSIZE];
		char hash[BCRYPT_HASHSIZE];
		
		bcrypt_gensalt(work, salt);
		bcrypt_hashpw(pwd, salt, hash);

		return std::string(hash);
	}

	int CompareBcrypt (const char* pwd, FILE* file) {
		char outhash[BCRYPT_HASHSIZE];
		char inhash[BCRYPT_HASHSIZE];

		

		fread(inhash, BCRYPT_HASHSIZE, 1, file);

		bcrypt_hashpw(pwd, inhash, outhash);
		int res = strcmp(inhash, outhash);

		printf("%d\n", res);
		return res;
	}

	std::string AES_String (std::string str) {
		int rem = AES_BLOCKLEN - (str.length()%AES_BLOCKLEN);
		if (rem != AES_BLOCKLEN) {
			for (size_t i = 0; i < rem; i++) {
				// str+=' ';
				str+= (char)0;
			}
		}
		
		return str;
	}

	std::string AES_Encrypt (std::string str, const uint8_t* key) {
		struct AES_ctx ctx;
		uint8_t buffer[AES_BLOCKLEN];
		
		AES_init_ctx(&ctx, key);


		//char end[str.size()];
		std::string end = str;

		int parts = AES_BLOCKLEN;
		int start = 0;
		
		while (start < str.length()) {
			std::string split = str.substr(start, parts);
			for (int i = 0; i < AES_BLOCKLEN; i++) {
				buffer[i] = split[i];
			}
			AES_ECB_encrypt(&ctx, buffer);

			for (int i = start; i < start+AES_BLOCKLEN; i++) {
				end[i] = buffer[i-start];
			}
			
			start += parts;
		}

		return end;
	}
	std::string AES_Decrypt (std::string str, const uint8_t* key) {
		struct AES_ctx ctx;
		uint8_t buffer[AES_BLOCKLEN];
		
		AES_init_ctx(&ctx, key);


		//char end[str.size()];
		std::string end = std::string(str);

		int parts = AES_BLOCKLEN;
		int start = 0;
		
		while (start < str.length()) {
			std::string split = str.substr(start, parts);
			for (int i = 0; i < AES_BLOCKLEN; i++) {
				buffer[i] = split[i];
			}
			AES_ECB_decrypt(&ctx, buffer);

			for (int i = start; i < start+AES_BLOCKLEN; i++) {
				end[i] = buffer[i-start];
			}
			
			start += parts;
		}

		return end;
	}

	std::string Base64_Encode (std::string str) {
		macaron::Base64 machine = macaron::Base64();
		return machine.Encode(str);
	}

	std::string Base64_Decode (std::string str) {
		macaron::Base64 machine = macaron::Base64();
		std::string out;
		machine.Decode(str, out);
		return out;
	}

}