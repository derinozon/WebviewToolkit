#pragma once

#include <string.h>

#if !defined(ISWIN)
	#include <pwd.h>
#else
	#include <windows.h>
	#include <Lmcons.h>
#endif


namespace WVTK::Util {

	std::string os_username () {
		#if !defined(ISWIN)
			struct passwd *tmp = getpwuid (geteuid ());
			return std::string(tmp->pw_name);
		#else
			char username[UNLEN+1];
			DWORD username_len = UNLEN+1;
			auto uname = GetUserName(username, &username_len);
			return std::string("uname");
		#endif
	}

	std::string req2str (const char* req) {
		int reqlen = strlen(req)-4;
		std::string inp = std::string(req);
		return inp.substr(2, reqlen);
	}

	std::string StringTrim (std::string str) {
		return str.substr(1, str.size()-2);
	}

	std::vector<std::string> StringSplit (std::string str, char delim) {
		std::stringstream ss(str);
		std::vector<std::string> result = {};

		while( ss.good() ) {
			std::string substr;
			getline( ss, substr, delim);
			result.push_back( substr );
		}
		return result;
	}
}