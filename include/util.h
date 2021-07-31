#pragma once

#include <string>

namespace WVTK::Util {

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