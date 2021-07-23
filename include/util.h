#pragma once

#include <string>

std::string req2str (const char* req) {
	int reqlen = strlen(req)-4;
	std::string inp = std::string(req);
	return inp.substr(2, reqlen);
}

std::string StringTrim (std::string str) {
	return str.substr(1, str.size()-2);
}

std::vector<std::string> StringSplit (std::string str, char delim) {
	stringstream ss(str);
	vector<string> result = {};

	while( ss.good() ) {
		string substr;
		getline( ss, substr, delim);
		result.push_back( substr );
	}
	return result;
}