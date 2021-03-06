#pragma once

#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <string>

#if defined(WIN32) || defined(_WIN32)
#include "dirent.h"
#else
#include <dirent.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <limits.h>
#endif

namespace WVTK::File {
	namespace fs = std::filesystem;

	std::string CurrentPath () {
		#if defined(ISWIN)
			return fs::current_path().string();
		#elif defined(__APPLE__)
			char buf [PATH_MAX];
			uint32_t bufsize = PATH_MAX;
			_NSGetExecutablePath(buf, &bufsize);
			std::string str = buf;
			std::size_t found = str.find_last_of("/\\");
			str = str.substr(0,found);
			return str;
		#else
			char path[FILENAME_MAX];
			ssize_t count = readlink("/proc/self/exe", path, FILENAME_MAX);
			return std::filesystem::path(std::string(path, (count > 0) ? count: 0)).parent_path().string();
		#endif
		
	}

	std::string ConnectPath (std::string a, std::string b) {
		if (b[0] != '/') b = '/'+b;
		auto pp = fs::path(a);
		pp += fs::path(b);
		return pp.string();
	}
	/*
	std::string ReadBinary (std::string path) {
		std::ifstream file(path, std::ios::binary | std::ios::ate);
		file.seekg(0, std::ios::end);
		int fsize=file.tellg();
		file.seekg(0, std::ios::beg);
		file.close();
		fsize = fs::file_size(path);
		std::ifstream rf(path, std::ios::out | std::ios::binary);
		char arr[fsize];
		std::string out;
		rf.read(arr, fsize);
   		rf.close();
		return std::string(arr);
	}

	void WriteBinary (std::string path, std::string content) {
		// UPDATE //
		std::ofstream file(path, std::ios::in | std::ios::binary);
		file << content;
		file.close();
	}
	*/

	std::string ReadFile (std::string path, bool raw = false) {
		std::string content;
		std::ifstream file;
		file.open (path);
		while (!file.eof()) {
			std::string a;
			getline(file,a);
			content += (raw ? a : a+"\\n");
		}
		
		file.close();
		return content;
	}

	void WriteFile (std::string path, std::string content) {
		std::ofstream file;
		file.open (path);
		file << content;
		file.close();
	}

	void DeleteFile (std::string filePath) {
		fs::remove(fs::path(filePath));
	}

	void DeleteFiles (std::vector<std::string> files) {
		for (std::string file : files) {
			DeleteFile(file);
		}
	}

	std::vector<std::string> GetAllFiles (std::string path,std::vector<std::string> extensions, bool recursive = false) {

		std::vector<std::string> finalList = {};

		if (recursive) {
			for (const auto& p: fs::recursive_directory_iterator(path)) {
				fs::path file = p.path();
				std::string fileExt = file.extension().string();

				for (std::string ext : extensions) {
					if (fileExt == ext) {
						finalList.push_back(file.string());
					}
				}
			}
		}
		else {
			for (const auto& p: fs::directory_iterator(path)) {
				fs::path file = p.path();
				std::string fileExt = file.extension().string();

				for (std::string ext : extensions) {
					if (fileExt == ext) {
						finalList.push_back(file.string());
					}
				}
			}
		}
		
		return finalList;
	}

	bool FileExists (std::string path) {
		return fs::exists(fs::path(path));
	}

	void MakeDir (std::string path) {
		fs::create_directory(path);
	}

	void MoveFile (std::string path,std::string to) {
		auto p = fs::path(path);
		
		fs::rename(p,to);
	}

	// int GetFileEpoch (string path) {
	// 	auto p = fs::path(path);
	// 	auto t = fs::last_write_time(p);
	// 	int e = t.time_since_epoch().count();
	// 	return e;
	// }

	std::string GetFileName (std::string path) {
		auto p = fs::path(path);
		return p.filename().string();
	}

	inline bool IsDir (std::string dirPath) {
		fs::path path(dirPath);
		return fs::is_directory(path);
	}


	inline std::vector<std::string> ListDirectory (const char* path, bool showHidden) {
		DIR *d = opendir(path);
		struct dirent *dir;

		std::vector<std::string> finalList;
		if (d) {
			while ((dir = readdir(d))) {
				char* d_name = dir->d_name;
				
				bool canPrint = !((strlen(d_name) == 1 && d_name[0] == '.')||(strlen(d_name) == 2 && d_name[0] == '.' && d_name[1] == '.'));
				if (canPrint) {
					canPrint = (showHidden)||(d_name[0] != '.');
				}
				if (canPrint) {
					finalList.push_back(std::string(d_name));
				}
			}
			closedir(d);
		}
		return finalList;
	}
}