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

namespace WVTK::File {
	namespace fs = std::filesystem;

	std::string CurrentPath () {
		return fs::current_path().string();
	}

	std::string ConnectPath (const std::string a, const std::string b) {
		auto pp = fs::path(a);
		pp += fs::path(b);
		return pp.string();
	}

	std::string ReadFile (std::string path) {
		std::string content;
		std::ifstream file;
		file.open (path);
		while (!file.eof()) {
			std::string a;
			getline(file,a);
			content += a;
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