#pragma once

#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <string>
#include <dirent.h>

using namespace std;
namespace fs = std::filesystem;

std::string CurrentPath () {
	return fs::current_path().string();
}

std::string ConnectPath (const std::string a, const std::string b) {
	auto pp = fs::path(a);
	pp += fs::path(b);
	return pp.string();
}

string ReadFile (string path) {
	string content;
	ifstream file;
	file.open (path);
	while (!file.eof()) {
		string a;
		getline(file,a);
		content += a;
	}
	
	file.close();
	return content;
}

void WriteFile (string path, string content) {
	ofstream file;
	file.open (path);
	file << content;
	file.close();
}

void DeleteFile (string filePath) {
	fs::remove(fs::path(filePath));
}

void DeleteFiles (vector<string> files) {
	for (string file : files) {
		DeleteFile(file);
	}
}

vector<string> GetAllFiles (string path,vector<string> extensions, bool recursive = false) {

	vector<string> finalList = {};

	if (recursive) {
		for (const auto& p: fs::recursive_directory_iterator(path)) {
			fs::path file = p.path();
			string fileExt = file.extension().string();

			for (string ext : extensions) {
				if (fileExt == ext) {
					finalList.push_back(file.string());
				}
			}
		}
	}
	else {
		for (const auto& p: fs::directory_iterator(path)) {
			fs::path file = p.path();
			string fileExt = file.extension().string();

			for (string ext : extensions) {
				if (fileExt == ext) {
					finalList.push_back(file.string());
				}
			}
		}
	}
    
	return finalList;
}

bool FileExists (string path) {
	return fs::exists(fs::path(path));
}

void MakeDir (string path) {
	fs::create_directory(path);
}

void MoveFile (string path,string to) {
	auto p = fs::path(path);
	
	fs::rename(p,to);
}

// int GetFileEpoch (string path) {
// 	auto p = fs::path(path);
// 	auto t = fs::last_write_time(p);
// 	int e = t.time_since_epoch().count();
// 	return e;
// }

string GetFileName (string path) {
	auto p = fs::path(path);
	return p.filename();
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