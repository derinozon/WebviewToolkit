// WARNING! USING THIS EXAMPLE AS SOFTWARE IS NOT SAFE //
// I tried to implement AES to make it safe but failed to do it :( //
// CURRENTLY DOES NOT WORK ON WINDOWS //

#include <iostream>
#include <sstream>

#include "../../webviewtk.hpp"

using namespace std;
using namespace WVTK::File;
using namespace WVTK::Util;
using namespace WVTK::Crypto;

std::string workspace = CurrentPath();
std::string pat = ConnectPath(workspace, "/www");
string notesPath = ConnectPath(workspace, "notes.bin");
string hashPath = ConnectPath(workspace, "hash.bin");
WVTK::WebviewTK ui = WVTK::WebviewTK(pat, 6868);

uint8_t key[16];


MAIN {
	ui.view.set_title(os_username()+"'s notebook");

	

	auto login = [] (std::string seq, std::string req, void* arg) {
		std::string inp = StringTrim( StringTrim(req) );
		
		FILE* file = fopen(hashPath.c_str(), "r");
		int pass = !CompareBcrypt(inp.c_str(), file);
		//fclose(file);

		if (pass) {
			string str = "";
			
			if (FileExists(notesPath)) {
				str = ReadFile(notesPath, true);
				str = Base64_Decode(str);
			}
			

			// for (size_t i = 0; i < 64; i++) {
			// 	if (i >= inp.length()) {
			// 		key[i] = '_';
			// 	}
			// 	else {
			// 		key[i] = inp[i];
			// 	}
			// }
			
			// str = AES_Decrypt(file, key);
			// // Cleans all null terminators //
			// str.erase(std::remove(str.begin(), str.end(), (char)0), str.end());
			// std::cout << "Decoded : " << str << std::endl;
			
			ui.view.eval("txt = \"" + str + "\";	login_success();");
		}
		else {
			ui.view.eval("login_fail()");
		}
	};

	auto reg = [] (std::string seq, std::string req, void* arg) {
		std::string inp = StringTrim( StringTrim(req) );

		FILE* file = fopen(hashPath.c_str(), "w");
		WriteBcrypt(inp.c_str(), file);
		fclose(file);
		ui.view.eval("txt = '';	login_success();");
	};

	auto encrypt = [] (std::string seq, std::string req, void* arg) {
		std::string inp = StringTrim( StringTrim(req) );

		// inp = "<h1>Passwords</h1><p>jeffbezos@amazon.com</p><button onclick=copy('pw')>copy password</button>";
		// inp = AES_String(inp);
		// inp = AES_Encrypt(inp, key);
		inp = Base64_Encode(inp);

		WriteFile(notesPath, inp);
	};

	ui.view.bind("c_login", login, NULL);
	ui.view.bind("c_register", reg, NULL);
	ui.view.bind("c_encrypt", encrypt, NULL);

	string command = "js_set_uname('"+os_username()+"');";

	if (!FileExists(hashPath)) {
		command += "login_section.style.display = 'none';	register_input.focus();";
	}
	else {
		command += "register_section.style.display = 'none';	login_input.focus();";
	}
	
	ui.EvalOnPageLoad(command);
    ui.Run();
	
	return 0;
}