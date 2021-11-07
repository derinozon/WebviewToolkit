#include <iostream>
#include <sstream>

#include "../../webviewtk.hpp"

using namespace std;
using namespace WVTK::File;
using namespace WVTK::Util;
using namespace WVTK::Crypto;

std::string pat = ConnectPath(CurrentPath(), "/www");
WVTK::WebviewTK ui = WVTK::WebviewTK(pat, 6868);

uint8_t key[64];

MAIN {
	ui.view.set_title(os_username()+"'s notebook");

	std::string workspace = CurrentPath();

	// std::string indexPath = ConnectPath(workspace, "/www/index.html");
    // std::string result = "file:///" + indexPath;

	std::string dataPath = ConnectPath(workspace, "/data");

	vector<string> files = GetAllFiles(dataPath, {".bin"});
	vector<string> file_content(files.size());

	for (size_t i = 0; i < files.size(); i++) {
		std::stringstream ss;
		file_content[i] = ReadFile(files[i]);

  		ss << "window.addEventListener('DOMContentLoaded', () => { "
			<< "Add('" << GetFileName(files[i]) << "','" << file_content[i] << "')"
		<< " });";
		//ui.view.eval(ss.str());
	}
	
	

	auto login = [] (std::string seq, std::string req, void* arg) {
		std::string inp = StringTrim( StringTrim(req) );
		printf("%s\n", inp.c_str());

	
		
		int pass = !CompareBcrypt(inp.c_str());

		if (pass) {
			
			// const uint8_t key[16] = "rootrootrootroo";
			
			for (size_t i = 0; i < 64; i++) {
				if (i > inp.length()) {
					key[i] = ' ';
				}
				else {
					key[i] = inp[i];
				}
			}
			
			// strcpy((char*)key, inp.c_str());
			
			
			string str = AES_Decrypt(ReadFile("notes.bin", true), key);
			std::cout << "Decoded : " << str << std::endl;
			
			

			
			// cout << result << endl;

			// result = AES_Decrypt(result, key);
			// cout << result << endl;

			
			
			
			
			


			// uint8_t buffer[AES_BLOCKLEN*4] = "Hello My name is unknown nice to meet you!";

			// const uint8_t key[64] = "root";
			// uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
			// AES_init_ctx_iv(&ctx, key, iv);
			
			// AES_CBC_encrypt_buffer(&ctx, buffer, 64);
			// cout << buffer << endl << endl << endl << endl;

			// AES_CBC_decrypt_buffer(&ctx, buffer, 64);
			// cout << buffer << endl << endl;
			

			// ui.view.eval("txt = \"" + ReadFile("text.txt") + "\";");
			ui.view.eval("txt = \"" + str + "\";");
			ui.view.eval("login_success()");


			str = "<h1>Passwords</h1><p>jeffbezos@amazon.com</p><button onclick=copy('pw')>copy password</button>";
			// str = "Hello My name is unknown nice to meet you!";
			// str = AES_String(str);
			// str = AES_Encrypt(str, key);
			
			
		}
		else {
			ui.view.eval("login_fail()");
		}

		
	};

	auto encrypt = [] (std::string seq, std::string req, void* arg) {
		std::string inp = StringTrim( StringTrim(req) );

		inp = AES_String(inp);
		inp = AES_Encrypt(inp, key);

		WriteFile("notes.bin", inp);
	};

	ui.view.bind("c_login", login, NULL);
	ui.view.bind("c_encrypt", encrypt, NULL);
	
    ui.Run();
	
	return 0;
}