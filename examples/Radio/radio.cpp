#include <sstream>
#include <algorithm>

#include "../../wwtk.hpp"

using namespace WebUI;

std::string pat = ConnectPath(CurrentPath(), "/www");
//WWTK ui = WWTK(6868, pat);
std::string filepath = "file:///Users/machina/Desktop/WebviewToolkit/examples/Radio/www/index.html";
std::string hostpath = "http://127.0.0.1:5500/examples/Radio/www/index.html";
WWTK ui = WWTK(filepath);


MAIN {

	auto cinit = [] (std::string seq, std::string req, void* arg) {
		std::string data = ReadFile("data.json");
		data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());

		std::stringstream ss;
		ss << "InitData('" << data << "');";
		
		ui.view.eval(ss.str());
	};

	ui.view.bind("cinit", cinit, NULL);

    ui.Run();
	return 0;
}