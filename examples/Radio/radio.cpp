#include <sstream>
#include <algorithm>

#define USESERVER
#include "../../wwtk.hpp"

using namespace WebUI;

std::string pat = ConnectPath(CurrentPath(), "/www");
//WWTK ui = WWTK(6868, pat);
WWTK ui = WWTK("http://127.0.0.1:5500/examples/Radio/www/index.html");


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