#include <sstream>
#include <algorithm>

#include "../../wwtk.hpp"

using namespace WVTK::File;

std::string path = ConnectPath(CurrentPath(), "/www");
WVTK::WebviewTK ui = WVTK::WebviewTK(path, 6868);

MAIN {
		
	auto cinit = [] (std::string seq, std::string req, void* arg) {
		std::string data = ReadFile("data.json");
		data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());

		std::stringstream ss;
		ss << "InitData('" << data << "');";
		
		ui.view.eval(ss.str());
	};

	ui.view.bind("cinit", cinit, NULL);
	ui.view.set_title("Radio");

    ui.Run();
	return 0;
}