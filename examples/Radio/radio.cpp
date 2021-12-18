#include <sstream>

#include "../../webviewtk.hpp"

using namespace WVTK::File;

std::string path = ConnectPath(CurrentPath(), "/www");
WVTK::WebviewTK ui = WVTK::WebviewTK(path, 6868);

MAIN {
	ui.view.set_title("Radio");
	
	std::string dataPath = ConnectPath(CurrentPath(), "data.json");
	std::string data = ReadFile(dataPath);

	data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());

	ui.EvalOnPageLoad("InitData('"+data+"');");
    ui.Run();
	return 0;
}