#include <sstream>
#include <algorithm>

#define USESERVER 0

#include "../../webviewtk.hpp"

MAIN {
	std::string url = "https://www.google.com";
	WVTK::WebviewTK ui = WVTK::WebviewTK(url, "Browser", 480, 640);
	return ui.Run();
}