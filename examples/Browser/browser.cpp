#include <sstream>
#include <algorithm>

#define USESERVER 0

#include "../../wwtk.hpp"

MAIN {
	std::string url = "https://www.youtube.com";
	WVTK::WebviewTK ui = WVTK::WebviewTK(url, "Browser", 480, 640);
	return ui.Run();
}