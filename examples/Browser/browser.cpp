#include <sstream>
#include <algorithm>

#include "../../wwtk.hpp"

using namespace WebUI;

MAIN {
	WWTK ui = WWTK("https://www.youtube.com", 480, 640);
	return ui.Run();
}