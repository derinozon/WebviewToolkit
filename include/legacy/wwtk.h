// WebUI | Derin Özön 2021

// This Header consists of two libraries merged together with my bridge functions.
// Both libraries are MIT licenced and can be found on links below
// webview by Serge Zaitsev (https://github.com/webview/webview)
// cpp-httplib by Yuji Hirose (https://github.com/yhirose/cpp-httplib)

#pragma once

#include "filemachine.hpp"
#include "webview.h"
#include "macmenu.h"
#include "httplib.h"

class WWTK {
	public:
		webview::webview view = webview::webview(false, nullptr);
		httplib::Server server;
		std::string mountDir;

		int PORT = 6666;

		//const webview::webview& view() const { return w; }

		WWTK () {
			
		}

		WWTK (std::string title, int width = 640, int height = 480) {
			Init("AutoMount()", title, width, height);
		}

		WWTK (std::string url, std::string title = "App", int width = 640, int height = 480) {
			Init(url, title, width, height);
		}

		void Init (std::string url, std::string title = "App", int width = 640, int height = 480) {
			view.navigate(url);
			view.set_size(width, height, WEBVIEW_HINT_NONE);
			view.set_title(title);
		}

		void Run () {
			#ifdef __APPLE__
			create_mac_menu();
			#endif
			view.run();
		}

		

		void ProcessDir (std::string dir) {
			const char* base = dir.c_str();
			
			for (std::string dir : ListDirectory(base, false)) {
				std::string dirPath = ConnectPath(base, dir);
				if (IsDir(dirPath)) {
					std::string mp = SubStr(dirPath, mountDir);
					TryMount(mp, dirPath);
					ProcessDir(dirPath.c_str());
				}
			}
		}

		std::string TryMount (std::string mount_point, std::string dir) {
			std::string err = "";
			
			if (!server.set_mount_point(mount_point.c_str(), dir.c_str())) {
				std::cout << "MOUNT_ERR" << std::endl;
				err = "/MOUNT_ERR";
				server.Get(err.c_str(), [err](const httplib::Request &req, httplib::Response &res) {
					res.set_header("Access-Control-Allow-Origin", "*");
					res.set_content(err, "text/plain");
				});
			}
			std::cout << "Mounted : " << mount_point << ' ' << dir << std::endl;
			return err;
		}

		void StartServer (int i) {
			TryMount("/", mountDir);
			ProcessDir(mountDir);
			std::cout << "listening on port " << PORT << std::endl;
			server.listen("localhost", PORT);
		}

		void AutoMount (int port, std::string mount_directory) {
			PORT = port;
			mountDir = mount_directory;

			std::thread t1(&WWTK::StartServer, 3);
		}

	private:
		std::thread server_thread;

		std::string SubStr (std::string text, std::string erase) {
			std::string::size_type i = text.find(erase);

			if (i != std::string::npos)
			text.erase(i, erase.length());
			return text;
		}
};