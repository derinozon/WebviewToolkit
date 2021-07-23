// WebUI | Derin Özön 2021

// This Header consists of two libraries merged together with my bridge functions.
// Both libraries are MIT licenced and can be found on links below
// webview by Serge Zaitsev (https://github.com/webview/webview)
// cpp-httplib by Yuji Hirose (https://github.com/yhirose/cpp-httplib)

#pragma once

#ifdef WIN32
#define MAIN int WINAPI WinMain(HINSTANCE hInt, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow) {
#else
#define MAIN int main (int argc, char** argv)
#endif

#include "include/webview.h"

#ifdef USESERVER
#include "include/httplib.h"
#endif

#include "include/filemachine.hpp"
#include "include/ezcrypto.h"
#include "include/util.h"

namespace WebUI {
	class WWTK {
		public:
			webview::webview view;

			
			
			

			std::string mountDir;
			int PORT = 0;

			WWTK () {
			
			}
			// Won't initialize the server //
			WWTK (std::string url) {
				InitView(url);
			}

			void Run () {
				view.run();
			}
			
			#ifdef USESERVER
			httplib::Server server;

			WWTK (int port, std::string mount_directory) : server_thread(&WWTK::StartServer, this) {
				PORT = port;
				mountDir = mount_directory;

				InitView("http://localhost:" + std::to_string(PORT));
			}

			void StartServer () {
				TryMount("/", mountDir);
				ProcessDir(mountDir);
				std::cout << "listening on port " << PORT << std::endl;
				server.listen("localhost", PORT);
			}

			std::string TryMount (std::string mount_point, std::string dir) {
				std::string err = "";
				
				if (!server.set_mount_point(mount_point.c_str(), dir.c_str())) {
					std::cout << MOUNT_ERR << std::endl;
					err = "/MOUNT_ERR";
					server.Get(err.c_str(), [err](const httplib::Request &req, httplib::Response &res) {
						res.set_header("Access-Control-Allow-Origin", "*");
						res.set_content(err, "text/plain");
					});
				}
				std::cout << "Mounted : " << mount_point << ' ' << dir << std::endl;
				return err;
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

			void Bind (std::string path, httplib::Server::Handler handler) {
				server.Get(path.c_str(), [handler](const httplib::Request &req, httplib::Response &res) {
					res.set_header("Access-Control-Allow-Origin", "*");
					handler(req, res);
				});
			}
			void Bind (std::string path, void(*handler)()) {
				server.Get(path.c_str(), [handler](const httplib::Request &req, httplib::Response &res) {
					handler();
				});
			}
			#else

			WWTK (int port, std::string mount_directory) {
				PORT = port;
				mountDir = mount_directory;

				InitView("http://localhost:" + std::to_string(PORT));
			}

			#endif
	
		private:
			std::thread server_thread;
			const char* MOUNT_ERR = "\033[31m Error: Mounting directory not found!\033[0m";

			void InitView (std::string init_page) {
				view.set_title("Web App");
				view.set_size(800, 450, WEBVIEW_HINT_NONE);
				view.navigate(init_page);
			}

			std::string SubStr (std::string text, std::string erase) {
				std::string::size_type i = text.find(erase);

				if (i != std::string::npos)
				text.erase(i, erase.length());
				return text;
			}
	};

	

	

	

	

	






	

	

	
}