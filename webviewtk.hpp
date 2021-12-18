// Webview Toolkit | Derin Özön 2021

// This Header consists of two libraries merged together with my bridge functions.
// Both libraries are MIT licenced and can be found on links below
// webview by Serge Zaitsev (https://github.com/webview/webview)
// cpp-httplib by Yuji Hirose (https://github.com/yhirose/cpp-httplib)

#include <algorithm>

#pragma once

#if defined(WIN32) || defined(_WIN32)
#define ISWIN
#endif

#ifdef ISWIN
#define MAIN int WINAPI WinMain(HINSTANCE hInt, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow)
#else
#define MAIN int main (int argc, char** argv)
#endif

#if !defined(USESERVER) && defined(ISWIN)
#define USESERVER 1
#endif

#if !defined(USESERVER) && !defined(ISWIN)
#define USESERVER 0
#endif

#if USESERVER == 1
#include "include/httplib.h"
#endif

#include "include/webview.h"

#include "include/filemachine.hpp"
#include "include/util.h"

#if !defined(ISWIN)
#include "include/macmenu.h"
#include "include/crypto/crypto.h"
#endif

namespace WVTK {
	

	class WebviewTK {
		public:
			webview::webview view = webview::webview(true, nullptr);

			std::string mountDir;
			int PORT = 0;

			WebviewTK () {
			
			}
			// Won't initialize the server //
			WebviewTK (std::string url) {
				InitView(url);
			}
			WebviewTK (std::string url, std::string title = "Web App", int width=640, int height=480) {
				InitView(url, title, width, height);
			}
			#if USESERVER == 1
			WebviewTK (std::string mount_directory, int port = 6868) : server_thread(&WebviewTK::StartServer, this) {
				PORT = port;
				mountDir = mount_directory;
				std::cout << "Initialising server..." << std::endl;

				InitView("http://localhost:" + std::to_string(PORT));
			}
			#else
			WebviewTK (std::string mount_directory, int port) {
				//char backslash = 92;
				//std::replace( mount_directory.begin(), mount_directory.end(), backslash, '/');
				InitView("file:///" + mount_directory + "/index.html");
			}
			#endif

			int Run () {
				view.navigate(initial_page);
				view.run();
				if (server_thread.joinable()) {
					std::cout << "Joined Thread" << std::endl;
					server_thread.join();
				}
					
				return 0;
			}
			
			#if USESERVER == 1
			httplib::Server server;

			

			void StartServer () {
				//server.set_file_extension_and_mimetype_mapping("js", "application/javascript");
				TryMount("/", mountDir);
				ProcessDir(mountDir);
				
				server.listen("localhost", PORT);
				std::cout << "listening on port " << PORT << std::endl;
			}

			void TryMount (std::string mount_point, std::string dir) {
				
				if (!server.set_mount_point(mount_point.c_str(), dir.c_str())) {
					Log("MOUNT_ERR");

					server.Get("/MOUNT_ERR", [](const httplib::Request &req, httplib::Response &res) {
						res.set_header("Access-Control-Allow-Origin", "*");
						res.set_content("MOUNT_ERR", "text/plain");
					});
				}
			}

			void ProcessDir (std::string dir) {
				const char* base = dir.c_str();
				
				for (std::string dir : File::ListDirectory(base, false)) {
					std::string dirPath = File::ConnectPath(base, dir);
					if (File::IsDir(dirPath)) {
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

			WebviewTK (int port, std::string mount_directory) {
				PORT = port;
				mountDir = mount_directory;

				InitView("http://localhost:" + std::to_string(PORT));
			}
			#endif

			void EvalOnPageLoad (std::string js) {
				view.eval("window.addEventListener('DOMContentLoaded', () => {"+js+"});");
			}
	
		private:
			std::thread server_thread;
			std::string initial_page = "https://www.google.com";

			void InitView (std::string init_page, std::string title = "Web App", int width=640, int height=480) {
				view.set_title(title);
				view.set_size(width, height, WEBVIEW_HINT_NONE);

				initial_page = init_page;

				#ifdef __APPLE__
				create_mac_menu();
				#endif
			}

			std::string SubStr (std::string text, std::string erase) {
				std::string::size_type i = text.find(erase);

				if (i != std::string::npos)
				text.erase(i, erase.length());
				return text;
			}

			void Log (std::string message) {
				std::cout << message << std::endl;
			}
	};
}