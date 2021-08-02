#pragma once

id operator"" _cls(const char *s, std::size_t) { return (id)objc_getClass(s); }
SEL operator"" _sel(const char *s, std::size_t) { return sel_registerName(s); }
id operator"" _str(const char *s, std::size_t) { return objc_msgSend("NSString"_cls, "stringWithUTF8String:"_sel, s); }

void create_mac_menu () {
	id app = objc_msgSend("NSApplication"_cls, "sharedApplication"_sel);
	objc_msgSend(app, "mainMenu"_sel, nil);



	id m1 = objc_msgSend(
		objc_msgSend("NSMenu"_cls, "alloc"_sel),
		"initWithTitle:"_sel, "MainMenu"_str
	);

	id m2 = objc_msgSend(
		objc_msgSend("NSMenuItem"_cls, "alloc"_sel),
		"initWithTitle:action:keyEquivalent:"_sel, "MenuTwo"_str, nil, ""_str
	);

	id m3 = objc_msgSend(
		objc_msgSend("NSMenu"_cls, "alloc"_sel),
		"initWithTitle:"_sel, "Menu3"_str
	);

	id quitMenuItem = objc_msgSend(
		objc_msgSend("NSMenuItem"_cls, "alloc"_sel),
		"initWithTitle:action:keyEquivalent:"_sel, "Quit"_str, "terminate:"_sel, "q"_str
	);

	id mm2 = objc_msgSend(
		objc_msgSend("NSMenuItem"_cls, "alloc"_sel),
		"initWithTitle:action:keyEquivalent:"_sel, "MenuTwo"_str, nil, ""_str
	);

	id mm3 = objc_msgSend(
		objc_msgSend("NSMenu"_cls, "alloc"_sel),
		"initWithTitle:"_sel, "Edit"_str
	);

	id cutMenuItem = objc_msgSend(
		objc_msgSend("NSMenuItem"_cls, "alloc"_sel),
		"initWithTitle:action:keyEquivalent:"_sel, "Cut"_str, "cut:"_sel, "x"_str
	);

	id copyMenuItem = objc_msgSend(
		objc_msgSend("NSMenuItem"_cls, "alloc"_sel),
		"initWithTitle:action:keyEquivalent:"_sel, "Copy"_str, "copy:"_sel, "c"_str
	);

	id pasteMenuItem = objc_msgSend(
		objc_msgSend("NSMenuItem"_cls, "alloc"_sel),
		"initWithTitle:action:keyEquivalent:"_sel, "Paste"_str, "paste:"_sel, "v"_str
	);

	objc_msgSend(app, "setMainMenu:"_sel, m1);

	objc_msgSend(m1, "addItem:"_sel, m2);
	objc_msgSend(m2, "setSubmenu:"_sel, m3);
	objc_msgSend(m3, "addItem:"_sel, quitMenuItem);

	objc_msgSend(m1, "addItem:"_sel, mm2);
	objc_msgSend(mm2, "setSubmenu:"_sel, mm3);
	objc_msgSend(mm3, "addItem:"_sel, cutMenuItem);
	objc_msgSend(mm3, "addItem:"_sel, copyMenuItem);
	objc_msgSend(mm3, "addItem:"_sel, pasteMenuItem);
}