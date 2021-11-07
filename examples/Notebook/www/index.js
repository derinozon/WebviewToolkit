
const text_area = document.getElementsByTagName("textarea")[0];
const dump = document.getElementById("dump");
var txt = "";

const edit_toggle = document.getElementById("edit-toggle");
edit_toggle.addEventListener("click", () => {
	if (edit_toggle.checked) {
		text_area.style.display = "block";
		dump.style.display = "none";
		text_area.value = txt;
	}
	else {
		text_area.style.display = "none";
		dump.style.display = "block";
		txt = text_area.value;
		dump.innerHTML = txt;

		c_encrypt(txt);
	}
});

function login () {
	c_login(login_input.value);
}

var login_section = document.getElementById("login-section");
var login_input = login_section.getElementsByTagName("input")[0];
var main_section = document.getElementById("main-section");

login_input.addEventListener("keyup", (event) => {
	if (event.keyCode === 13) {
		login();
	}
});

function login_success () {
	//login_section.style.display = "none";
	login_section.remove();
	main_section.style.display = "initial";
	dump.innerHTML = txt;
}

function login_fail () {
	login_input.style.borderColor = "red";
}

text_area.style.display = "none";
main_section.style.display = "none";

login_input.focus();





function copy (val) {
	navigator.clipboard.writeText(val);
}

function gettext () {
	return text_area.value;
}