function GetTimeIO() {
	nocache = "nocache=" + Math.random() * 1000000; // Nabigatzaileak HTTP erantzunak aurrememorian gorde ez ditzan
	var request = new XMLHttpRequest(); // Nabigatzaileak HTTP erantzunak aurrememorian gorde ez ditzan

	request.onreadystatechange = function() {
	if (request.readyState == 4) { // XMLHttpRequest-en status-a: 4-aren esanahia: request finished and response is ready
		if (request.status == 200) { // HTTP erantzunaren status-a
			if (request.responseText != null) { // erantzunak edukirik al dauka?
				var jsonObj = JSON.parse(request.responseText); // HTTP erantzunetik edukia string bezela jaso (request.responseText)
				                                                // eta JSON bihurtu (JSON.parse())
				document.getElementsByClassName("year")[0].innerHTML = jsonObj.urtea;
				document.getElementsByClassName("month")[0].innerHTML = jsonObj.hilabetea;
				document.getElementsByClassName("day")[0].innerHTML = jsonObj.eguna;
				document.getElementsByClassName("hour")[0].innerHTML = jsonObj.orduak;
				document.getElementsByClassName("minute")[0].innerHTML = jsonObj.minutuak;
				document.getElementsByClassName("second")[0].innerHTML = jsonObj.segunduak;
			}
		}
	}
};

request.open("GET", "/currentTime?" + nocache, true); // HTTP eskaera prestatu
request.send(null); // HTTP eskaera bidali
setTimeout("GetTimeIO()", 1000);} // GetArduinoIO funtzioa segunduro deitu, hau da,
                                  // segunduro HTTP eskaera egin eta honen erantzuna prozesatu
