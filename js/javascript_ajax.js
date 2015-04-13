__author__ = 'aitor'
 function GetTweet() {
    nocache = "nocache=" + Math.random() * 1000000;
    var request = new XMLHttpRequest();

    request.onreadystatechange = function() {
        if (request.readyState == 4) {
            if (request.status == 200) {
                if (request.responseText != null) {
                    var jsonObj = JSON.parse(request.responseText);
                    document.getElementsByClassName("name1")[0].innerHTML = jsonObj.name1;
                    document.getElementsByClassName("tweet1")[0].innerHTML = jsonObj.tweet1;

                    document.getElementsByClassName("name2")[0].innerHTML = jsonObj.name2;
                    document.getElementsByClassName("tweet2")[0].innerHTML = jsonObj.tweet2;

                    document.getElementsByClassName("name3")[0].innerHTML = jsonObj.name3;
                    document.getElementsByClassName("tweet3")[0].innerHTML = jsonObj.tweet3;
                }
            }
        }
    };
    request.open("GET", "/RefreshLast3Tweets?"+nocache, true);
    request.send(null);
    setTimeout("GetTweet()", 60000);
}