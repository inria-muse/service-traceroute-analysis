
//Flash plugin
// sudo dnf install http://linuxdownload.adobe.com/adobe-release/adobe-release-x86_64-1.0-1.noarch.rpm
// sudo dnf install flash-plugin

var system = require('system')
var numberOfArg = system.args.length;


//First argument => URL
var url = system.args[1];
//Second argument => timeout
var timeout = system.args[2];
// //Third argument => type (netflix / webpage / youtube / twitch)
// var pageType = system.args[3];


function sleep(ms) {
    console.log("Sleeping for " + ms.toString());
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function main(){
    var page = require('webpage').create();
    console.log("Opening " + url);
    page.open(url, async function (status) {
        page.viewportSize = { width:1024, height:768 };
        console.log("Waiting timeout...")
        await sleep(timeout);
        console.log("Closing...");
        page.close();
        phantom.exit();
    
    });    
}
main();




// setTimeout(function(){
// page.close();
//      phantom.exit();
// }, 20000);

