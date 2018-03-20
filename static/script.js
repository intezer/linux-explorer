
function hash(path, handler) {
    $.get('/fs/hash', { 'path': path }, function(data, status) {
        if (status == "success") {
            handler(data['md5'], data["sha256"]);
        } else {
            console.log("error! could not hash " + path + " . status:" + status);
        }
    });
}

/* --- MalShare --- */
function MalShare_search(sha256, handler, error) {
    $.get("/malshare/" + sha256, function(data, status) {
        if (status === "success") {
            if (data.hasOwnProperty("error")) {
                error(data["error"]);
            } else {
                handler(data);
            }
        }
    });
}


/* --- VirusTotal --- */
function VT_search(sha256, handler, error, interval=5000) {
    $.get("/vt/report/" + sha256, function(data, status) {
        if (status == "success" && data["response_code"] != -2) {
            if(data.hasOwnProperty("error")) {
                error(data["error"]);
            } else {
                handler(data);
            }
        } else {
            setTimeout(function () {
                VT_search(sha256, handler, interval); // retry until success
            }, interval);
        }
    });
}

function VT_upload(path, handler, error) {
    $.get("/vt/upload", { "path": path },function(data, status) {
        if (status == "success") {
            if(data.hasOwnProperty("error")) {
                error(data["error"]);
            } else {
                handler(data);
            }
        } else {
            error("faild to upload " + path);
        }
    });
}

/* --- Open Threat Exchange --- */
function OTX_pulses(type, indicator, handler, error) {
    $.get("/otx/" + type + "/" + indicator, function (data, status) {
        if (status == "success") {
            if(data.hasOwnProperty("error")) {
                error(data["error"]);
            } else {
                handler(data["general"]["pulse_info"]["pulses"]);
            }
        }
    });
}

function OTX_link(pulse) {
    return "<a href=\"https://otx.alienvault.com/pulse/" + pulse["id"] + "/\" target=\"_blank\">" +  pulse["name"] + "</a>";
}
