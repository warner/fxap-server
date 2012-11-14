
var crypto = require("crypto");
var express = require("express");
var base64 = require("base64");

var emailToUserid = {};
var useridToData = {};
var nextUserid = 0;

var app = express();
app.use(express.logger);
app.use(express.bodyParser());
/*app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    return next();
    });*/

function create_salt() {
    // the salt merely needs to be unique, not unguessable (since we hand it
    // out to anyone who asks). 128 bits is enough for that.
    return create_random(16);
}
function create_random(len) {
    return base64.encode(crypto.randomBytes(len));
}

function compare(a, b) {
    // constant-time comparison, assuming lengths are equal
    if (a.length != b.length)
        return false;
    var reduction = 0;
    for (var i=0; i<a.length; i++)
        reduction |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    return reduction == 0;
}

app.post("/api/create_account", function(req, res) {
    console.log("in create_account");
    var email = req.params.email;
    if (email.indexOf("@") == -1)
        return res.send(400, "malformed email address"); // minimal
    var userid = emailToUserid[email];
    if (userid !== undefined)
        return res.send(409, "email already in use");
    userid = ""+nextUserid; // as string
    nextUserid += 1;
    emailToUserid[email] = userid;
    var salt = create_salt();
    useridToData[userid] = {S1: req.params.S1,
                            salt: salt,
                            WSUK: undefined,
                            RUK: create_random(32)
                           };
    return res.json({userid: userid,
                     salt: salt});
});

app.post("/api/get_userid", function(req, res) {
    var userid = emailToUserid[req.params.email];
    if (userid === undefined)
        return res.send(404, "unknown email address");
    return res.json({userid: userid,
                     salt: useridToData[userid].salt});
});

app.post("/api/sign_key", function(req, res) {
    var userid = emailToUserid[req.params.email];
    if (userid === undefined)
        return res.send(404, "unknown email address");
    var data = useridToData[userid];
    if (!compare(req.params.S1, data.S1))
        return res.send(401, "bad authorization string");
    var pubkey = req.params.pubkey;
    if (!pubkey)
        return res.send(400, "malformed public key");
    var signed = sign_key(req.params.email, pubkey);
    return res.json({cert: signed});
});

app.post("/api/set_keys", function(req, res) {
    var userid = req.params.userid;
    var data = useridToData[userid];
    if (data === undefined)
        return res.send(404, "unknown email address");
    if (!compare(req.params.S1, data.S1))
        return res.send(401, "bad authorization string");
    data.WSUK = req.params.WSUK;
    return res.json({});
});

app.post("/api/get_keys", function(req, res) {
    var userid = req.params.userid;
    var data = useridToData[userid];
    if (data === undefined)
        return res.send(404, "unknown email address");
    if (!compare(req.params.S1, data.S1))
        return res.send(401, "bad authorization string");
    return res.json({WSUK: data.WSUK, RUK: data.RUK});
});

app.post("/api/get_entropy", function(req, res) {
    return res.json({entropy: create_random(32)});
});

app.listen(8081);
console.log("listening on port 8081");
