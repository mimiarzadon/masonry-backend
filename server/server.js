require('./passport');
require("dotenv").config();
require("./config/database").connect();
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const express = require('express');
const passport = require('passport');
const refresh = require('passport-oauth2-refresh');
const cookieSession = require('cookie-session');
//import google api
const { google } = require('googleapis')
const fs = require("fs");
const https = require('https');
const cors = require('cors');
const path = require('path');
const { default: intlFormat } = require('date-fns/intlFormat');
const { setDefaultResultOrder } = require('dns');
var pathToJson_1 = path.resolve(__dirname, './credentials.json');
const credentials = JSON.parse(fs.readFileSync(pathToJson_1));
const axios = require('axios');
const { Console } = require('console');
const app = express();

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QR = require("qrcode");
const User = require("./model/user");
const ConnectedDevice = require("./model/connectedDevice");
const QRCode = require("./model/qrCode");

const {response} = require('express');

var tokenNow = ""
var userId = ""
var generatedToken = ""
var scannedToken = ""

var accountType = "" // msgraph , google

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieSession({
    name: 'google-auth-session',
    keys: ['key1', 'key2']
}))

const isLoggedIn = (req, res, next) => {
    if (req.user) {
        next();
    } else {
        res.sendStatus(401);
    }
}

app.use(passport.initialize());
app.use(passport.session());

const port = process.env.PORT || 8443
const qrtoken = process.env.TOKEN_KEY || "random"

app.get("/", (req, res) => {
    res.json({ message: "You are not logged in" })
})

app.get("/failed", (req, res) => {
    res.send("Failed")
})
app.get("/success", (req, res) => {
    res.send(`Welcome ${req.user.email}`)
})

app.get("/linked-in", (req, res) => {

    // step 1
    const pathToJson = path.resolve(__dirname, "./" + req.query.user + ".json");
    const sessionFile = { userName: req.query.user.toLowerCase(), gtoken: pathToJson };

    console.log("getTokenFile: Hello Mimi")

    let data = JSON.stringify(sessionFile);
    fs.writeFileSync('./session.json', data);

    clearTokenFile()

    if (req.query.accType === "google") {
        res.redirect('/google')
    }
    else if (req.query.accType === "msgraph") {
        res.redirect('/auth/microsoft')
    }


})

const { networkInterfaces } = require('os');

const getIPAddress = () => {
  const nets = networkInterfaces();
  const results = {};

  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      // Retrieve only IPv4 addresses
      if (net.family === 'IPv4' && !net.internal) {
        if (!results[name]) {
          results[name] = [];
        }
        results[name].push(net.address);
      }
    }
  }
  
  // Return the first IP address for the first NIC found
  const nicNames = Object.keys(results);
  if (nicNames.length > 0) {
    const firstNICAddresses = results[nicNames[0]];
    if (firstNICAddresses.length > 0) {
      return firstNICAddresses[0];
    }
  }
  
  // No IP address found
  return null;
};



const ipAddress = getIPAddress();
console.log(ipAddress);


var options =
{
  key: fs.readFileSync('keys/server.key'),
  cert: fs.readFileSync('keys/server.crt')
};


function getTokenFile() {
    if (tokenNow === "" || accountType === "") {
        var pathToSession = path.resolve(__dirname, '../session.json');
        let session = JSON.parse(fs.readFileSync(pathToSession));

        tokenNow = session.gtoken;

        // accountType
        var pathToJson_2 = path.resolve(__dirname, tokenNow);
        const tokens = JSON.parse(fs.readFileSync(pathToJson_2));

        // console.log("getTokenFile: ", tokens.google, tokens.msgraph)
        if (tokens.google !== undefined) {
            accountType = "google"
        }
        else if (tokens.msgraph !== undefined) {
            accountType = "msgraph"
        }
        // console.log("getTokenFile: ", tokens, tokenNow, accountType)

    }
    else {
    }
    return tokenNow;
}

function clearTokenFile() {
    tokenNow = ""
    accountType = ""
    accountType = ""
}


function setTokenFile(refreshToken, accessToken) {
    var doSave = false
    if (typeof refreshToken === "string" || typeof accessToken === "string") // TODO: logic if argument is NULL
    {
        var pathToSession = path.resolve(__dirname, '../session.json');
        let session = JSON.parse(fs.readFileSync(pathToSession));

        var pathToJson_2 = path.resolve(__dirname, session.gtoken);
        const tokens = JSON.parse(fs.readFileSync(pathToJson_2));

        if (tokens.google !== undefined) {
            var tokObjInfo = JSON.parse(tokens.google)
            tokObjInfo.access_token = accessToken;
            // tokObjInfo.refresh_token = refreshToken;

            var tokStrInfo = JSON.stringify(tokObjInfo)
            tokens.google = tokStrInfo
            doSave = true
        }
        else if (tokens.msgraph !== undefined) {

            var tokObjInfo = JSON.parse(tokens.msgraph)
            tokObjInfo.access_token = accessToken;
            tokObjInfo.refresh_token = refreshToken;

            var tokStrInfo = JSON.stringify(tokObjInfo)
            tokens.msgraph = tokStrInfo

            doSave = true
        }

        if (doSave) {
            // // console.log("will save the new token: ", tokens)
            // write token to token file
            let updatedTokenFile = JSON.stringify(tokens);
            fs.writeFileSync(pathToJson_2, updatedTokenFile);

        }
    }
}

function getGoogleToken(tok) {
    //read token file you saved earlier in passport_setup.js
    var pathToJson_2 = path.resolve(__dirname, tok);
    //get tokens to details to object
    const tokens = JSON.parse(fs.readFileSync(pathToJson_2));

    var realTok = tokens.google !== null ? JSON.parse(tokens.google) : null

    return realTok !== null ? realTok : null
}

function getMsGraphToken(tok) {
    // console.log("Being called from " + arguments.callee.caller.toString());
    //read token file you saved earlier in passport_setup.js
    var pathToJson_2 = path.resolve(__dirname, tok);
    //get tokens to details to object
    const tokens = JSON.parse(fs.readFileSync(pathToJson_2));

    var realTok = tokens.msgraph !== null ? JSON.parse(tokens.msgraph) : null

    return realTok !== null ? realTok : null
}

function refreshToken() {
    var tok = getTokenFile();


    var tokens = null
    var strategyType = null

    if (accountType === "google") {
        // console.log("gone through ms path")
        tokens = getGoogleToken(tok)
        strategyType = "google"
    }
    else if (accountType === "msgraph") {
        tokens = getMsGraphToken(tok)
        strategyType = "microsoft"
    }

    // console.log("old accessToken: ", tokens.access_token)
    // console.log("old refreshToken: ", tokens.refresh_token)

    refresh.requestNewAccessToken(
        strategyType,
        tokens.refresh_token,
        function (err, accessToken, refreshToken) {

            // console.log("err: ", err)
            // console.log("new accessToken: ", accessToken)
            // console.log("new refreshToken: ", refreshToken)

            if (err === null) {
                setTokenFile(refreshToken, accessToken)
            }
        },
    );
}

app.get("/try", (req, res) => {


    // getTokenFile()

    // let myUrl = `https://graph.microsoft.com/v1.0/me/todo/lists/AQMkADAwATMwMAItNGYwZi01OTRjLTAwAi0wMAoALgAAAzWtymRWT08AQIKhndHG8I2EAQAbWMWWlYcFSLXuz2S5KiArAAAABD8ytAAAAA==/tasks/AQMkADAwATMwMAItNGYwZi01OTRjLTAwAi0wMAoARgAAAzWtymRWT08AQIKhndHG8I2EBwAbWMWWlYcFSLXuz2S5KiArAAAABD8ytAAAABtYxZaVhwVIte7PZLkqICsAAAAFCM23AAAA`

    // axios({
    //     method: 'patch',
    //     url: myUrl,
    //     headers: {
    //         Authorization: `Bearer ${tokens.access_token}`,
    //         'Content-Type': 'application/json'
    //     },
    //     data: {
    //         title: 'EggBendsOverRow'
    //     }
    //   }).then( response => {

    //             // console.log("output here for try ")
    //             // console.log(response.data)

    //             // // console.log(response.data.value[0].emailAddress)
    //           }).catch(error => {
    //             // console.log("error here ")
    //             // console.log(error)
    //           })


})

app.get("/log-in", (req, res) => {

    // step 1        

    clearTokenFile()

    let sessionList = JSON.parse(fs.readFileSync("./sessionList.json"));
    let index = sessionList.userList.findIndex((element) => element.userName.toLowerCase() === req.query.user.toLowerCase())
    if (index !== -1) {
        // console.log("has found user")
        // if session list is existing, there is no need for 
        const pathToJson = path.resolve(__dirname, "./" + req.query.user + ".json");
        const sessionFile = { userName: req.query.user.toLowerCase(), gtoken: pathToJson };
        let data = JSON.stringify(sessionFile);
        fs.writeFileSync('./session.json', data);

        tokenNow = pathToJson;

        // get new token regardless
        refreshToken()

        res.send(["result", "OK"]);
    }
    else {
        // console.log("Cannot find user")
        res.send(["result", "Error pulling of accounts"]);
    }
    //
})

app.get("/use-in", (req, res) => {

    // step 1

    // console.log("using token:" + tokenNow);        
})

app.get('/google',
    passport.authenticate('google', {
        scope:
            ['email', 'profile',
                'https://www.googleapis.com/auth/calendar',
                'https://www.googleapis.com/auth/calendar.events',
                'https://www.googleapis.com/auth/tasks'],
        accessType: 'offline',
        prompt: 'consent',
    }
    ));

// GET /auth/microsoft
//   Use passport.authenticate() as route middleware to authenticate the
//   request. The first step in Microsoft Graph authentication will involve
//   redirecting the user to the common Microsoft login endpoint. After authorization, Microsoft
//   will redirect the user back to this application at /auth/microsoft/callback
app.get('/auth/microsoft',
    passport.authenticate('microsoft', {
        // Optionally add any authentication params here
        prompt: 'select_account'
    }),
    // eslint-disable-next-line no-unused-vars
    function (req, res) {
        // The request will be redirected to Microsoft for authentication, so this
        // function will not be called.
    });

// GET /auth/microsoft/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/microsoft/callback',
    passport.authenticate('microsoft', { failureRedirect: '/login' }),

    function (req, res) {

        //res.redirect('http://10.131.178.21:3000/calendar-settings');
        //change frontend url
        res.redirect('masonry-office.netlify.app/calendar-settings');
    });

app.get('/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/failed',
    }),
    function (req, res) {
        //res.redirect('/success')
        // res.redirect('http://10.131.178.21:3000/link-user?result=ok') // result=ok is my way to highlight google button
        //res.redirect('http://localhost:3000/calendar-settings') // result=ok is my way to highlight google button
        //res.redirect('http://10.131.178.21:3000/calendar-settings');
        //change frontend url
        res.redirect('https://masonry-office.netlify.app/calendar-settings');
    }
);

app.get("/logout", (req, res) => {
    req.session = null;
    req.logout();
    res.redirect('/');
});


/**
 * @description Request for Calendar Event
 * @param  {} authToken - authentication token
 * @param  {} selectDays - date to request, converted to month period
 * @param  {} user - user name af calendar primary/shared calendar
 */
async function fetchEvent(authToken, selectDay, user) {

    var events = [];

    const calendar = google.calendar({ version: 'v3', auth: authToken });

    var firstDay = null;
    var lastDay = null;
    firstDay = new Date(selectDay.getFullYear(), selectDay.getMonth(), 1);
    lastDay = new Date(selectDay.getFullYear(), selectDay.getMonth() + 2, 0);

    return new Promise((resolve, reject) => {
        const eventsA = calendar.events.list({
            calendarId: user,
            timeMin: firstDay,
            timeMax: lastDay,
            singleEvents: true,
            orderBy: 'startTime',
        }, (err, res) => {
            if (err) {
                resolve([]);
            }
            else {
                events = res.data.items;

                // console.log(res.data.items)

                if (events.length) {

                    resolve([{ userName: user, eventsInfo: events }]);
                    //console.log({userName: user, eventsInfo: events});
                } else {
                    resolve([]); // if no event return empty obj array
                }
            }
        });
    });
}

function getGoogleCalendarListEvent(req, res, tok) {
    try {
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);

        // setup selectDay argument for fetchEvent
        var selectDay = null;
        if (req.query.dateNow != null) {
            selectDay = new Date(req.query.dateNow);
        }
        else {
            // send error
            res.send([]);
            return;
        }

        // setup userName as argument for fetchEvent
        var userName = [];
        if (req.query.userName != null) {
            userName = JSON.parse(req.query.userName);
        }
        else {
            userName = [{ user: "primary" },];
        }

        var promises = [];

        userName.forEach(users => {
            promises.push(fetchEvent(oAuth2Client, selectDay, users.user));
        })

        Promise.all(promises).then((turnOuts) => {
            console.log("TURNOUT: ", turnOuts);
            res.send({ result: turnOuts });
        });

    } catch (err) {
        res.status(500).json(err);
    }
}
function pad(number) {
    if (number < 10) {
        return '0' + number;
    }
    return number;
}

async function fetchMsEvent(selectDay, user, tok) {

    var events = [];

    var firstDay = null;
    var lastDay = null;
    firstDay = new Date(selectDay.getFullYear(), selectDay.getMonth(), 1);
    lastDay = new Date(selectDay.getFullYear(), selectDay.getMonth() + 2, 0);

    // console.log(`https://graph.microsoft.com/v1.0/me/calendars/${user}/events?startDateTime={${firstDay.toISOString()}}&endDateTime={${lastDay.toISOString()}}`)

    let startDate = firstDay.getFullYear() +
        '-' + pad(firstDay.getMonth() + 1) +
        '-' + pad(firstDay.getDate()) +
        'T' + pad(firstDay.getHours()) +
        ':' + pad(firstDay.getMinutes()) +
        ':' + pad(firstDay.getSeconds()) +
        '.' + (firstDay.getMilliseconds() / 1000).toFixed(3).slice(2, 5) +
        'Z';
    let endDate = lastDay.getFullYear() +
        '-' + pad(lastDay.getMonth() + 1) +
        '-' + pad(lastDay.getDate()) +
        'T' + pad(lastDay.getHours()) +
        ':' + pad(lastDay.getMinutes()) +
        ':' + pad(lastDay.getSeconds()) +
        '.' + (lastDay.getMilliseconds() / 1000).toFixed(3).slice(2, 5) +
        'Z';

    // console.log(startDate)
    // console.log(`https://graph.microsoft.com/v1.0/me/calendars/${user}/events?$filter=start/dateTime ge '${startDate}'`)

    return new Promise((resolve, reject) => {


        try {
            const tokens = getMsGraphToken(tok)

            axios.get(`https://graph.microsoft.com/v1.0/me/calendars/${user}/events?$filter=start/dateTime ge '${startDate}' and end/dateTime le '${endDate}'`,
                {
                    headers: {
                        Authorization: `Bearer ${tokens.access_token}`
                    },
                },
            ).then(response => {

                events = response.data.value;
                if (events.length) {

                    // // console.log(response.data.value)
                    resolve([{ userName: user, eventsInfo: events }]);
                } else {
                    resolve([]); // if no event return empty obj array
                }

            }).catch(error => {
                // console.log("error here ")
                // console.log(error)
            })


        }
        catch (error) {
            // console.log(error)
        }


    });
}

function getMsGraphCalendarEventList(req, res, tok) {
    try {

        // const tokens = getMsGraphToken(tok)

        // setup selectDay argument for fetchEvent
        var selectDay = null;
        if (req.query.dateNow != null) {
            selectDay = new Date(req.query.dateNow);
        }
        else {
            // send error
            res.send([]);
            return;
        }

        // setup userName as argument for fetchEvent
        var userName = [];
        if (req.query.userName != null) {
            userName = JSON.parse(req.query.userName);

        }
        else {
            res.status(500).json(err);
            return
        }

        var promises = [];

        userName.forEach(users => {


            promises.push(fetchMsEvent(selectDay, users.user, tok));
        })

        Promise.all(promises).then((turnOuts) => {
            // console.log("outputs: ", turnOuts)
            res.send({ result: turnOuts });
        });

    } catch (err) {
        res.status(500).json(err);
    }

}

// Sample Query to Google Calendar
app.get("/listEvent", (req, res) => {

    var tok = getTokenFile();

    if (accountType === "google") {
        getGoogleCalendarListEvent(req, res, tok)
    }
    else if (accountType === "msgraph") {
        getMsGraphCalendarEventList(req, res, tok)
    }


});

// Sample Query to Google Calendar
app.get("/listDadEvent", (req, res) => {

    try {
        var tok = getTokenFile();
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);


        const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
        let selectDay = req.query.dateNow;

        const dateSplit = selectDay.split('T')[0];
        const lastDay = dateSplit + "T23:59:59Z"

        //    // console.log("SELECT DAY:", selectDay);
        //     // console.log("LAST DAY:", lastDay);
        const eventsA = calendar.events.list({
            calendarId: "dad.lilikoi@gmail.com",
            timeMin: selectDay, //"2022-03-02T00:00:00Z"
            timeMax: lastDay,//"2022-03-03T23:59:59Z",
            singleEvents: true,
            orderBy: 'startTime',
        }, (err, result) => {

            if (err) {

                res.status(500).json(err);
            }
            else {
                res.send({ eventsInfo: result.data.items });
                console.log("ENTERED RESULT: ", result.data.items);

            }


            //    events = result.data.items;
            // if (result.data.items !== null) {
            // } else {
            //   res.send("NOT EXISTING");
            // }
        });

    } catch (err) {
        // console.log("ENTERED LIST DAD err",err)
        res.status(500).json(err);
    }
});

// Sample Query to Google Calendar
app.get("/listMomEvent", (req, res) => {

    try {
        var tok = getTokenFile();
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);


        const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
        let selectDay = req.query.dateNow;

        const dateSplit = selectDay.split('T')[0];
        const lastDay = dateSplit + "T23:59:59Z"

        //    // console.log("SELECT DAY:", selectDay);
        //     // console.log("LAST DAY:", lastDay);
        const eventsA = calendar.events.list({
            calendarId: "mom.lilikoi@gmail.com",
            timeMin: selectDay, //"2022-03-02T00:00:00Z"
            timeMax: lastDay,//"2022-03-03T23:59:59Z",
            singleEvents: true,
            orderBy: 'startTime',
        }, (err, result) => {

            if (err) {

                res.status(500).json(err);
            }
            else {

                // events = result.data.items;
                // if (result.data.items !== null) {
                res.send({ eventsInfo: result.data.items });
                // } else {
                //   res.send("NOT EXISTING");
                // }
                // console.log("ENTERED RESULT: ", result.data.items);
            }

        });

    } catch (err) {
        // console.log("ENTERED LIST DAD err",err)
        res.status(500).json(err);
    }
});

// Sample Query to Google Calendar
app.get("/listChildEvent", (req, res) => {

    try {
        var tok = getTokenFile();
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);


        const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
        let selectDay = req.query.dateNow;

        const dateSplit = selectDay.split('T')[0];
        const lastDay = dateSplit + "T23:59:59Z"

        //    // console.log("SELECT DAY:", selectDay);
        //     // console.log("LAST DAY:", lastDay);
        const eventsA = calendar.events.list({
            calendarId: "child.lilikoi@gmail.com",
            timeMin: selectDay, //"2022-03-02T00:00:00Z"
            timeMax: lastDay,//"2022-03-03T23:59:59Z",
            singleEvents: true,
            orderBy: 'startTime',
        }, (err, result) => {

            if (err) {

                res.status(500).json(err);
            }
            else {

                // events = result.data.items;
                // if (result.data.items !== null) {
                res.send({ eventsInfo: result.data.items });
                // } else {
                //   res.send("NOT EXISTING");
                // }
                // console.log("ENTERED RESULT: ", result.data.items);
            }

        });

    } catch (err) {
        // console.log("ENTERED LIST DAD err",err)
        res.status(500).json(err);
    }
});

function addEventOnGoogleCalendar(req, res, tok) {
    try {
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);


        const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });

        // not optional req.body.summary, start, end

        // about all day, for start end use date, yyy-mm-dd


        let event = {
            summary: req.body.summary,
            description: req.body.description !== null ? req.body.description : "",
        }

        if (req.body.start !== undefined) {
            if (req.body.start.dateTime !== undefined) {
                event["start"] = req.body.start;
            }
            else {

                let dateOnly = { date: req.body.start.date.slice(0, 10) }
                if (req.body.start.timeZone !== undefined) {
                    dateOnly["timeZone"] = req.body.start.timeZone
                }
                event["start"] = dateOnly;
            }

        }
        if (req.body.end !== undefined) {
            if (req.body.end.dateTime !== undefined) {
                event["end"] = req.body.end;
            }
            else {
                let dateOnly = { date: req.body.end.date.slice(0, 10) }
                if (req.body.end.timeZone !== undefined) {
                    dateOnly["timeZone"] = req.body.end.timeZone
                }
                event["end"] = dateOnly;
            }
        }

        // if req.body.recurrence different body
        if (req.body.recurrence !== undefined) {
            event["recurrence"] = req.body.recurrence; // must be an array
        }
        // about end: The (exclusive) end time of the event. For a recurring event, this is the end time of the first instance
        // add to event

        // attachments add if available
        if (req.body.attachments !== undefined) {
            event["attachments"] = req.body.attachments; // must contain attachments.fileUrl
        }

        event["status"] = "confirmed"

        let param = {
            calendarId: req.query.calendarId,
            resource: event
        }

        // console.log(param)

        const eventsA = calendar.events.insert(param, (err, result) => {
            if (err) {
                // console.log(err)
                res.status(500).json(err);
            }
            else {
                res.status(200).send(result)
            }

        });



    } catch (err) {
        // console.log(err)
        res.status(500).json(err);
    }

}

function addEventOnMSGraphCalendar(req, res, tok) {

    const token = getMsGraphToken(tok)
    let calendarId = req.query.calendarId;

    let myUrl = `https://graph.microsoft.com/v1.0/me/calendars/${calendarId}/events`

    let eventsInfo = {
        subject: req.body.summary,
    }

    if (req.body.start !== undefined) {
        if (req.body.start.dateTime !== undefined) {
            eventsInfo["start"] = req.body.start;
        }
        else {

            let dateOnly = { dateTime: req.body.start.date.slice(0, 10) }
            if (req.body.start.timeZone !== undefined) {
                dateOnly["timeZone"] = req.body.start.timeZone
            }
            eventsInfo["start"] = dateOnly;
        }

    }

    if (req.body.end !== undefined) {
        if (req.body.end.dateTime !== undefined) {
            eventsInfo["end"] = req.body.end;
        }
        else {
            let dateOnly = { dateTime: req.body.end.date.slice(0, 10) }
            if (req.body.end.timeZone !== undefined) {
                dateOnly["timeZone"] = req.body.end.timeZone
            }
            eventsInfo["end"] = dateOnly;
        }
    }

    axios({
        method: 'post',
        url: myUrl,
        headers: {
            Authorization: `Bearer ${token.access_token}`,
            'Content-Type': 'application/json'
        },
        data: eventsInfo
    }).then(response => {

        // // console.log("output here for try post ")
        // // console.log(response.data)
        res.send({ result: true, data: response.data })
        // // console.log(response.data.value[0].emailAddress)
    }).catch(error => {
        // // console.log("error here ")
        // console.log(error)
        res.send({ result: false })
    })

}


app.post("/addEvent", (req, res) => {

    var tok = getTokenFile();

    if (accountType === "google") {
        addEventOnGoogleCalendar(req, res, tok)
    }
    else if (accountType === "msgraph") {
        addEventOnMSGraphCalendar(req, res, tok)

    }

});

function updateEventOnGoogleCalendar(req, res, tok) {
    // requires calendar ID and event ID
    try {
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);


        const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });

        if (req.query.calendarId != null && req.query.eventId != null) {
            let event = {
                summary: req.body.summary,
                description: req.body.description !== null ? req.body.description : "",

            }

            if (req.body.start !== undefined) {
                if (req.body.start.dateTime !== undefined) {
                    event["start"] = req.body.start;
                }
                else {
                    let dateOnly = { date: req.body.start.date.slice(0, 10) }
                    if (req.body.start.timeZone !== undefined) {
                        dateOnly["timeZone"] = req.body.start.timeZone
                    }
                    event["start"] = dateOnly;
                }

            }

            if (req.body.end !== undefined) {
                if (req.body.end.dateTime !== undefined) {
                    event["end"] = req.body.end;
                }
                else {
                    let dateOnly = { date: req.body.end.date.slice(0, 10) }
                    if (req.body.end.timeZone !== undefined) {
                        dateOnly["timeZone"] = req.body.end.timeZone
                    }
                    event["end"] = dateOnly;
                }
            }

            // if req.body.recurrence different body
            if (req.body.recurrence !== undefined) {
                event["recurrence"] = req.body.recurrence; // must be an array
            }
            // about end: The (exclusive) end time of the event. For a recurring event, this is the end time of the first instance
            // add to event

            // attachments add if available
            if (req.body.attachments !== undefined) {
                event["attachments"] = req.body.attachments; // must contain attachments.fileUrl
            }

            event["status"] = "confirmed"
            // about end: The (exclusive) end time of the event. For a recurring event, this is the end time of the first instance
            // add to event

            // attachments add if available
            if (req.body.attachments !== null) {
                event["attachments"] = req.body.attachments; // must contain attachments.fileUrl
            }

            let param = {
                calendarId: req.query.calendarId,
                eventId: req.query.eventId,
                resource: event
            }

            const eventsA = calendar.events.patch(param, (err, result) => {
                if (err) {
                    res.status(500).json(err);
                }
                else {
                    res.status(200).send(result)
                }
            });

        }
        else {
            // console.log("Error")
        }

    }
    catch {
        // console.log("Error")
    }
}

function updateEventOnMSGraphCalendar(req, res, tok) {
    const token = getMsGraphToken(tok)
    let calendarId = req.query.calendarId;
    let eventId = req.query.eventId;

    let myUrl = `https://graph.microsoft.com/v1.0/me/calendars/${calendarId}/events/${eventId}`

    let eventsInfo = {
        subject: req.body.summary,
    }

    if (req.body.start !== undefined) {
        if (req.body.start.dateTime !== undefined) {
            eventsInfo["start"] = req.body.start;
        }
        else {
            let dateOnly = { dateTime: req.body.start.date.slice(0, 10) }
            if (req.body.start.timeZone !== undefined) {
                dateOnly["timeZone"] = req.body.start.timeZone
            }
            eventsInfo["start"] = dateOnly;
        }

    }

    if (req.body.end !== undefined) {
        if (req.body.end.dateTime !== undefined) {
            eventsInfo["end"] = req.body.end;
        }
        else {
            let dateOnly = { dateTime: req.body.end.date.slice(0, 10) }
            if (req.body.end.timeZone !== undefined) {
                dateOnly["timeZone"] = req.body.end.timeZone
            }
            eventsInfo["end"] = dateOnly;
        }
    }

    axios({
        method: 'patch',
        url: myUrl,
        headers: {
            Authorization: `Bearer ${token.access_token}`,
            'Content-Type': 'application/json'
        },
        data: eventsInfo
    }).then(response => {

        // // console.log("output here for try post ")
        // // console.log(response.data)
        res.send({ result: true, data: response.data })
        // // console.log(response.data.value[0].emailAddress)
    }).catch(error => {
        // // console.log("error here ")
        // console.log(error)
        res.send({ result: false })
    })


}

app.put("/updateEvent", (req, res) => {

    var tok = getTokenFile();

    if (accountType === "google") {
        updateEventOnGoogleCalendar(req, res, tok)
    }
    else if (accountType === "msgraph") {
        updateEventOnMSGraphCalendar(req, res, tok)

    }

});


function deleteEventOnGoogleCalendar(req, res, tok) {
    // requires calendar ID and event ID
    try {
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);


        const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });

        if (req.query.calendarId != null && req.query.eventId != null) {
            let param = {
                calendarId: req.query.calendarId,
                eventId: req.query.eventId
            }

            const eventsA = calendar.events.delete(param, (err, result) => {
                if (err) {
                    // console.log(err)
                    res.status(500).json(err);
                }
                else {
                    // // console.log("No Error")
                    res.status(200).send(result)
                }
            });
        }
        else {
            // console.log("Error")
        }

    }
    catch {
        // console.log("Error")
    }
}

function deleteEventOnMSGraphCalendar(req, res, tok) {

}

app.delete("/deleteEvent", (req, res) => {

    var tok = getTokenFile();
    // console.log("listTaskList: ", tok)

    if (accountType === "google") {
        deleteEventOnGoogleCalendar(req, res, tok)
    }
    else if (accountType === "msgraph") {
        deleteEventOnMSGraphCalendar(req, res, tok)

    }


});



/**
 * @description
 * @param       {} authToken
 * @returns     promise
 */
async function fetchTaskList(authToken) {

    const service = google.tasks({ version: 'v1', auth: authToken });

    return new Promise((resolve, reject) => {
        const eventsA = service.tasklists.list({
        }, (err, res) => {

            if (err) {
                // console.log(err);
                resolve([]);
            }
            else {
                resolve(res.data.items);
            }


        });
    });

}

function listGoogleCalendar(req, res, tok) {
    try {
        //read token file you saved earlier in passport_setup.js

        const tokens = getGoogleToken(tok)
        // // console.log("listCalendarList ", tokens)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);

        oAuth2Client.setCredentials(tokens);

        const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });

        const calendarList = calendar.calendarList.list({ maxResults: 100 }, (err, qres) => {
            if (err) {
                res.send({ result: "error" });

            }
            else {
                var calInfoReturn = [];
                qres.data.items.forEach(calendarItem => {

                    calInfoReturn.push({ calendarId: calendarItem.id, summary: calendarItem.summary })
                    // console.log("calendarId", calendarItem.id)
                    // console.log("summary: ", calendarItem.summary)
                })
                res.send({ "calendarList": calInfoReturn });
            }


        });
    }
    catch (error) {
        // console.log(error)
    }

}

function listMsGraphCalendar(req, res, tok) {
    try {
        const token = getMsGraphToken(tok)
        // console.log("listMsGraphCalendar", token)

        axios.get('https://graph.microsoft.com/v1.0/me/calendars',
            {
                headers: {
                    Authorization: `Bearer ${token.access_token}`
                },
            },
        ).then(response => {

            var calInfoReturn = [];

            response.data.value.forEach(calendarItem => {
                calInfoReturn.push({ calendarId: calendarItem.id, summary: calendarItem.name })

            })

            res.send({ "calendarList": calInfoReturn });

            // // console.log(response.data.value[0].emailAddress)
        }).catch(error => {
            // console.log("error here ")
            // console.log(error)
        })



    }
    catch (error) {
        // console.log(error)
    }
}

app.get("/listCalendarList", (req, res) => {

    var tok = getTokenFile();

    // console.log("listCalendarList", accountType, tok)

    if (accountType === "google") {
        listGoogleCalendar(req, res, tok)
    }
    else if (accountType === "msgraph") {
        listMsGraphCalendar(req, res, tok)
    }
    else {
        // console.log("Error no tocken")
    }

});

//list of task for the Living room
app.get("/listTaskLivingRoom", (req, res) => {

    try {
        var tok = getTokenFile();
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);

        oAuth2Client.setCredentials(tokens);

        const service = google.tasks({ version: 'v1', auth: oAuth2Client });

        var taskListId = 'MDczMDgxOTk0ODExMTA2MTM1ODY6MDow'
        if (req.query.taskListId !== null) {
            taskListId = req.query.taskListId
        }

        // Dad.lilikoi@gmail hast List with Tille of: Kitchen and tasklist ID of: emVtMzFQTXR0N2pjYkZCWg
        service.tasks.list({
            tasklist: taskListId,
        }, (err, result) => {

            if (err) {

                return // console.log('The API returned an error: ' + err);
            } else {

                const taskList = result.data.items;
                res.send({ data: taskList });
            }



            // if (taskList.length) {
            //     // console.log('Upcoming ' + taskList.length + ' task:');
            //     taskList.map((task, i) => {
            //       // console.log(task.title);
            //     });
            //   } else {
            //     // console.log('No upcoming task found.');
            //   }
        });




    } catch (err) {
        res.status(500).json(err);
    }
});

function listGoogleTaskList(req, res, tok) {
    try {

        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);

        oAuth2Client.setCredentials(tokens);


        fetchTaskList(oAuth2Client).then((result) => {

            var listOfTaskList = []
            result.forEach((taskList) => {
                var info = {
                    title: taskList.title,
                    id: taskList.id
                }
                listOfTaskList.push(info)
            })


            res.send(listOfTaskList);
        });



    } catch (err) {
        res.status(500).json(err);
    }

}

function listMsGraphTaskList(req, res, tok) {
    try {
        const token = getMsGraphToken(tok)
        // // console.log("listMsGraphCalendar", token)

        axios.get('https://graph.microsoft.com/v1.0/me/todo/lists',
            {
                headers: {
                    Authorization: `Bearer ${token.access_token}`
                },
            },
        ).then(response => {


            var listOfTaskList = []
            response.data.value.forEach((taskList) => {
                var info = {
                    title: taskList.displayName,
                    id: taskList.id
                }
                listOfTaskList.push(info)
            })


            res.send(listOfTaskList);


        }).catch(error => {
            // console.log("error here ")
            // console.log(error)
        })



    }
    catch (error) {
        // console.log(error)
    }
}

/**
 * @function {} "/listTaskList"
 * @param    {} req
 * @returns  {} res
 */
app.get("/listTaskList", (req, res) => {

    var tok = getTokenFile();
    // console.log("listTaskList: ", tok)

    if (accountType === "google") {
        listGoogleTaskList(req, res, tok)
    }
    else if (accountType === "msgraph") {
        listMsGraphTaskList(req, res, tok)

    }


});

async function fetchListTask(authToken, taskId) {

    var listOfTask = []

    const service = google.tasks({ version: 'v1', auth: authToken });
    return new Promise((resolve, reject) => {
        service.tasks.list({
            tasklist: taskId,
        }, (err, result) => {
            if (err) {
                // console.log('The API returned an error: ' + err);
                resolve([]);
            }
            else {

                // console.log("now result:", result)

                var itemInfo = []

                result.data.items.forEach(item => {
                    let info = {
                        title: item.title,
                        id: item.id,
                        updated: item.updated,
                        status: item.status,
                        due: item.due,
                        completed: item.completed,
                        hidden: item.hidden,
                        notes: item.notes,
                    }
                    itemInfo.push(info)
                })

                resolve({ "taskId": taskId, taskList: itemInfo });
            }

        });

    });

}

function listTasksOnGoogleList(req, res, tok, taskId) {
    try {
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);
        // setup credentials to OAuth2 object as argument for fetchEvent
        oAuth2Client.setCredentials(tokens);

        var promises = [];

        // // console.log("loop: ", Array.isArray(taskId))

        if (Array.isArray(taskId) === true) {
            taskId.forEach(task => {
                promises.push(fetchListTask(oAuth2Client, task));
            })

        }
        else {
            promises.push(fetchListTask(oAuth2Client, taskId));
        }

        Promise.all(promises).then((turnOuts) => {
            res.send({ result: turnOuts });
        });


    } catch (err) {
        res.status(500).json(err);
    }
}

function isCompleted(item) {

    var ret = false;
    if (item.status === "completed") {
        ret = true;
    }

    return ret;
}

async function fetchMsGraphListTask(tok, cmdStr, id) {


    return new Promise((resolve, reject) => {

        const token = getMsGraphToken(tok)

        axios.get(cmdStr,
            {
                headers: {
                    Authorization: `Bearer ${token.access_token}`
                },
            },
        ).then(response => {

            var itemInfo = []
            // var listOfTaskList = []

            response.data.value.forEach((item) => {
                let info = {
                    title: item.title, //available
                    id: item.id, // available
                    updated: item.lastModifiedDateTime !== undefined ? item.lastModifiedDateTime : item.createdDateTime,
                    status: item.status, // available, completed, notStarted
                    due: item.dueDateTime !== undefined ? item.dueDateTime.dateTime : null, // available
                    completed: item.completed, // available, returned date completed
                    hidden: item.hidden !== undefined ? item.hidden : isCompleted(item), //worked around
                    notes: item.notes, // body.content
                }
                itemInfo.push(info)
            })


            resolve({ "taskId": id, taskList: itemInfo });


        }).catch(error => {
            // console.log("error here ")
            // console.log(error)
            resolve([]);
        })


    })



}

function listTasksOnMsGraphList(req, res, tok, taskId) {

    try {

        var promises = [];

        if (Array.isArray(taskId) === true) {
            taskId.forEach(task => {

                let cmdStr = `https://graph.microsoft.com/v1.0/me/todo/lists/${task}/tasks`
                promises.push(fetchMsGraphListTask(tok, cmdStr, task));
            })

        }
        else {
            let cmdStr = `https://graph.microsoft.com/v1.0/me/todo/lists/${taskId}/tasks`
            promises.push(fetchMsGraphListTask(tok, cmdStr, taskId));
        }

        Promise.all(promises).then((turnOuts) => {
            res.send({ result: turnOuts });
        });


    } catch (err) {
        res.status(500).json(err);
    }

}

app.get("/listTask", (req, res) => {

    var taskId = req.query.taskId;
    var tok = getTokenFile();

    // console.log("listTask", tok, accountType)

    if (taskId !== null) {
        if (accountType === "google") {
            listTasksOnGoogleList(req, res, tok, taskId)
        }
        else if (accountType === "msgraph") {
            listTasksOnMsGraphList(req, res, tok, taskId)
        }

    }



})

/**
 * @function {} "/listTaskList"
 * @param    {} req listName: string = Name of List to be Created
 * @returns  {} res
 */
app.get("/CreateTaskList", (req, res) => {

    try {
        var tok = getTokenFile();
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);

        oAuth2Client.setCredentials(tokens);

        if (req.query.listName != null) {
            // console.log(req.query.listName);
        }
        else {
            res.send([]); // send error
        }

        // fetchTaskList(oAuth2Client).then((result) => {
        //     res.send(result);
        // });



    } catch (err) {
        res.status(500).json(err);
    }
});


/// Reference function
app.get("/listIngredients", (req, res) => {

    try {
        var tok = getTokenFile();
        const tokens = getGoogleToken(tok)
        //extract credential details
        const { client_secret, client_id, redirect_uris } = credentials.web;

        //make OAuth2 object
        const oAuth2Client = new google.auth.OAuth2(client_id,
            client_secret,
            redirect_uris[0]);

        oAuth2Client.setCredentials(tokens);

        const service = google.tasks({ version: 'v1', auth: oAuth2Client });

        var taskListId = 'emVtMzFQTXR0N2pjYkZCWg'
        if (req.query.taskListId !== undefined) {
            taskListId = req.query.taskListId;
        }

        // Dad.lilikoi@gmail hast List with Tille of: Kitchen and tasklist ID of: emVtMzFQTXR0N2pjYkZCWg
        service.tasks.list({
            tasklist: taskListId,
        }, (err, result) => {

            if (err) {

                return // console.log('The API returned an error: ' + err);

            }
            else {
                const taskList = result.data.items;
                res.send({ data: taskList });

            }

            // if (taskList.length) {
            //     // console.log('Upcoming ' + taskList.length + ' task:');
            //     taskList.map((task, i) => {
            //       // console.log(task.title);
            //     });
            //   } else {
            //     // console.log('No upcoming task found.');
            //   }

        });

        // res.send("got Task List");

    } catch (err) {
        res.status(500).json(err);
    }
});

async function fetchDeleteTask(authToken, taskListId, taskId) {

    const service = google.tasks({ version: 'v1', auth: authToken });

    return new Promise((resolve, reject) => {
        const eventsA = service.tasks.delete({
            tasklist: taskListId,
            task: taskId,
        }, (err, res) => {
            if (err) {
                // console.log(err);
                resolve(false);
            }
            else {
                resolve(true);
            }
        });

    });

}

function deleteTaskOnGoogleTaskList(req, res, tok) {
    const tokens = getGoogleToken(tok)
    //extract credential details
    const { client_secret, client_id, redirect_uris } = credentials.web;

    //make OAuth2 object
    const oAuth2Client = new google.auth.OAuth2(client_id,
        client_secret,
        redirect_uris[0]);
    // setup credentials to OAuth2 object as argument for fetchEvent
    oAuth2Client.setCredentials(tokens);

    if ((req.query.taskListId != null) && (req.query.taskId != null)) {
        // console.log(req.query.taskListId, req.query.taskId);
        fetchDeleteTask(oAuth2Client, req.query.taskListId, req.query.taskId).then((result) => {
            // console.log("Delete Completed");
        })

    }
    else {
        res.send("missing arguments");
    }
}

function deleteTaskOnMSGraphTaskList(req, res, tok) {
    // DELETE https://graph.microsoft.com/v1.0/me/todo/lists/{todoTaskListId}/tasks/{todoTaskId}

    const token = getMsGraphToken(tok)

    let todoTaskListId = req.query.taskListId
    let todoTaskId = req.query.taskId
    let cmdStr = `https://graph.microsoft.com/v1.0/me/todo/lists/${todoTaskListId}/tasks/${todoTaskId}`

    axios.delete(cmdStr, {
        headers: {
            Authorization: `Bearer ${token.access_token}`
        },
    },).then(response => {

        // console.log(response)

    }).catch(error => {

        // console.log(error)

    })



}

/**
 * @description  
 * @param       {} req - taskListId
 * @param       {} req - taskId
 * @returns taskId
 */
app.get("/deleteTaskOnTaskList", (req, res) => {

    var tok = getTokenFile();
    // console.log("deleteTaskOnTaskList: ")

    if (accountType === "google") {
        deleteTaskOnGoogleTaskList(req, res, tok)
    }
    else if (accountType === "msgraph") {
        deleteTaskOnMSGraphTaskList(req, res, tok)

    }


});
/**
 * @param  {} authToken
 * @param  {} taskListId
 * @param  {} taskName
 */
async function fetchAddTask(authToken, taskListId, taskName) {

    const service = google.tasks({ version: 'v1', auth: authToken });

    // const taskBody = { title: taskName};

    return new Promise((resolve) => {
        const eventsA = service.tasks.insert({
            tasklist: taskListId,
            resource: { title: taskName },
        }, (err, res) => {
            if (err) {
                resolve({ result: false, id: "", title: "" });
            }
            else {
                resolve({ result: true, id: res.data.id, title: res.data.title, status: res.data.status });
            }
        });

    });

}

function addTaskOnGoogleTaskList(req, res, tok) {
    const tokens = getGoogleToken(tok)
    //extract credential details
    const { client_secret, client_id, redirect_uris } = credentials.web;

    //make OAuth2 object
    const oAuth2Client = new google.auth.OAuth2(client_id,
        client_secret,
        redirect_uris[0]);
    // setup credentials to OAuth2 object as argument for fetchEvent
    oAuth2Client.setCredentials(tokens);

    if ((req.query.taskListId != null) && (req.query.taskName != null)) {
        fetchAddTask(oAuth2Client, req.query.taskListId, req.query.taskName).then((result) => {
            res.send(result);
        })

    }
    else {
        res.send("missing arguments");
    }

}

// TODO: Add Task to List 
function addTaskOnMSGraphTaskList(req, res, tok) {
    //POST https://graph.microsoft.com/v1.0/me/todo/lists/{todoTaskListId}/tasks

    const token = getMsGraphToken(tok)

    let todoTaskListId = req.query.taskListId

    let myUrl = `https://graph.microsoft.com/v1.0/me/todo/lists/${todoTaskListId}/tasks/`
    let taskName = req.query.taskName

    axios({
        method: 'post',
        url: myUrl,
        headers: {
            Authorization: `Bearer ${token.access_token}`,
            'Content-Type': 'application/json'
        },
        data: {
            title: taskName
        }
    }).then(response => {

        // // console.log("output here for try post ")
        // // console.log(response.data)
        res.send({ result: true, id: response.data.id, title: response.data.title, status: response.data.status })
        // // console.log(response.data.value[0].emailAddress)
    }).catch(error => {
        // // console.log("error here ")
        // console.log(error)
        res.send({ result: false, id: "", title: "" })
    })

}

/**
 * @title  {} "/addTaskOnTaskList"
 * @param  {} req - taskListId
 * @param  {} req - taskName
 * @return {} res - {status: bool, id: string, title: string}
 */
app.get("/addTaskOnTaskList", (req, res) => {

    var tok = getTokenFile();
    // console.log("addTaskOnTaskList: ")

    if (accountType === "google") {
        addTaskOnGoogleTaskList(req, res, tok)
    }
    else if (accountType === "msgraph") {
        addTaskOnMSGraphTaskList(req, res, tok)

    }

});


/**
 * @param  {} authToken
 * @param  {} taskListId
 * @param  {} taskName
 */
async function fetchEditTask(authToken, taskListId, taskID, newtaskName) {

    const service = google.tasks({ version: 'v1', auth: authToken });

    return new Promise((resolve) => {
        const eventsA = service.tasks.patch({
            tasklist: taskListId,
            task: taskID,
            resource: { title: newtaskName },
        }, (err, res) => {
            if (err) {
                resolve({ result: false, id: "", title: "" });
            }
            else {
                resolve({ result: true, id: res.data.id, title: res.data.title, status: res.data.status });
            }
        });

    });

}

function editTaskOnGoogleTaskList(req, res, tok) {
    const tokens = getGoogleToken(tok)
    //extract credential details
    const { client_secret, client_id, redirect_uris } = credentials.web;

    //make OAuth2 object
    const oAuth2Client = new google.auth.OAuth2(client_id,
        client_secret,
        redirect_uris[0]);
    // setup credentials to OAuth2 object as argument for fetchEvent
    oAuth2Client.setCredentials(tokens);

    if ((req.query.taskListId != null) && (req.query.taskId != null) && (req.query.newTitle != null)) {
        fetchEditTask(oAuth2Client, req.query.taskListId, req.query.taskId, req.query.newTitle).then((result) => {
            res.send(result);
        })

    }
    else {
        res.send("missing arguments");
    }
}

function editTaskOnMSGraphTaskList(req, res, tok) {
    const token = getMsGraphToken(tok)

    let todoTaskListId = req.query.taskListId
    let todoTaskId = req.query.taskId

    let myUrl = `https://graph.microsoft.com/v1.0/me/todo/lists/${todoTaskListId}/tasks/${todoTaskId}`

    let newTitle = " "
    if (req.query.newTitle !== undefined) {
        newTitle = req.query.newTitle
    }

    // // console.log(todoTaskListId, todoTaskId, newTitle)

    axios({
        method: 'patch',
        url: myUrl,
        headers: {
            Authorization: `Bearer ${token.access_token}`,
            'Content-Type': 'application/json'
        },
        data: {
            title: newTitle
        }
    }).then(response => {

        // // console.log("output here for try ")
        // // console.log(response.data)
        res.send({ result: true, id: response.data.id, title: response.data.title, status: response.data.status })
        // // console.log(response.data.value[0].emailAddress)
    }).catch(error => {
        // // console.log("error here ")
        // console.log(error)
        res.send({ result: false, id: "", title: "" })
    })

}

/**
 * @title  {} "/editTaskTitle"
 * @param  {} req - taskListId
 * @param  {} req - taskId
 * @param  {} req - newTitle
 * @return {} res - {status: bool, id: string, title: string}
 */
app.get("/editTaskTitle", (req, res) => {

    var tok = getTokenFile();
    // console.log("editTaskTitle: ",accountType , tok)

    if (accountType === "google") {
        editTaskOnGoogleTaskList(req, res, tok)
    }
    else if (accountType === "msgraph") {
        editTaskOnMSGraphTaskList(req, res, tok)

    }



});

/**
 * @param  {} authToken
 * @param  {} taskListId
 * @param  {} taskName
 */
async function fetchSetTaskStatus(authToken, taskListId, taskID, newtaskStatus) {

    const service = google.tasks({ version: 'v1', auth: authToken });

    var newStatus = "needsAction";
    if (newtaskStatus === "true") {
        newStatus = "completed";
    }


    return new Promise((resolve) => {
        const eventsA = service.tasks.patch({
            tasklist: taskListId,
            task: taskID,
            resource: { status: newStatus },
        }, (err, res) => {
            if (err) {
                resolve({ result: false, id: "", title: "" });
            }
            else {
                resolve({ result: true, id: res.data.id, title: res.data.title, status: res.data.status });
            }
        });

    });

}

function setGoogleTaskStatus(req, res, tok) {

    const tokens = getGoogleToken(tok)
    //extract credential details
    const { client_secret, client_id, redirect_uris } = credentials.web;

    //make OAuth2 object
    const oAuth2Client = new google.auth.OAuth2(client_id,
        client_secret,
        redirect_uris[0]);
    // setup credentials to OAuth2 object as argument for fetchEvent
    oAuth2Client.setCredentials(tokens);

    if ((req.query.taskListId != null) && (req.query.taskId != null) && (req.query.taskStatus != null)) {
        fetchSetTaskStatus(oAuth2Client, req.query.taskListId, req.query.taskId, req.query.taskStatus).then((result) => {
            res.send(result);
        })

    }
    else {
        res.send("missing arguments");
    }

}

function setMSGraphTaskStatus(req, res, tok) {

    const token = getMsGraphToken(tok)

    let todoTaskListId = req.query.taskListId
    let todoTaskId = req.query.taskId

    let myUrl = `https://graph.microsoft.com/v1.0/me/todo/lists/${todoTaskListId}/tasks/${todoTaskId}`

    var newtaskStatus = req.query.taskStatus
    var newStatus = "notStarted";
    if (newtaskStatus === "true") {
        newStatus = "completed";
    }


    // // console.log(todoTaskListId, todoTaskId, newTitle)
    // console.log("new status should be:", newStatus, newtaskStatus)

    axios({
        method: 'patch',
        url: myUrl,
        headers: {
            Authorization: `Bearer ${token.access_token}`,
            'Content-Type': 'application/json'
        },
        data: {
            status: newStatus
        }
    }).then(response => {

        // // console.log("output here for try ")
        // // console.log(response.data)
        res.send({ result: true, id: response.data.id, title: response.data.title, status: response.data.status })

        // // console.log(response.data.value[0].emailAddress)
    }).catch(error => {
        // // console.log("error here ")
        // console.log(error)
        res.send({ result: false, id: "", title: "" })
    })

}

/**
 * @title  {} "/setTaskStatus"
 * @param  {} req - taskListId : string
 * @param  {} req - taskId : string
 * @param  {} req - taskStatus : boolean
 * @return {} res - {status: bool, id: string, title: string}
 */
app.get("/setTaskStatus", (req, res) => {

    var tok = getTokenFile();

    // console.log("setTaskStatus: ")

    if (accountType === "google") {
        setGoogleTaskStatus(req, res, tok)
    }
    else if (accountType === "msgraph") {
        setMSGraphTaskStatus(req, res, tok)

    }



});

var pathToUserlist = path.resolve(__dirname, './userList.json');

/**
 * @description  
 * @param       {} req - user name
 * @param       {} req - encrypted password
 * @returns taskId
 */
app.post("/UpdateUserSetting", (req, res) => {

    if ((req.body.userName != null) && (req.body.password != null)) {
        // read file list
        let userListFile = JSON.parse(fs.readFileSync(pathToUserlist));

        let indx = userListFile.userList.findIndex((element) => element.userName.toLowerCase() === req.body.userName.toLowerCase())
        if (indx !== -1) {
            if (userListFile.userList[indx].password === req.body.password) {
                userListFile.userList[indx]["taskSetting"] = req.body.taskSetting
                let newData = JSON.stringify(userListFile);
                fs.writeFileSync(pathToUserlist, newData);
                // // console.log(newData)
                // return OK
                return res.status(200).send({ status: 0, message: "No Problem" });
            }
            else {
                // console.log("Error: Password not match")
                // return OK
                return res.status(503).send({ status: 1, message: "Password not match" });
            }
        }
        else {
            // error. user not found
            // console.log("Error: User not found")
            // return OK
            return res.status(503).send({ status: 1, message: "User not found" });
        }

    }

})

/**
 * @description  
 * @param       {} req - user name
 * @param       {} req - encrypted password
 * @returns taskId
 */
app.post("/SaveUserAccount", (req, res) => {

    if ((req.body.userName != null) && (req.body.password != null)) {

        // if not null, check if user list file exist
        // if user list file not exist create new
        if (!fs.existsSync(pathToUserlist)) {
            // create if not existing
            let userSessionList = { userList: [] };
            let strUserSessList = JSON.stringify(userSessionList);
            fs.writeFileSync(pathToUserlist, strUserSessList);
        }

        // check if user exist in user list
        let userListFile = JSON.parse(fs.readFileSync(pathToUserlist));
        // if user exist, return error
        let indx = userListFile.userList.findIndex((element) => element.userName.toLowerCase() === req.body.userName.toLowerCase())
        if (indx !== -1) {
            var info = userListFile.userList[indx];
            if (req.body.calendarSetting != null) {
                info["calendarSetting"] = req.body.calendarSetting;
                // // console.log(req.body.calendarSetting)
            }

            if (req.body.taskSetting != null) {
                info["taskSetting"] = req.body.taskSetting;
            }

            userListFile.userList.splice(indx, 1, info);
            let newData = JSON.stringify(userListFile);
            fs.writeFileSync(pathToUserlist, newData);

            return res.status(200).send({ status: 0, message: "Messages available" });
        }
        else {
            // if user not exist, add user and password to local list
            var newItem = { 'userName': req.body.userName.toLowerCase(), 'password': req.body.password }

            if (req.body.calendarSetting != null) {
                newItem["calendarSetting"] = req.body.calendarSetting;
            }

            if (req.body.taskSetting != null) {
                newItem["taskSetting"] = req.body.taskSetting;
            }


            userListFile.userList.push(newItem)

            // rewrite
            let newData = JSON.stringify(userListFile);
            fs.writeFileSync(pathToUserlist, newData);

            // return OK
            return res.status(200).send({ status: 0, message: "Messages available" });
        }


    }
    else {
        // if null return error
        return res.status(503).send({ status: 1, message: "Messages is not available" });
    }


})

app.post("/register", async (req, res) => {
    // Our register logic starts here

    try {
        // Get user input
        const { first_name, email, password } = req.body;

        // Validate user input
        if (!(email && password && first_name)) {
            res.status(400).send("All input is required");
        }

        // check if user already exist
        // Validate if user exist in our database
        const oldUser = await User.findOne({ email });

        if (oldUser) {
            return res.status(409).send("User Already Exist. Please Login");
        }

        // Encrypt user password
        encryptedPassword = await bcrypt.hash(password, 10);

        // Create user in our database
        const user = await User.create({
            first_name,
            email: email.toLowerCase(), // sanitize: convert email to lowercase
            password: encryptedPassword,
        });

        // Create token
        const token = jwt.sign(
            { user_id: user._id, email },
            qrtoken,
            {
                expiresIn: "2h",
            }
        );

        // return new user
        res.status(201).json({ token });
    } catch (err) {
        console.log(err);
    }
    // Our register logic ends here
});

app.post("/login", async (req, res) => {
    try {
        // Get user input
        const { first_name } = req.body;
        let userID = '';
        // Validate user input
        if (!(first_name)) {
            res.status(400).send("All input is required");
        }
        // Validate if user exist in our database
        const user = await User.findOne({ first_name });

        if (user) {
            // Create token
            const token = jwt.sign(
                { user_id: user._id, first_name },
                qrtoken,
                {
                    expiresIn: "2h",
                }
            );
           return res.json( user._id);
        }
        return res.status(400).send("Invalid Credentials");
    } catch (err) {
        console.log(err);
    }
    // Our login logic ends here
});


app.post("/qr/generate", async (req, res) => {
    try {
        const { userId } = req.body;

        // Validate user input
        if (!userId) {
            res.status(400).send("User Id is required");
        }

        const user = await User.findById(userId);

        // Validate is user exist
        if (!user) {
            res.status(400).send("User not found");
        }

        const qrExist = await QRCode.findOne({ userId });

        // If qr exist, update disable to true and then create a new qr record
        if (!qrExist) {
            await QRCode.create({ userId });
        } else {
            await QRCode.findOneAndUpdate({ userId }, { $set: { disabled: true } });
            await QRCode.create({ userId });
        }

        // Generate encrypted data
        const encryptedData = jwt.sign(
            { userId: user._id },
            qrtoken,
            {
                expiresIn: "1d",
            }
        );
        // Generate qr code
        //console.log("ENCRYPTED DATA: ",'\n', encryptedData);
        let url = "https://"+ipAddress+":8443/redirectLogin?token=" + encryptedData;
        generatedToken = encryptedData;
        const dataImage = await QR.toDataURL(url);
        //console.log("URL: ", '\n', url);
        // Return qr code
        return res.status(200).json({ dataImage });
    } catch (err) {
        console.log(err);
    }
});

app.get("/redirectLogin", (req, res) => {
    if (req.query.token != null) {
        console.log("redirectLogin");
        res.redirect("http://"+ipAddress+":3000/login-page")
        //res.send(req.query.token);
    } else {
        res.send("QR Scanned Fail");
    }    
});

app.get("/getToken", (req, res) => {
    console.log("GENERATED TOKEN: ", generatedToken)
    return res.send({"token": generatedToken});
});



app.post("/qr/scan", async (req, res) => {
    //console.log("enter qr scan")
    try {
        const { token } = req.body.token;
        //console.log("REQ BODY: ", req.body.token);
        if (!token) {
            res.status(400).send("Token is required");
        }

        const decoded = jwt.verify(token, qrtoken);
        //console.log("token scan QR: ", token);
        const qrCode = await QRCode.findOne({
            userId: decoded.userId,
            disabled: false,
        });

        if (!qrCode) {
            res.status(400).send("QR Code not found");
        }

        const connectedDeviceData = {
            userId: decoded.userId,
            qrCodeId: qrCode._id
        };

        const connectedDevice = await ConnectedDevice.create(connectedDeviceData);

        // Update qr code
        await QRCode.findOneAndUpdate(
            { _id: qrCode._id },
            {
                isActive: true,
                connectedDeviceId: connectedDevice._id,
                lastUsedDate: new Date(),
            }
        );
        
        // Find user
        const user = await User.findById(decoded.userId);

        // Create token
        const authToken = jwt.sign({ user_id: user._id },qrtoken, {
            expiresIn: "2h",
        });

        // Return token
        scannedToken = authToken;
        console.log("Scanned token:", scannedToken);
        return res.status(200).json({ token: authToken });

        //res.redirect("http://10.131.178.21:3000/living-room");
    } catch (err) {
        console.log(err);
    }
});

app.get("/waitToken", (req, res) => {
    if(scannedToken != null || scannedToken != undefined || scannedToken != ''){
        //console.log("LOGGED IN");
        res.status(200).json({ scannedToken });
        scannedToken = null;
        console.log("scanned token clear: ", scannedToken);
    }
})

app.get("/UserSettings", (req, res) => {

    const sessionData = JSON.parse(fs.readFileSync('./session.json'));

    if (sessionData != null) {
        // let userInfor = fs.readFileSync(pathToUserlist);
        let userListFile = JSON.parse(fs.readFileSync(pathToUserlist));
        let index = userListFile.userList.findIndex((x) => x.userName === sessionData.userName)

        // // console.log(userListFile)
        if (index != -1) {
            res.send(userListFile.userList[index])
        }
        else {
            res.send({ result: "error" })
        }

    }
});

/**
 * @description  
 * @returns taskId
 */
app.get("/ListUserAccount", (req, res = response) => {

    //return res.json({userList: []});

    // check if user list file exist
    if (!fs.existsSync(pathToUserlist)) {
        // create if not existing
        // if user list file not exist create new and return empty
        let userSessionList = { userList: [] };
        let strUserSessList = JSON.stringify(userSessionList);
        fs.writeFileSync(pathToUserlist, strUserSessList);

        res.send(userSessionList);
    }
    // else, return list of users
    else {
        let userListFile = JSON.parse(fs.readFileSync(pathToUserlist));
        res.send(userListFile);
    }

});

/**
 * @description  
 * @param       {} req - user name
 * @returns taskId
 */
app.get("/LoadUserAccount", (req, res) => {

    // check if user name is not null
    if (req.query.userName != null) {

        // if not null, check if user list file exist
        if (!fs.existsSync(pathToUserlist)) {
            // if user list file not exist, return error
            res.send({ result: "Error: User List not exist" });
        }
        else {
            let userListFile = JSON.parse(fs.readFileSync(pathToUserlist));
            // else, check if user exist in user list
            let index = userListFile.userList.findIndex((element) => element.userName.toLowerCase() === req.query.userName.toLowerCase())
            // if user exist, return user information
            if (index != null) {
                // if user not exist, return error
                res.send(userListFile.userList[index]);

            }
            else {
                // if user not exist, return error
                res.send({ result: "Error: Cannot Find User" });

            }

        }
    }
    // if null return error
    else {
        res.send({ result: "Error: Insufficient Parameter" });
    }

});


/**
 * @description  
 * @param       {} req - user name
 * @returns taskId
 */
app.get("/getDevices", (req, res) => {
    let listDeviceCmd = "https://api.switch-bot.com/v1.0/devices"
    let auth = "d698192195a04cf2667f41df22ee93fed3bd8668ab9e81230a1e51245d4ce63c4378e45fbfb24e8406426ede55be6130"


    // console.log("sending result")
    axios.get(listDeviceCmd, {
        // headers: {'Content-Type': "application/json; charset=utf8" ,'Authorization': auth}
        mode: 'no-cors',
        headers: { 'Authorization': auth },
    }).then(result => {
        // console.log(result.data.body.deviceList)
    })

});

/**
 * @description  
 * @param       {} req - user name
 * @returns taskId
 */
app.get("/getDevicesStatus", (req, res) => {
    let listDeviceCmd = "https://api.switch-bot.com/v1.0/devices/"
    let auth = "d698192195a04cf2667f41df22ee93fed3bd8668ab9e81230a1e51245d4ce63c4378e45fbfb24e8406426ede55be6130"

    listDeviceCmd = listDeviceCmd + req.query.deviceID + "/status"

    // console.log(listDeviceCmd)
    axios.get(listDeviceCmd, {
        // headers: {'Content-Type': "application/json; charset=utf8" ,'Authorization': auth}
        mode: 'no-cors',
        headers: { 'Authorization': auth },
    }).then(result => {
        // // console.log(result.data.body)
        res.send(result.data.body)
    })

});

async function fetchCommandList(devId, command) {
    let listDeviceCmd = "https://api.switch-bot.com/v1.0/devices/"
    let auth = "d698192195a04cf2667f41df22ee93fed3bd8668ab9e81230a1e51245d4ce63c4378e45fbfb24e8406426ede55be6130"
    listDeviceCmd = listDeviceCmd + devId + "/commands"

    let body = { "command": command }

    return new Promise((resolve) => {

        fetch(listDeviceCmd, {
            method: 'post',
            body: JSON.stringify(body),
            headers: { 'Authorization': auth, 'Content-Type': 'application/json; charset=utf8' }
        }).then(res => res.json())
            .then((result) => {
                // // console.log(result)
                resolve(result)
            }).catch((error) => {
                // console.log(error)
            })
        // const data = await response.json();

    })
}

/**
 * @description  
 * @param       {} req - user name
 * @returns taskId
 */
app.get("/postDevicesCommand", (req, res) => {

    fetchCommandList(req.query.deviceID, req.query.command).then((result) => {
        // // console.log("done:", result)
        res.send(result)
    })

});



app.get("/pass", (req, res) => {
    if (req.query.token != undefined) {
        console.log("success");

        res.status(201).json({ token });
    } else {
        res.status(400).send("Error");
    }
})

//app.listen(port, () => console.log("server running on port" + port))

var server = https.createServer(options, app).listen(port, function () {
    console.log("server running on port" + port);
    //console.log('Open ' + url.format(asUrl) + ' with a WebRTC capable browser');
  });

module.exports = app;