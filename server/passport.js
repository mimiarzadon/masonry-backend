
const passport = require("passport");
const refresh = require('passport-oauth2-refresh');
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy
const fs = require("fs");
const path = require('path');
//make OAuth2 Credentials file using Google Developer console and download it(credentials.json)
//replace the 'web' using 'installed' in the file downloaded
var pathToJson = path.resolve(__dirname, './credentials.json');
const config = JSON.parse(fs.readFileSync(pathToJson));

// var MICROSOFT_GRAPH_CLIENT_ID = '783c605c-af60-4e98-8e4a-1a87224b630e';
// var MICROSOFT_GRAPH_CLIENT_SECRET = 'ATQ8Q~X3Rpj5dc--J6SAGJC.dkbecemQ2aod_bgP';

var MICROSOFT_GRAPH_CLIENT_ID = '83bf0f5c-fbf1-40e8-ae6f-16703dbf2f38';
var MICROSOFT_GRAPH_CLIENT_SECRET = 'MeP8Q~wNXF5GfLwu-2UptSnFZlYUDZG1JOZ62csN';



passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
        done(null, user);
});

const MSGraphStrategy = new MicrosoftStrategy({
    clientID: MICROSOFT_GRAPH_CLIENT_ID,
    clientSecret: MICROSOFT_GRAPH_CLIENT_SECRET,
    callbackURL: 'https://10.131.178.21:8443/auth/microsoft/callback',
    accessType: 'offline',
    scope: ['user.read', 'offline_access', 'calendars.readWrite', 'tasks.readWrite']
  },
  function (accessToken, refreshToken, params, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
  
      // To keep the example simple, the user's Microsoft Graph profile is returned to
      // represent the logged-in user. In a typical application, you would want
      // to associate the Microsoft account with a user record in your database,
      // and return that user instead.
      // console.log("profile:", profile)
      
  
    let tokens = {
        access_token: accessToken,
        refresh_token: refreshToken,
        scope: params.scope,
        token_type: params.token_type,
        expiry_date:params.expires_in
    };
  
        // get full path of session.json from __dirname if it exist
        var pathToSession = path.resolve(__dirname, '../session.json');
        // read session file and parse to create oject session, contains userName, and gtoken
        let session = JSON.parse(fs.readFileSync(pathToSession));
        // console.log("creating token for mom", session.gtoken);
        
        // convert token object to JSON
        let data = JSON.stringify(tokens);
        // console.log("data:", data)

        let tokenDat = {}
        // if tocken file has been created
        if(fs.existsSync(session.gtoken))
        {
            tokenDat = JSON.parse(fs.readFileSync(session.gtoken));
        }


        tokenDat["msgraph"] = data;
        // console.log("ms graph tokenDat after:", tokenDat)

        // write token to token file
        let updatedTokenFile = JSON.stringify(tokenDat);
        fs.writeFileSync(session.gtoken, updatedTokenFile);

        if(!fs.existsSync("./sessionList.json"))
        {
            // create if not existing
            let userSessionList = {userList: []};
            let strUserSessList = JSON.stringify(userSessionList);
            fs.writeFileSync("./sessionList.json", strUserSessList);
        }

        let sessionList = JSON.parse(fs.readFileSync("./sessionList.json"));
        let index = sessionList.userList.findIndex((element) => element.userName.toLowerCase() === session.userName)
        if(index === -1)
        {
            sessionList.userList.push(session)
            let newSessList = JSON.stringify(sessionList);
            fs.writeFileSync("./sessionList.json", newSessList);
            
        }
  
  
  
      return done(null, profile);
    });
  }
  )

// Use the MicrosoftStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and profile),
//   and invoke a callback with a user object.
passport.use(MSGraphStrategy);
refresh.use(MSGraphStrategy);


const GoogleAPIStrategy = new GoogleStrategy({
    clientID:config.web.client_id,
    clientSecret:config.web.client_secret,
    callbackURL: config.web.redirect_uris[0],
    passReqToCallback   : true
},
function(request, accessToken, refreshToken, params, profile, done) {
    // console.log(request.query);
    let tokens = {
            access_token: accessToken,
            refresh_token: refreshToken,
            scope: params.scope,
            token_type: params.token_type,
            expiry_date:params.expires_in
        };

        // console.log("refreshToken:", refreshToken)
    
        // get full path of session.json from __dirname if it exist
    var pathToSession = path.resolve(__dirname, '../session.json');
    // read session file and parse to create oject session, contains userName, and gtoken
    let session = JSON.parse(fs.readFileSync(pathToSession));
    // console.log("creating token for mom", session.gtoken);
    
    // convert token object to JSON
    let data = JSON.stringify(tokens);
    // console.log("data:", data)

    let tokenDat = {}
    // if tocken file has been created
    if(fs.existsSync(session.gtoken))
    {
        tokenDat = JSON.parse(fs.readFileSync(session.gtoken));
    }

    // console.log("tokenDat:", tokenDat)

    tokenDat["google"] = data;
    // console.log("tokenDat after:", tokenDat)

    // write token to token file
    let updatedTokenFile = JSON.stringify(tokenDat);
    fs.writeFileSync(session.gtoken, updatedTokenFile);

    if(!fs.existsSync("./sessionList.json"))
    {
        // create if not existing
        let userSessionList = {userList: []};
        let strUserSessList = JSON.stringify(userSessionList);
        fs.writeFileSync("./sessionList.json", strUserSessList);
    }

    let sessionList = JSON.parse(fs.readFileSync("./sessionList.json"));
    let index = sessionList.userList.findIndex((element) => element.userName.toLowerCase() === session.userName)
    if(index === -1)
    {
        sessionList.userList.push(session)
        let newSessList = JSON.stringify(sessionList);
        fs.writeFileSync("./sessionList.json", newSessList);
        
    }

    return done(null, profile);
}
)

passport.use(GoogleAPIStrategy);
refresh.use(GoogleAPIStrategy);
