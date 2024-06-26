import express from "express";
import * as crypto from "crypto";
import dotenv from "dotenv";
import NodeCache from "node-cache";

dotenv.config();
const app = express();
const cache = new NodeCache();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const parseServerHeader = {
  "x-parse-application-id": process.env.PARSE_SERVER_APP_ID,
  "x-parse-rest-api-key": process.env.PARSE_SERVER_RESTAPI_KEY,
};

async function parseServerAuth() {
  const cacheKey = "parse-server-sessionToken";
  const token = cache.get(cacheKey);

  if (token) {
    console.log("Session token found in memory cache");
    return token;
  }

  const res = await fetch(`${process.env.PARSE_SERVER_URL}/login`, {
    method: "POST",
    headers: parseServerHeader,
    body: JSON.stringify({
      username: process.env.PARSE_SERVER_USERNAME,
      password: process.env.PARSE_SERVER_USER_PASSWORD,
    }),
  });
  const authData = await res.json();

  cache.set("parse-server-sessionToken", authData, 3 * 24 * 60 * 60);
  return authData;
}

//Test Zoom Webhook , Fung sir account
app.post("/zoom-webhook/test", async (request, response) => {
  const body = request.body;
  console.log(`Request headers:` + JSON.stringify(request.headers, null, 2));
  console.log(`event: ` + JSON.stringify(body.event, null, 2));
  console.log(`payload: ` + JSON.stringify(body.payload, null, 2));

  const hashForVaildate = crypto
    .createHmac("sha256", process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
    .update(body.payload.plainToken)
    .digest("hex");

  const data = {
    plainToken: body.payload.plainToken,
    encryptedToken: hashForVaildate,
  };

  response.json(data);
});

app.get("/is_server_running", async (request, response) => {
  const body = request.body;
  console.log(`Request headers:` + JSON.stringify(request.headers, null, 2));
  console.log(`event: ` + JSON.stringify(body.event, null, 2));
  console.log(`payload: ` + JSON.stringify(body.payload, null, 2));

  try {
    console.log("Login to Parse Server");

    const authData = await parseServerAuth();
    if (authData.sessionToken) {
      console.log(`Login to Parse server success`);
      const parseServerRes = await fetch(
        `${process.env.PARSE_SERVER_URL}/functions/test`,
        {
          method: "POST",
          headers: {
            ...parseServerHeader,
            "x-parse-session-token": authData.sessionToken,
          },
        }
      );
      const data = await parseServerRes.json();
      response.send(data);
    }
  } catch (error) {
    response.send(error);
  }
});

app.post("/zoom-webhook", async (request, response) => {
  const body = request.body;
  console.log(`Request headers:` + JSON.stringify(request.headers, null, 2));
  console.log(`event: ` + JSON.stringify(body.event, null, 2));
  console.log(`payload: ` + JSON.stringify(body.payload, null, 2));

  //Get specify Zoom Webhook token from parse server
  const authData = await parseServerAuth();
  if (authData.sessionToken) {
    console.log("Login to Parse server success");
    try {
      const parseServerRes = await fetch(
        `${process.env.PARSE_SERVER_URL}/functions/getZoomWebhookSecret`,
        {
          method: "POST",
          headers: {
            ...parseServerHeader,
            "x-parse-session-token": authData.sessionToken,
          },
          body: JSON.stringify({
            zoom_events: { headers: request.headers, body: body },
          }),
        }
      );
      const parseServerData = await parseServerRes.json();

      console.log(`Successfully get secret token from Parse server`);

      if (body.event === "endpoint.url_validation") {
        const hashForVaildate = crypto
          .createHmac("sha256", parseServerData["result"])
          .update(body.payload.plainToken)
          .digest("hex");

        const data = {
          plainToken: body.payload.plainToken,
          encryptedToken: hashForVaildate,
        };

        response.json(data);
      } else {
        fetch(`${process.env.PARSE_SERVER_URL}/functions/zoomWebhook`, {
          method: "POST",
          headers: {
            ...parseServerHeader,
            "x-parse-session-token": authData.sessionToken,
          },
          body: JSON.stringify({
            zoom_events: { headers: request.headers, body: body },
          }),
        });

        response.json({ status: 200, message: "Zoom event forward success" });
      }
    } catch (error) {
      response.json({ status: 141, error: error });
    }
  }
});

const port = 23000;

app.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
