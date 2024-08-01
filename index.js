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
  try {
    const token = cache.get("token");

    if (token) {
      console.log(`Cached token exist, return cached seession token`);
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
    console.log(`Auth data:${JSON.stringify(authData, null, 2)}`);
    if (authData.sessionToken) {
      cache.set("token", authData.sessionToken, 21600);
      return authData.sessionToken;
    }
    return null;
  } catch (error) {
    console.log(`Error ocurred during login to Parse Server: ${error}`);
    return null;
  }
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

  console.log("Login to Parse Server");

  const sessionToken = await parseServerAuth();
  if (sessionToken) {
    console.log(`Login to Parse server success`);

    const parseServerRes = await fetch(
      `${process.env.PARSE_SERVER_URL}/functions/test`,
      {
        method: "POST",
        headers: {
          ...parseServerHeader,
          "x-parse-session-token": sessionToken,
        },
      }
    );
    const data = await parseServerRes.json();
    response.status(200).send(data);
  } else {
    console.log(`Login to Parse server failed`);
    response.status(500).json({ message: `Login to Parse server failed` });
  }
});

app.post("/zoom-webhook", async (request, response) => {
  const body = request.body;
  console.log(`Request headers:` + JSON.stringify(request.headers, null, 2));
  console.log(`event: ` + JSON.stringify(body.event, null, 2));
  console.log(`payload: ` + JSON.stringify(body.payload, null, 2));

  //Get specify Zoom Webhook token from parse server
  const sessionToken = await parseServerAuth();
  if (sessionToken) {
    console.log("Login to Parse server success");
    if (body.event === "endpoint.url_validation") {
      try {
        const parseServerRes = await fetch(
          `${process.env.PARSE_SERVER_URL}/functions/getZoomWebhookSecret`,
          {
            method: "POST",
            headers: {
              ...parseServerHeader,
              "x-parse-session-token": sessionToken,
            },
            body: JSON.stringify({
              zoom_events: { headers: request.headers, body: body },
            }),
          }
        );
        const parseServerData = await parseServerRes.json();
        if (parseServerData["error"]) {
          console.log(`Get secret token from Parse server failded`);
          response.status(500).send();
        }
        console.log(`Get secret token from Parse server successfully`);

        const hashForVaildate = crypto
          .createHmac("sha256", parseServerData["result"])
          .update(body.payload.plainToken)
          .digest("hex");

        const data = {
          plainToken: body.payload.plainToken,
          encryptedToken: hashForVaildate,
        };
        response.json(data);
      } catch (error) {
        console.log(`Error ocurred during endpoint url validation: ${error}`);
      }
    } else {
      try {
        await fetch(`${process.env.PARSE_SERVER_URL}/functions/zoomWebhook`, {
          method: "POST",
          headers: {
            ...parseServerHeader,
            "x-parse-session-token": sessionToken,
          },
          body: JSON.stringify({
            zoom_events: { headers: request.headers, body: body },
          }),
        });
        console.log("Zoom event forward success");
        response.status(204).send();
      } catch (error) {
        response.status(500).json({ message: "Zoom event forward failed" });
      }
    }
  } else {
    console.log(`Login to Parse server failed`);
    response.status(500).json({ message: "Login to Parse server failed" });
  }
});

const port = 23000;

app.listen(port, () => {
  console.log(`Parse server: ${process.env.PARSE_SERVER_URL}`);
  console.log(`http://localhost:${port}`);
});
