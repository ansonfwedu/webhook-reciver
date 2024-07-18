import express from "express";
import * as crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const parseServerHeader = {
  "x-parse-application-id": process.env.PARSE_SERVER_APP_ID,
  "x-parse-rest-api-key": process.env.PARSE_SERVER_RESTAPI_KEY,
};

async function parseServerAuth() {
  const res = await fetch(`${process.env.PARSE_SERVER_URL}/login`, {
    method: "POST",
    headers: parseServerHeader,
    body: JSON.stringify({
      username: process.env.PARSE_SERVER_USERNAME,
      password: process.env.PARSE_SERVER_USER_PASSWORD,
    }),
  });
  const authData = await res.json();
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
    } else {
      console.log(`Login to Parse server failed`);
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
      if (body.event === "endpoint.url_validation") {
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
        await fetch(`${process.env.PARSE_SERVER_URL}/functions/zoomWebhook`, {
          method: "POST",
          headers: {
            ...parseServerHeader,
            "x-parse-session-token": authData.sessionToken,
          },
          body: JSON.stringify({
            zoom_events: { headers: request.headers, body: body },
          }),
        });
        console.log("Zoom event forward success");
      }
    } catch (error) {
      console.log(`${error}`);
    }
  } else {
    console.log(`Login to Parse server failed`);
  }
});

const port = 23000;

app.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
