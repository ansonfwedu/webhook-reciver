import express from "express";
import * as crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
const port = 3000;

// Define routes
app.get("/is_server_running", async (request, response) => {
  const body = request.body;
  console.log(`Request recive from client: ${body}`);
  try {
    const parseServerRepsonse = await fetch(
      `${process.env.PARSE_SERVER_URL}/functions/test`,
      {
        method: "POST",
      }
    );
    const data = await parseServerRepsonse.json();
    response.send(data);
  } catch (error) {
    response.send(error);
  }
});

app.post("/zoomWebhook", async (request, response) => {
  const body = request.body;

  console.log(`Recive Zoom Webhook data: ${body}`);
  console.log(`Recive Zoom Webhook header: ${request.headers}`);

  const message = `v0:${
    request.headers["x-zm-request-timestamp"]
  }:${JSON.stringify(body)}`;

  const hashForVerify = crypto
    .createHmac("sha256", process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
    .update(message)
    .digest("hex");

  const signature = `v0=${hashForVerify}`;

  if (request.header["x-zm-signature"] === signature) {
    if (body.event === "endpoint.url_validation") {
      console.log("Request vaildate");
      const hashForVaildate = crypto
        .createHmac("sha256", process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
        .update(body.payload.plainToken)
        .digest("hex");

      const data = {
        plainToken: body.payload.plainToken,
        encryptedToken: hashForVaildate,
      };

      response.json(data);
    }else{
      try {
        const parseServerRepsonse = await fetch(
          `${process.env.PARSE_SERVER_URL}/functions/zoomWebhook`,
          {
            method: "POST",
            body: body
          }
        );
        const data = await parseServerRepsonse.json();
        console.log(`Parse Server Api response: \n${data}`)
      } catch (error) {
        console.log(`Error occurred: ${error}`)
      }
    }

  } else {
    response.json({ status: 141, error: "Invaild request signture" });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
