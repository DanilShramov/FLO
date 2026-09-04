const ADMIN_UID = "0chboPZMvGQhR92hbkM37tUhJ0l1";
const FIREBASE_WEB_API_KEY = "AIzaSyDm4TBEVuiv-d1y64WvimmVeWE9G-xb9-A";

export async function onRequestPost(context) {
  try {
    const { request, env } = context;

    const authorization = request.headers.get("Authorization") || "";
    const idToken = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";

    if (!idToken) {
      return json({ error: "Unauthorized" }, 401);
    }

    const lookupResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_WEB_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken }),
      }
    );

    const lookupData = await lookupResponse.json();
    const callerUid = lookupData?.users?.[0]?.localId;

    if (!lookupResponse.ok || callerUid !== ADMIN_UID) {
      return json({ error: "Admin access required" }, 403);
    }

    const body = await request.json();
    const uid = body?.uid;

    if (!uid || typeof uid !== "string") {
      return json({ error: "Employee UID required" }, 400);
    }

    if (uid === ADMIN_UID) {
      return json({ error: "Admin account cannot be deleted" }, 400);
    }

    const accessToken = await getGoogleAccessToken(env);

    const deleteResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/accounts:delete`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ localId: uid }),
      }
    );

    const deleteData = await deleteResponse.json().catch(() => ({}));

    if (!deleteResponse.ok) {
      return json({
        error: "Firebase Authentication deletion failed",
        details: deleteData,
      }, 500);
    }

    return json({ ok: true, uid });

  } catch (error) {
    return json({
      error: String(error?.message || error)
    }, 500);
  }
}

export async function onRequestGet() {
  return json({
    ok: true,
    service: "FLO delete-user"
  });
}

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const payload = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/identitytoolkit",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const unsignedToken =
    base64url(JSON.stringify(header)) +
    "." +
    base64url(JSON.stringify(payload));

  const privateKey = (env.FIREBASE_PRIVATE_KEY || "")
    .replace(/\\n/g, "\n")
    .trim();

  const keyData = pemToArrayBuffer(privateKey);

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const assertion =
    unsignedToken + "." + arrayBufferToBase64url(signature);

  const tokenResponse = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type:
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
    }
  );

  const tokenData = await tokenResponse.json();

if (!tokenResponse.ok || !tokenData.access_token) {
  throw new Error(
    "Google token error: " + JSON.stringify(tokenData)
  );
}

  return tokenData.access_token;
}

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

function base64url(value) {
  return arrayBufferToBase64url(
    new TextEncoder().encode(value)
  );
}

function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    },
  });
}
