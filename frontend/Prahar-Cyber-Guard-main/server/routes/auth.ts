import { Router, type Request, type Response } from "express";
import { Client, Databases, ID, Query } from "node-appwrite";

const router = Router();

function getServerClient(): Client {
  const client = new Client()
    .setEndpoint(process.env.APPWRITE_ENDPOINT || process.env.VITE_APPWRITE_ENDPOINT || "https://sgp.cloud.appwrite.io/v1")
    .setProject(process.env.APPWRITE_PROJECT_ID || process.env.VITE_APPWRITE_PROJECT_ID || "")
    .setKey(process.env.APPWRITE_API_KEY || "");
  return client;
}

/**
 * POST /api/auth/register
 * Body: { firstName, emailAddress, password }
 * Creates a row in the Users → users collection.
 */
router.post("/register", async (req: Request, res: Response) => {
  const { firstName, emailAddress, password } = req.body as {
    firstName?: string;
    emailAddress?: string;
    password?: string;
  };

  if (!firstName || !emailAddress || !password) {
    res.status(400).json({ error: "firstName, emailAddress, and password are required." });
    return;
  }

  try {
    const client = getServerClient();
    const databases = new Databases(client);

    const databaseId = process.env.APPWRITE_DATABASE_ID || "Users";
    const collectionId = process.env.APPWRITE_COLLECTION_ID || "users";

    const doc = await databases.createDocument(databaseId, collectionId, ID.unique(), {
      firstName,
      emailAddress,
      passwordHash: password,
    });

    res.status(201).json({ id: doc.$id, message: "User registered successfully." });
  } catch (err: any) {
    console.error("[auth] register error:", err?.message || err);
    res.status(500).json({ error: err?.message || "Failed to save user data." });
  }
});

/**
 * POST /api/auth/login
 * Body: { emailAddress, password }
 * Validates credentials against the Users → users collection.
 */
router.post("/login", async (req: Request, res: Response) => {
  const { emailAddress, password } = req.body as {
    emailAddress?: string;
    password?: string;
  };

  if (!emailAddress || !password) {
    res.status(400).json({ error: "emailAddress and password are required." });
    return;
  }

  try {
    const client = getServerClient();
    const databases = new Databases(client);

    const databaseId = process.env.APPWRITE_DATABASE_ID || "Users";
    const collectionId = process.env.APPWRITE_COLLECTION_ID || "users";

    const result = await databases.listDocuments(databaseId, collectionId, [
      Query.equal("emailAddress", [emailAddress]),
    ]);

    if (result.total === 0) {
      res.status(401).json({ error: "No account found with that email." });
      return;
    }

    const user = result.documents[0];
    if (user.passwordHash !== password) {
      res.status(401).json({ error: "Invalid password." });
      return;
    }

    res.status(200).json({ id: user.$id, firstName: user.firstName, message: "Login successful." });
  } catch (err: any) {
    console.error("[auth] login error:", err?.message || err);
    res.status(500).json({ error: err?.message || "Login failed." });
  }
});

export default router;
