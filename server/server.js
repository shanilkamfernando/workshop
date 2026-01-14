import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "./db.js"; // PostgreSQL pool
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { log } from "console";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

//------------------------------middleware---------------------------------------------------
app.use(
  cors({
    origin: "http://localhost:3000",
  })
);

app.use(express.json());

// Serve static files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "uploads", "partners");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "partner-" + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only images are allowed"));
    }
  },
});

//---------------------------------JWT Auth Middleware------------------------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

//----------------------------signup route-------------------------------------------------------
app.post("/signup", async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    // Check if user exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR username=$2",
      [email, username]
    );
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into DB
    await pool.query(
      `INSERT INTO users (username, email, password_hash, role)
         VALUES ($1, $2, $3, $4)`,
      [username, email, hashedPassword, role]
    );

    res.json({ message: "Signup successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//----------------------------login route-------------------------------------------------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user
    const userResult = await pool.query("SELECT * FROM users WHERE email=$1", [
      email,
    ]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const user = userResult.rows[0];

    // Check password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Generate JWT
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        username: user.username,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//delete a partner (admin only)
app.delete("/partners/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admin can delete partners " });
  }

  const { id } = req.params;

  try {
    const projectCheck = await pool.query(
      "SELECT COUNT(*) as count FROM projects WHERE partner_id = $1",
      [id]
    );

    if (parseInt(projectCheck.rows[0].count) > 0) {
      return res.status(400).json({
        error:
          "Cannot delete partner with existing projects. Delete projects first.",
      });
    }

    //delete the partner
    const result = await pool.query(
      "DELETE FROM partners WHERE id = $1 RETURNING id, name",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Partner not found" });
    }
    res.json({
      message: "Partner deleted successfully",
      deleted: result.rows[0],
    });
  } catch (err) {
    console.error("Error deleting partner:", err);
    res.status(500).json({ error: "Error deleting partner" });
  }
});

app.get("/partners/status/all", authenticateToken, async (req, res) => {
  // Only admin can see notifications
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access Denied - Admin only" });
  }

  try {
    const result = await pool.query(
      "SELECT id, name FROM partners ORDER BY id"
    );

    // For each partner, count pending entries across all projects
    const partnersWithStatus = await Promise.all(
      result.rows.map(async (partner) => {
        const countResult = await pool.query(
          `SELECT 
            COUNT(*) FILTER (WHERE order_form_no IS NULL AND user_id IS NOT NULL) as new_entries,
            COUNT(*) FILTER (WHERE order_form_no IS NOT NULL AND approved IS FALSE) as pending_approval,
            COUNT(*) FILTER (WHERE approved IS TRUE AND po_no IS NULL) as approved_pending_po,
            COUNT(*) FILTER (WHERE po_no IS NOT NULL AND invoice_no IS NULL) as pending_invoice,
            COUNT(*) FILTER (WHERE invoice_no IS NOT NULL AND driver_description IS NULL) as pending_driver
          FROM data_entries de
          JOIN projects p ON de.project_id = p.id
          WHERE p.partner_id = $1`,
          [partner.id]
        );

        const counts = countResult.rows[0];
        const totalPending =
          parseInt(counts.new_entries) +
          parseInt(counts.pending_approval) +
          parseInt(counts.approved_pending_po) +
          parseInt(counts.pending_invoice) +
          parseInt(counts.pending_driver);

        let notificationColor = null;

        if (counts.new_entries > 0) {
          notificationColor = "red";
        } else if (counts.pending_approval > 0) {
          notificationColor = "yellow";
        } else if (counts.approved_pending_po > 0) {
          notificationColor = "green";
        } else if (counts.pending_invoice > 0) {
          notificationColor = "orange";
        } else if (counts.pending_driver > 0) {
          notificationColor = "gray";
        }

        return {
          ...partner,
          notificationColor,
          totalPending,
          counts: {
            newEntries: parseInt(counts.new_entries),
            pendingApproval: parseInt(counts.pending_approval),
            approvedPendingPo: parseInt(counts.approved_pending_po),
            pendingInvoice: parseInt(counts.pending_invoice),
            pendingDriver: parseInt(counts.pending_driver),
          },
        };
      })
    );

    res.json(partnersWithStatus);
  } catch (err) {
    console.error("Error fetching partners with status:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Add this new endpoint for office users to see partner status
app.get("/partners/status/office", authenticateToken, async (req, res) => {
  // Only office and admin can see notifications
  if (req.user.role !== "office" && req.user.role !== "admin") {
    return res.status(403).json({ error: "Access Denied" });
  }

  try {
    const result = await pool.query(
      "SELECT id, name FROM partners ORDER BY id"
    );

    // For each partner, count pending entries that office needs to handle
    const partnersWithStatus = await Promise.all(
      result.rows.map(async (partner) => {
        const countResult = await pool.query(
          `SELECT 
            COUNT(*) FILTER (WHERE order_form_no IS NULL AND user_id IS NOT NULL) as new_entries,
            COUNT(*) FILTER (WHERE approved IS TRUE AND po_no IS NULL) as approved_pending_po,
            COUNT(*) FILTER (WHERE po_no IS NOT NULL AND invoice_no IS NULL) as pending_invoice,
            COUNT(*) FILTER (WHERE invoice_no IS NOT NULL AND driver_description IS NULL) as pending_driver
          FROM data_entries de
          JOIN projects p ON de.project_id = p.id
          WHERE p.partner_id = $1`,
          [partner.id]
        );

        const counts = countResult.rows[0];
        const totalPending =
          parseInt(counts.new_entries) +
          parseInt(counts.approved_pending_po) +
          parseInt(counts.pending_invoice) +
          parseInt(counts.pending_driver);

        let notificationColor = null;

        // Priority order for office users (no yellow for approval)
        if (counts.new_entries > 0) {
          notificationColor = "red"; // New entries need Order Form No
        } else if (counts.approved_pending_po > 0) {
          notificationColor = "green"; // Approved entries need PO
        } else if (counts.pending_invoice > 0) {
          notificationColor = "orange"; // PO added, need Invoice
        } else if (counts.pending_driver > 0) {
          notificationColor = "gray"; // Invoice added, need Driver details
        }

        return {
          ...partner,
          notificationColor,
          totalPending,
          counts: {
            newEntries: parseInt(counts.new_entries),
            approvedPendingPo: parseInt(counts.approved_pending_po),
            pendingInvoice: parseInt(counts.pending_invoice),
            pendingDriver: parseInt(counts.pending_driver),
          },
        };
      })
    );

    res.json(partnersWithStatus);
  } catch (err) {
    console.error("Error fetching partners with status for office:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get project status with notification indicators
app.get("/projects/:partnerId/status", authenticateToken, async (req, res) => {
  const { partnerId } = req.params;

  try {
    const projectsResult = await pool.query(
      "SELECT id, name, partner_id FROM projects WHERE partner_id = $1 ORDER BY id",
      [partnerId]
    );

    const projectsWithStatus = await Promise.all(
      projectsResult.rows.map(async (project) => {
        const entriesResult = await pool.query(
          `SELECT 
            COUNT(*) FILTER (WHERE order_form_no IS NULL AND user_id IS NOT NULL) as new_entries,
            COUNT(*) FILTER (WHERE order_form_no IS NOT NULL AND approved IS FALSE) as pending_approval,
            COUNT(*) FILTER (WHERE approved IS TRUE AND po_no IS NULL) as approved_pending_po,
            COUNT(*) FILTER (WHERE po_no IS NOT NULL AND invoice_no IS NULL) as pending_invoice,
            COUNT(*) FILTER (WHERE invoice_no IS NOT NULL AND driver_description IS NULL) as pending_driver
          FROM data_entries 
          WHERE project_id = $1`,
          [project.id]
        );

        const counts = entriesResult.rows[0];
        const totalPending =
          parseInt(counts.new_entries) +
          parseInt(counts.pending_approval) +
          parseInt(counts.approved_pending_po) +
          parseInt(counts.pending_invoice) +
          parseInt(counts.pending_driver);

        let notificationColor = null;

        if (counts.new_entries > 0) {
          notificationColor = "red";
        } else if (counts.pending_approval > 0) {
          notificationColor = "yellow";
        } else if (counts.approved_pending_po > 0) {
          notificationColor = "green";
        } else if (counts.pending_invoice > 0) {
          notificationColor = "orange";
        } else if (counts.pending_driver > 0) {
          notificationColor = "gray";
        }

        return {
          ...project,
          notificationColor,
          totalPending,
          counts: {
            newEntries: parseInt(counts.new_entries),
            pendingApproval: parseInt(counts.pending_approval),
            approvedPendingPo: parseInt(counts.approved_pending_po),
            pendingInvoice: parseInt(counts.pending_invoice),
            pendingDriver: parseInt(counts.pending_driver),
          },
        };
      })
    );

    res.json(projectsWithStatus);
  } catch (err) {
    console.error("Error fetching project status:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Add this new endpoint for office users to see project status
app.get(
  "/projects/:partnerId/status/office",
  authenticateToken,
  async (req, res) => {
    const { partnerId } = req.params;

    // Only office and admin can see notifications
    if (req.user.role !== "office" && req.user.role !== "admin") {
      return res.status(403).json({ error: "Access Denied" });
    }

    try {
      const projectsResult = await pool.query(
        "SELECT id, name, partner_id FROM projects WHERE partner_id = $1 ORDER BY id",
        [partnerId]
      );

      const projectsWithStatus = await Promise.all(
        projectsResult.rows.map(async (project) => {
          const entriesResult = await pool.query(
            `SELECT 
            COUNT(*) FILTER (WHERE order_form_no IS NULL AND user_id IS NOT NULL) as new_entries,
            COUNT(*) FILTER (WHERE approved IS TRUE AND po_no IS NULL) as approved_pending_po,
            COUNT(*) FILTER (WHERE po_no IS NOT NULL AND invoice_no IS NULL) as pending_invoice,
            COUNT(*) FILTER (WHERE invoice_no IS NOT NULL AND driver_description IS NULL) as pending_driver
          FROM data_entries 
          WHERE project_id = $1`,
            [project.id]
          );

          const counts = entriesResult.rows[0];
          const totalPending =
            parseInt(counts.new_entries) +
            parseInt(counts.approved_pending_po) +
            parseInt(counts.pending_invoice) +
            parseInt(counts.pending_driver);

          let notificationColor = null;

          // Priority order for office users
          if (counts.new_entries > 0) {
            notificationColor = "red";
          } else if (counts.approved_pending_po > 0) {
            notificationColor = "green";
          } else if (counts.pending_invoice > 0) {
            notificationColor = "orange";
          } else if (counts.pending_driver > 0) {
            notificationColor = "gray";
          }

          return {
            ...project,
            notificationColor,
            totalPending,
            counts: {
              newEntries: parseInt(counts.new_entries),
              approvedPendingPo: parseInt(counts.approved_pending_po),
              pendingInvoice: parseInt(counts.pending_invoice),
              pendingDriver: parseInt(counts.pending_driver),
            },
          };
        })
      );

      res.json(projectsWithStatus);
    } catch (err) {
      console.error("Error fetching project status for office:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

//create partner
app.post(
  "/partners",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    console.log("Create partner request received");
    console.log("Body", req.body);
    console.log("File:", req.file);

    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Only admin can create partners" });
    }

    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Partner name is required" });
    }

    try {
      const imageUrl = req.file
        ? `/uploads/partners/${req.file.filename}`
        : null;

      const result = await pool.query(
        "INSERT INTO partners (name, image_url) VALUES ($1, $2) RETURNING id, name, image_url",
        [name.trim(), imageUrl]
      );

      console.log("Partner Created", result.rows[0]);
      res.json(result.rows[0]);
    } catch (err) {
      console.error("Error creating partner:", err);
      res
        .status(500)
        .json({ error: "Error creating partner", details: err.message });
    }
  }
);

//get all the partners
app.get("/partners", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name FROM partners ORDER BY id"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching partners:", err);
    res.status(500).json({ error: "Error getting partners" });
  }
});

app.get("/projects/:partnerId", authenticateToken, async (req, res) => {
  const { partnerId } = req.params;

  console.log("==== GET PROJECTS ======");
  console.log("Partner ID:", partnerId);
  console.log("User:", req.user.username);

  try {
    const result = await pool.query(
      "SELECT id, name, partner_id FROM projects WHERE partner_id = $1 ORDER BY id",
      [partnerId]
    );

    console.log("Projects found:", result.rows.length);
    console.log("Projects:", result.rows);

    res.json(result.rows);
  } catch (err) {
    console.error("=== ERROR FETCHING PROJECTS ===");
    console.error("Error message:", err.message);
    console.error("Error code:", err.code);
    console.error("Full error:", err);
    res
      .status(500)
      .json({ error: "Error getting projects", details: err.message });
  }
});

//Optional ----> Get project info
app.get("/projects/info/:projectId", authenticateToken, async (req, res) => {
  const { projectId } = req.params;

  console.log("Fetching project info for:", projectId);

  try {
    const result = await pool.query(
      `SELECT p.id, p.name, p.partner_id, pa.name as partner_name
       FROM projects p
       JOIN partners pa ON p.partner_id = pa.id
       WHERE p.id = $1`,
      [projectId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Project not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching project info:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Create a project under a partner (POST /projects) - admin only
app.post("/projects", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admin can create projects" });
  }

  const { name, partnerId } = req.body;
  if (!name || !name.trim() || !partnerId) {
    return res
      .status(400)
      .json({ error: "Project name and partnerId are required" });
  }

  try {
    // ensure partner exists
    const partnerCheck = await pool.query(
      "SELECT id FROM partners WHERE id = $1",
      [partnerId]
    );
    if (partnerCheck.rows.length === 0) {
      return res.status(404).json({ error: "Partner not found" });
    }

    const result = await pool.query(
      "INSERT INTO projects (name, partner_id) VALUES ($1, $2) RETURNING id, name, partner_id",
      [name.trim(), partnerId]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error creating project:", err);
    res.status(500).json({ error: "Error creating project" });
  }
});

//delete a project (admin only)
app.delete("/projects/:id", authenticateToken, async (req, res) => {
  console.log("🔴 DELETE PROJECT ROUTE HIT");
  console.log("Project ID to delete:", req.params.id);
  console.log("User:", req.user?.username, "Role:", req.user?.role);

  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admin can delete projects" });
  }

  const { id } = req.params;

  try {
    // Check if project has entries
    const entryCheck = await pool.query(
      "SELECT COUNT(*) as count FROM data_entries WHERE project_id = $1",
      [id]
    );

    if (parseInt(entryCheck.rows[0].count) > 0) {
      return res.status(400).json({
        error:
          "Cannot delete project with existing entries. Delete entries first or contact system administrator.",
      });
    }

    // Delete the project
    const result = await pool.query(
      "DELETE FROM projects WHERE id = $1 RETURNING id, name, partner_id",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Project not found" });
    }

    res.json({
      message: "Project deleted successfully",
      deleted: result.rows[0],
    });
  } catch (err) {
    console.error("Error deleting project:", err);
    res.status(500).json({ error: "Error deleting project" });
  }
});

//--------------------------Entries Routes------------------------

//user create entry - with project id
app.post("/entries", authenticateToken, async (req, res) => {
  if (req.user.role !== "user")
    return res.status(403).json({ error: "Access Denied" });

  const { product, quantity, description, due_date, project_id } = req.body;

  //validate project_id
  if (!project_id) {
    return res.status(400).json({ error: "Project ID is required" });
  }

  try {
    await pool.query(
      `INSERT INTO data_entries 
             (user_id, user_name, product, quantity, user_datetime, due_date, description, project_id)
             VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7)`,
      [
        req.user.id,
        req.user.username,
        product,
        quantity,
        due_date,
        description,
        project_id,
      ]
    );
    res.json({ message: "Entry created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//get entries (role-based and project-specific)
app.get("/entries/:projectId", authenticateToken, async (req, res) => {
  const { projectId } = req.params;

  console.log("Fetching entries for project:", projectId);
  console.log("User:", req.user.username, "Role:", req.user.role);

  try {
    let result;
    if (req.user.role === "admin" || req.user.role === "office") {
      result = await pool.query(
        "SELECT * FROM data_entries WHERE project_id=$1 ORDER BY id DESC",
        [projectId]
      );
    } else if (req.user.role === "user") {
      result = await pool.query(
        "SELECT * FROM data_entries WHERE project_id=$1 AND user_id=$2 ORDER BY id DESC",
        [projectId, req.user.id]
      );
    }
    console.log("Entries found:", result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching entries:", err);
    res.status(500).json({ error: "Server error" });
  }
});

//office --> step 1 - Order Form No ----------------------------
app.put("/entries/:id/orderform", authenticateToken, async (req, res) => {
  if (req.user.role !== "office")
    return res.status(403).json({ error: "Access Denied" });

  const { order_form_no, notes } = req.body;
  const entryId = parseInt(req.params.id);

  try {
    console.log("Incoming request", {
      order_form_no,
      notes,
      entryId,
      user: req.user,
    });

    const result = await pool.query(
      `UPDATE data_entries
            SET order_form_no = $1, notes = $2, office_user_1 = $3, office_datetime_1 = NOW()
            WHERE id = $4 RETURNING *`,
      [order_form_no, notes || null, req.user.username, entryId]
    );

    console.log("update success", result.rows[0]);
    res.json(result.rows[0]);

    if (result.rowCount === 0) {
      console.log("no entry found ", entryId);
      return res.status(404).json({ error: "Entry not found" });
    }

    // Return just the entry object, not nested in a message
    console.log("update success", result.rows[0]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//ADMIN --> step 2 - Approve ----------------------------------
app.put("/entries/:id/approve", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Access Denied" });

  try {
    const entryId = parseInt(req.params.id);

    console.log("Approving entry:", entryId);

    const result = await pool.query(
      `UPDATE data_entries 
       SET approved = true
       WHERE id = $1 RETURNING *`,
      [entryId]
    );

    console.log("Entry approved successfully:", result.rows[0]);
    res.json(result.rows[0]); // Return complete entry
  } catch (err) {
    console.error("Approve error:", err);
    res.status(500).json({ error: "Server error approving entry" });
  }
});

//Office --> step 3 - PO no -----------------------------------
app.put("/entries/:id/po", authenticateToken, async (req, res) => {
  if (req.user.role !== "office")
    return res.status(403).json({ error: "Access Denied" });

  const { po_no } = req.body;
  const entryId = parseInt(req.params.id);

  try {
    const result = await pool.query(
      `UPDATE data_entries
            SET po_no = $1, office_user_2 = $2, office_datetime_2 = NOW()
            WHERE id = $3 AND approved = true RETURNING *`,
      [po_no, req.user.username, entryId]
    );

    if (result.rowCount === 0) {
      return res
        .status(400)
        .json({ error: "Entry not approved yet or not found" });
    }

    // Return just the entry object
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// app.put("/entries/:id/po", authenticateToken, async (req, res) =>{
//   if (req.user.role !== "office") return res.status(403).json({error: "Access Denied"});

//   const {po_no} = req.body;
//   const entryId = parseInt(req.params.id);

//   try{
//     const result = await pool.query(
//       `UPDATE data_entries
//       SET po_no=$1, office_user_2=$2, office_datetime_2=NOW()
//       WHERE id=$3 AND approved=TRUE RETURNING *`,
//       [po_no, req.user.username, entryId]
//     );

//     if(result.rowCount === 0){
//       return res.status(400).json({error: "Entry not approved yet"})
//     }
//     res.json({ message: "PO No added", entry: result.rows[0] });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({error: "Server error"});
//   }
// });

//office --> step 4 - Invoice No--------------------------------
app.put("/entries/:id/invoice", authenticateToken, async (req, res) => {
  if (req.user.role !== "office")
    return res.status(403).json({ error: "Access Denied" });

  const { invoice_no } = req.body;
  const entryId = parseInt(req.params.id);

  try {
    // Simple update and return everything
    await pool.query(
      `UPDATE data_entries
            SET invoice_no = $1, office_user_3 = $2, office_datetime_3 = NOW()
            WHERE id = $3`,
      [invoice_no, req.user.username, entryId]
    );

    // Get the complete updated entry
    const result = await pool.query(
      "SELECT * FROM data_entries WHERE id = $1",
      [entryId]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//office --> step 5 - Drivers details
app.put("/entries/:id/driver", authenticateToken, async (req, res) => {
  if (req.user.role !== "office")
    return res.status(403).json({ error: "Access Denied" });

  const {
    purchase_date,
    drivers_name,
    vehicle_no,
    received,
    driver_description,
  } = req.body;
  const entryId = parseInt(req.params.id);

  try {
    // Simple update and return everything
    await pool.query(
      `UPDATE data_entries
            SET purchase_date = $1, drivers_name = $2, vehicle_no = $3, received = $4, driver_description = $5
            WHERE id = $6`,
      [
        purchase_date,
        drivers_name || null,
        vehicle_no || null,
        received || null,
        driver_description || null,
        entryId,
      ]
    );

    // Get the complete updated entry
    const result = await pool.query(
      "SELECT * FROM data_entries WHERE id = $1",
      [entryId]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//Admin update entry
app.put("/entries/:id/admin", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Access denied" });

  const entryId = parseInt(req.params.id, 10);
  const {
    user_name,
    user_datetime,
    product,
    quantity,
    description,
    office_name,
    office_datetime,
    status,
    delivery_date,
    office_locked,
  } = req.body;
  try {
    const result = await pool.query(
      `UPDATE data_entries
           SET 
              user_name = COALESCE($1, user_name),
              user_datetime = COALESCE($2, user_datetime),
              product = COALESCE($3, product),
              quantity = COALESCE($4, quantity),
              description = COALESCE($5, description),
              office_name = COALESCE($6, office_name),
              office_datetime = COALESCE($7, office_datetime),
              status = COALESCE($8, status),
              delivery_date = COALESCE($9, delivery_date),
              office_locked = COALESCE($10, office_locked),
              updated_at = NOW()
           WHERE id=$11
           RETURNING *`,
      [
        user_name,
        user_datetime ? new Date(user_datetime) : null,
        product,
        quantity ? parseInt(quantity) : null,
        description,
        office_name,
        office_datetime ? new Date(office_datetime) : null,
        status,
        delivery_date ? new Date(delivery_date) : null,
        office_locked,
        entryId,
      ]
    );

    if (result.rowCount === 0)
      return res.status(400).json({ error: "Entry not found" });

    res.json({ message: "Entry updated by admin", entry: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
  // const {product, quantity, description, status} = req.body;
  // const entryId = req.params.id;
  // try {
  //     await pool.query(
  //         `UPDATE data_entries
  //         SET product=$1, quantity=$2, description=$3, status=$4, updated_at=NOW()
  //         WHERE id=$5`,
  //         [product, quantity, description, status, req.params.id, entryId]
  //     );
  //     res.json({message: "Entry updated by admin"});
  // } catch (err) {
  //     console.error(err);
  //     res.status(500).json({error: "Server error"});
  // }
});

//get entries (role-based)

app.get("/entries", authenticateToken, async (req, res) => {
  try {
    let result;
    if (req.user.role === "admin") {
      result = await pool.query("SELECT * FROM data_entries ORDER BY id DESC");
    } else if (req.user.role === "user") {
      result = await pool.query(
        "SELECT * FROM data_entries WHERE user_id=$1 ORDER BY id DESC",
        [req.user.id]
      );
    } else if (req.user.role === "office") {
      result = await pool.query("SELECT * FROM data_entries ORDER BY id DESC");
    }
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//------------------testing------------------------------
app.get("/", (req, res) => {
  res.send("Backend is working 🚀");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
