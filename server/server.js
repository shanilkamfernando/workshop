import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "./db.js"; // PostgreSQL pool

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

//------------------------------middleware---------------------------------------------------
app.use(cors({
    origin: "http://localhost:3000"
  }));

app.use(express.json());

//---------------------------------JWT Auth Middleware------------------------------------------
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if(!token) return res.sendStatus(401);

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
      const userResult = await pool.query(
        "SELECT * FROM users WHERE email=$1",
        [email]
      );
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
        { id: user.id, email: user.email, role: user.role, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
  
      res.json({ message: "Login successful", token, user: { id: user.id, username: user.username, role: user.role } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  });

//--------------------------Entries Routes------------------------

//user create entry
app.post("/entries", authenticateToken, async (req, res) => {
    if (req.user.role !== "user") return res.status(403).json({error: "Access Denied"});

    const {product, quantity, description, due_date} = req.body;
    try {
        await pool.query(
           `INSERT INTO data_entries 
             (user_id, user_name, product, quantity, user_datetime, due_date, description)
             VALUES ($1, $2, $3, $4, NOW(), $5, $6)`,
            [req.user.id, req.user.username, product, quantity, due_date, description]
        );
        res.json({message: "Entry created successfully"});
        alert("Entry Created successfully");
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Server error"});
    }
});

//office update entry
// app.put("/entries/:id/office", authenticateToken, async (req, res) => {

//   if (req.user.role !== "office") 
//         return res.status(403).json({error: "Access Denied"});

//     const {status, delivery_date} = req.body;
//     const entryId = parseInt(req.params.id);
//     try {
//         const result = await pool.query(
//             `UPDATE data_entries
//      SET office_id=$1, office_name=$2, office_datetime=NOW(), status=$3, delivery_date=$4, office_locked=TRUE, updated_at=NOW()
//      WHERE id=$5 AND office_locked=FALSE
//      RETURNING id, office_name, office_datetime, status, delivery_date, office_locked`,
//             [req.user.id, req.user.username, status, delivery_date ? new Date(delivery_date) : null, entryId]
//         );

//         if (result.rowCount === 0)
//             return res.status(400).json({error: "Entry is already loacked or does not exist"});

//         res.json({message: "Entry updated by office", entry: result.rows[0]});
//         alert("Entry updated by the Office");
//     } catch (err) {
//         console.log(err);
//         res.status(500).json({error: "Server error"});
//     }
// });

//office --> step 1 - Order Form No ----------------------------
app.put("/entries/:id/orderform", authenticateToken, async (req, res) => {
    if (req.user.role !== "office") return res.status(403).json({error: "Access Denied"});

    const {order_form_no} = req.body;
    const entryId = parseInt(req.params.id);
    
    try {
        const result = await pool.query(
            `UPDATE data_entries
            SET order_form_no = $1, office_user_1 = $2, office_datetime_1 = NOW()
            WHERE id = $3 RETURNING *`,
            [order_form_no, req.user.username, entryId]
        );
        
        if (result.rowCount === 0) {
            return res.status(404).json({error: "Entry not found"});
        }
        
        // Return just the entry object, not nested in a message
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Server error"});
    }
});
// app.put("/entries/:id/orderform", authenticateToken, async (req, res) => {
//   if (req.user.role !== "office") return res.status(403).json({error: "Access Denied"});

//   const {order_form_no} = req.body;
//   const entryId = parseInt(req.params.id);
//   try{
//     const result = await pool.query(
//       `UPDATE data_entries
//       SET order_form_no= $1, office_user_1=$2, office_datetime_1=NOW()
//       WHERE id=$3 RETURNING *`,
//       [order_form_no, req.user.username, entryId]
//     );
//     res.json({message: "Order Form No added", entry: result.rows[0] });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({error: "server error"});
//   }
// });




//ADMIN --> step 2 - Approve ----------------------------------
app.put("/entries/:id/approve", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({error: "Access Denied"});
  
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
// app.put("/entries/:id/approve", authenticateToken, async (req, res) => {
//   console.log("=== APPROVE ROUTE HIT ===");
//   console.log("User role:", req.user.role);
//   console.log("Entry ID:", req.params.id);
//   console.log("Request body:", req.body);
  
//   try {
//     // Simple role check
//     if (req.user.role !== "admin") {
//       console.log("Access denied - not admin");
//       return res.status(403).json({error: "Access Denied"});
//     }
    
//     const entryId = parseInt(req.params.id);
//     console.log("Parsed entry ID:", entryId);
    
//     // Just try to update - no fancy checks
//     const result = await pool.query(
//       "UPDATE data_entries SET approved = true WHERE id = $1 RETURNING *",
//       [entryId]
//     );
    
//     console.log("Query executed, rows affected:", result.rowCount);
    
//     if (result.rowCount === 0) {
//       console.log("No rows updated");
//       return res.status(404).json({ error: "Entry not found" });
//     }
    
//     console.log("Success! Returning:", result.rows[0]);
//     res.json(result.rows[0]);
    
//   } catch (err) {
//     console.error("=== ERROR IN APPROVE ROUTE ===");
//     console.error("Error message:", err.message);
//     console.error("Error code:", err.code);
//     console.error("Error detail:", err.detail);
//     console.error("Full error:", err);
//     res.status(500).json({ 
//       error: "Server error approving entry", 
//       details: err.message,
//       code: err.code 
//     });
//   }
// });


// app.put("/entries/:id/approve", authenticateToken, async (req, res) => {

//   console.log("Approve route hit - user role", req.user.role);
//   console.log("request params", req.params);
//   console.log("request body", req.body);

//   if (req.user.role !== "admin") return res.status(403).json({error: "Access Denied"});
// try {
//    const {entryId} = parseInt(req.params.id);
//   const {approved} = req.body;

//   //first check if entry ecists and has order_form_no
//   const checkResult = await pool.query(
//     "SELECT * FROM data_entries WHERE id = $1",
//     [entryId]
//   );

//   if (checkResult.rows.length === 0){
//     return res.status(404).json({error: "Entry not found"});
//   }

//   const entry = checkResult.rows[0];

//   if (!entry.order_form_no){
//     return res.status(400).json({error: "Cannot approve: order form no missing"});
//   }

//   // update the entry
//   const result = await pool.query(
//     `UPDATE data_entries
//     SET approved = $1, updated_at = NOW()
//     WHERE id = $2
//     RETURNING *`,
//     [approved, entryId]
//   );
//   console.log("updated successfu;, rows affected:", result.rowCount)
//   res.json(result.rows[0]);
// }
// catch (err){
//   console.error("error in approve route", err.message);
//   console.error("full error", err);
//   res.status(500).json({error: "Server error approving entry"});
// }
//   // const entry = await Entry.findByPk(id);
//   // if(!entry) return res.status(404).json({error: "Entry not found"});

//   // if(!entry.order_form_no){
//   //   return res.status(400).json({error: "Cannot approve: Order Form no missing"});
//   // }
// //   entry.approved = approved;
// //   await entry.save();

// //   res.json(entry) //return updated entry
// // } catch (err) {
// //    console.error(err);
// //     res.status(500).json({ error: "Server error approving entry" });
// // }
 
//   // try {
//   //   const result = await pool.query(
//   //     `UPDATE data_entries
//   //     SET approved=TRUE
//   //     WHERE id=$2 RETURNING *`,
//   //     [entryId]
//   //   );
//   //   res.json({message: "Entry Approved", entry: result.rows[0] });
//   // } 
//   // catch (err) {
//   //   console.error(err);
//   //   res.status(500).json({error: "Server error"});
//   // }
// });



//Office --> step 3 - PO no -----------------------------------
app.put("/entries/:id/po", authenticateToken, async (req, res) => {
    if (req.user.role !== "office") return res.status(403).json({error: "Access Denied"});

    const {po_no} = req.body;
    const entryId = parseInt(req.params.id);

    try {
        const result = await pool.query(
            `UPDATE data_entries
            SET po_no = $1, office_user_2 = $2, office_datetime_2 = NOW()
            WHERE id = $3 AND approved = true RETURNING *`,
            [po_no, req.user.username, entryId]
        );

        if (result.rowCount === 0) {
            return res.status(400).json({error: "Entry not approved yet or not found"});
        }
        
        // Return just the entry object
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Server error"});
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
    if (req.user.role !== "office") return res.status(403).json({error: "Access Denied"});

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
// app.put("/entries/:id/invoice", authenticateToken, async (req, res) => {
//   if(req.user.role !== "office") return res.status(403).json({error: "Access Denied"});

//   const {invoice_no} = req.body;
//   const entryId = parseInt(req.params.id);
//   console.log("Invoice update request:", req.body, "Entry ID:", entryId)
//   try {
//     const result = await pool.query(
//       `UPDATE data_entries
//       SET invoice_no=$1, office_user_3=$2, invoice_datetime=NOW()
//       WHERE id=$3 AND po_no IS NOT NULL RETURNING *`,
//       [invoice_no, req.user.username, entryId]
//     );

//     if (result.rowCount === 0){
//       return res.status(400).json({error: "PO number is not added yet"})
//     }
//     res.json({ message: "Invoice No added", entry: result.rows[0] });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Server error" });
//   }
// })

//Admin update entry
app.put("/entries/:id/admin", authenticateToken, async (req, res) => {
    if (req.user.role !== "admin") 
        return res.status(403).json({error: "Access denied"});

    const entryId = parseInt(req.params.id, 10);
    const {user_name,user_datetime,product,quantity,description,office_name,office_datetime,status,delivery_date,office_locked} = req.body;
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
              entryId
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
        if (req.user.role === "admin"){
            result = await pool.query (
                "SELECT * FROM data_entries ORDER BY id DESC"
            );
        } else if (req.user.role === "user") {
            result = await pool.query(
                "SELECT * FROM data_entries WHERE user_id=$1 ORDER BY id DESC",
                [req.user.id]
            );
        } else if (req.user.role === "office") {
            result = await pool.query(
                "SELECT * FROM data_entries ORDER BY id DESC"
            );
        }
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Server error"});
    }
});

//------------------testing------------------------------
app.get("/", (req, res) => {
  res.send("Backend is working 🚀");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
