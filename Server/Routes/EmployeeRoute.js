import express from 'express';
import jwt from 'jsonwebtoken';
import con from "../database.js";
import bcrypt from 'bcrypt';

const router = express.Router();

// Employee Login
router.post("/employee_login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ loginStatus: false, Error: "Email and password required" });
  }

  const sql = "SELECT * FROM employee WHERE email = ?";
  con.query(sql, [email], (err, result) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ loginStatus: false, Error: "Internal server error" });
    }

    if (result.length === 0) {
      return res.status(401).json({ loginStatus: false, Error: "Wrong email or password" });
    }

    const employee = result[0];

    // Compare password (hashed or plaintext)
    bcrypt.compare(password.toString(), employee.password.toString(), (bErr, isMatch) => {
      if (bErr) {
        console.error("Bcrypt error:", bErr);
        return res.status(500).json({ loginStatus: false, Error: "Password comparison error" });
      }

      if (!isMatch) {
        return res.status(401).json({ loginStatus: false, Error: "Wrong email or password" });
      }

      // Sign JWT with employee id
      const token = jwt.sign(
        { role: "employee", email: employee.email, id: employee.id },
        "jwt_secret_key_modesty_kings",
        { expiresIn: "1d" }
      );

      res.cookie("token", token, { httpOnly: true, sameSite: "lax" });

      return res.json({ loginStatus: true, id: employee.id });
    });
  });
});

//Get Employee Details
router.get("/detail/:id", (req, res) => {
    const id = req.params.id;
    console.log("Fetching employee id:", id);
    const sql = `
      SELECT e.*, c.name AS category_name
      FROM employee e
      LEFT JOIN category c ON e.category_id = c.id
      WHERE e.id = ?
    `;
    con.query(sql, [id], (err, result) => {
        if (err) {
            console.error("SQL Error:", err);
            return res.status(500).json({ error: "Internal server error" });
        }
        if (result.length === 0) return res.status(404).json({ error: "Employee not found" });

        res.json(result[0]); 
    });
});

//Logout
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: true });
});

export { router as EmployeeRouter };
