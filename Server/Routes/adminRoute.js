import express from 'express';
import jwt from 'jsonwebtoken';
import con from "../database.js";
import bcrypt from 'bcrypt'; 
import multer from 'multer';
import path from 'path';

const router = express.Router();

// Admin Login
router.post("/adminlogin", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ loginStatus: false, Error: "Email and password required" });

  const sql = "SELECT * FROM admin WHERE email = ?";
  con.query(sql, [email], (err, result) => {
    if (err) {
      console.error('adminlogin query error:', err);
      return res.status(500).json({ loginStatus: false, Error: "Query error" });
    }
    if (result.length === 0) return res.status(401).json({ loginStatus: false, Error: "Wrong email or password" });

    const admin = result[0];
    // support both hashed and plaintext passwords (prefer hashed)
    bcrypt.compare(password.toString(), admin.password.toString(), (bErr, isMatch) => {
      if (bErr) {
        console.error('bcrypt compare error:', bErr);
        // fallback to direct compare if stored password is plaintext
        if (admin.password === password) { 
          const token = jwt.sign({ role: "admin", email:email, id: result[0].id  }, "jwt_secret_key_modesty_kings", { expiresIn: '1d' });
          res.cookie('token', token);
          return res.json({ loginStatus: true });
        }
        return res.status(500).json({ loginStatus: false, Error: "Hashing error" });
      }
      if (!isMatch && admin.password !== password) {
        return res.status(401).json({ loginStatus: false, Error: "Wrong email or password" });
      }
      const token = jwt.sign({ role: "admin", email: admin, id: result[0].id }, "jwt_secret_key_modesty_kings", { expiresIn: '1d' });
      res.cookie('token', token);
      return res.json({ loginStatus: true });
    });
  });
});

// Get all categories
router.get("/category", (req, res) => {
  const sql = "SELECT * FROM category";
  con.query(sql, (err, result) => {
    if (err) {
      console.error('category query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error" });
    }
    return res.json({ Status: true, Result: result });
  });
});

// Add category
router.post("/add_category", (req, res) => {
  const name = (req.body.name || req.body.category || '').toString().trim();
  if (!name) return res.status(400).json({ Status: false, Error: "Category name required" });

  const sql = "INSERT INTO category (name) VALUES (?)";
  con.query(sql, [name], (err, result) => {
    if (err) {
      console.error('add_category query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error" });
    }
    return res.json({ Status: true });
  });
});

// Image upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'Public/Images');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// Add employee
router.post("/add_employee", upload.single('image'), (req, res) => {
  const { name, email, password, salary, address, category_id } = req.body;
  if (!name || !email || !password) return res.status(400).json({ Status: false, Error: "Name, email and password required" });

  bcrypt.hash(password.toString(), 10, (err, hash) => {
    if (err) {
      console.error('hash error:', err);
      return res.status(500).json({ Status: false, Error: "Hashing Error" });
    }
    const sql = "INSERT INTO employee (name, email, password, salary, address, category_id, image) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const values = [name, email, hash, salary || null, address || null, category_id || null, req.file ? req.file.filename : null];

    con.query(sql, values, (err2, result) => {
      if (err2) {
        console.error('add_employee query error:', err2);
        return res.status(500).json({ Status: false, Error: "Query Error" });
      }
      return res.json({ Status: true });
    });
  });
});

// Get all employees
router.get('/employee', (req, res) => {
  const sql = "SELECT * FROM employee";
  con.query(sql, (err, result) => {
    if (err) {
      console.error('employee query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error" });
    }
    return res.json({ Status: true, Result: result });
  });
});

// Get employee by ID
router.get('/employee/:id', (req, res) => {
  const id = req.params.id;
  const sql = "SELECT * FROM employee WHERE id = ?";
  con.query(sql, [id], (err, result) => {
    if (err) {
      console.error('get employee by id error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error" });
    }
    return res.json({ Status: true, Result: result });
  });
});

// Edit employee
router.put('/edit_employee/:id', (req, res) => {
  const id = req.params.id;
  const sql = "UPDATE employee SET name = ?, email = ?, salary = ?, address = ?, category_id = ? WHERE id = ?";
  const values = [req.body.name, req.body.email, req.body.salary, req.body.address, req.body.category_id];
  con.query(sql, [...values, id], (err, result) => {
    if (err) {
      console.error('edit_employee query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error: " + err });
    }
    return res.json({ Status: true, Result: result });
  });
});

// Delete employee
router.delete('/delete_employee/:id', (req, res) => {
  const id = req.params.id;
  const sql = "DELETE FROM employee WHERE id = ?";
  con.query(sql, [id], (err, result) => {
    if (err) {
      console.error('delete_employee query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error: " + err });
    }
     if (result.affectedRows === 0) {
      return res.json({ Status: false, Error: "Employee not found" });
    }
    return res.json({ Status: true, Message: "Employee deleted successfully"});
  });
});

router.get('/admin_count', (req, res) => {
    const sql = "SELECT COUNT(*) AS admin FROM admin";
    con.query(sql, (err, result) => {
    if (err) {
      console.error('admin count query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error" });
    }
    return res.json({ Status: true, Result: result });
    })
})

router.get('/employee_count', (req, res) => {
    const sql = "SELECT COUNT(*) AS employee FROM employee";
    con.query(sql, (err, result) => {
    if (err) {
      console.error('employee count query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error" });
    }
    return res.json({ Status: true, Result: result });
    })
})

router.get('/salary_count', (req, res) => {
  const sql = "SELECT IFNULL(SUM(salary),0) AS salary FROM employee";
  con.query(sql, (err, result) => {
    if (err) {
      console.error('salary count query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error:" + err.message });
    }
    return res.json({ Status: true, Result: result });
  });
});
 
router.get('/admin_records', (req, res) => {
  const sql = "SELECT * FROM admin"
  con.query(sql, (err, result) => {
    if (err) {
      console.error('admin records query error:', err);
      return res.status(500).json({ Status: false, Error: "Query Error:" + err.message });
    }
    return res.json({ Status: true, Result: result });
  });
});

router.get('/logout',(req, res) => {
  res.clearCookie('token')
  return res.json({Status: true})
})

export { router as adminRouter };