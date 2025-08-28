import express from 'express';
import bodyParser from 'body-parser';
import PG from 'pg';
import bcrypt from "bcrypt"
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from "dotenv"
import session from 'express-session';
import ejs from "ejs"
import nodemailer from "nodemailer"
import { v4 as uuidv4}  from "uuid"


dotenv.config();

const app = express();
const PORT = 3000;

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly:true,
        secure:process.env.NODE_ENV === "production",
        sameSite:"strict",
        maxAge: 24 * 60 * 60 * 1000
    }
}))

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login')
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user || !req.session.user.is_admin) {
        return res.redirect('/login')
    }
    next()
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());


const saltRounds = 10

const db = new PG.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
})

db.connect()

const transporter = nodemailer.createTransport({
    service:"gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.APP_PASSWORD
    },
})

app.get('/', (req,res) => {
   res.render("login.ejs", {
        error: null
    }) 
})


app.get('/login', (req, res) => {
    res.render("login.ejs", {
        error: null
    })
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.log(err);
            return res.send("Error logging out");
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});


app.get("/register", (req, res) => {
    res.render("register.ejs", {
        message: null
    })
})

app.get('/report', requireLogin, (req, res) => {
    res.render("report.ejs", {
        complaint: null
    })
});

app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM problems ORDER BY id ASC");
        res.render("admin.ejs", { problems: result.rows, success: null, error: null });
    } catch (err) {
        console.log(err);
        res.render("admin.ejs", { problems: [], success: null, error: "Error fetching problems" });
    }
});


app.post('/admin/delete', requireAdmin, async (req, res) => {
    const ids = req.body.deleteIds; 

    if (!ids) {
        return res.render("admin.ejs", { problems: [], success: null, error: "No problems selected" });
    }

    try {
        await db.query("DELETE FROM problems WHERE id = ANY($1)", [Array.isArray(ids) ? ids : [ids]]);
        const result = await db.query("SELECT * FROM problems ORDER BY id ASC");
        res.render("admin.ejs", { problems: result.rows, success: "Deleted successfully!", error: null });
    } catch (err) {
        console.log(err);
        const result = await db.query("SELECT * FROM problems ORDER BY id ASC");
        res.render("admin.ejs", { problems: result.rows, success: null, error: "Error deleting problems" });
    }
});



app.post("/register", async (req, res) => {
    try {
        const email = req.body.email
        const mobile = req.body.mobileNumber
        const password = req.body.password
        const rePassword = req.body.rePassword

        if (!email.endsWith("@gmail.com")) {
            return res.render("register.ejs", {
                message: "Email must be a @gmail.com address"
            });
        }

        // Mobile number validation
        if (!/^\d{10}$/.test(mobile)) {
            return res.render("register.ejs", {
                message: "Mobile number must be exactly 10 digits"
            });
        }

        // Password and confirm password check
        if (password !== rePassword) {
            return res.render("register.ejs", {
                message: "Passwords do not match"
            });
        }


        // Check if user already exists
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (result.rows.length > 0) {
            return res.render("register.ejs", { message: "Email already exists" });
        }

        const token = uuidv4()

        // Hash password
        bcrypt.hash(password, saltRounds, async (err, hash) => {
            try {
                if (err) {
                    console.error("Hashing error:", err);
                    return res.status(500).send("Error while registering");
                }

                await db.query(
                    "INSERT INTO users (email, mobile, password, is_admin, token) VALUES ($1, $2, $3, $4, $5)",
                    [email, mobile, hash, false, token]
                );

                const verifyLink = `${process.env.BASE_URL}/verify/${token}`;
                await transporter.sendMail({
                    from:"hostelgrevience@gmail.com",
                    to: email,
                    subject: "Verify your email",
                    text: `Click the link to verify your email: ${verifyLink}`
                })

                res.render("register.ejs", { message: "An email has sent to your inbox please verify it" });

            } catch (innerError) {
                console.error("Error inside bcrypt.hash:", innerError);
                res.status(500).send("Internal Server Error");
            }
        });

    } catch (error) {
        console.error("Register route error:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get('/verify/:token', async (req,res) => {
    const { token } = req.params

    try {
        const result = await db.query("SELECT * FROM users WHERE token = $1", [token]);

        if(result.rows.length === 0){
            return res.send("Invalid or expired link")
        }

        await db.query("UPDATE users SET verified = true, token = NULL WHERE token = $1", [token])
        res.send("Email verified successfully Please Login")
    } catch (error) {
        console.log(error)
    }
})


app.post("/login", async (req, res) => {
    try {
        const loginEmail = req.body.email
        const loginPassword = req.body.password

        const result = await db.query("SELECT * FROM users WHERE email = $1", [loginEmail]);

        if (result.rows.length === 0) {
            return res.render("login.ejs", {
                error: "No email exist with Entered Email"
            });
        }

        if(!result.rows[0].verified){
            return res.render("login.ejs", {
                error: 'Please verify your email first'
            })
        }

        const storedPassword = result.rows[0].password;

        bcrypt.compare(loginPassword, storedPassword, async function (err, match) {
            try {
                if (err) {
                    return res.send("Something went wrong");
                }

                

                if (match) {
                    req.session.user = {
                        id: result.rows[0].id,
                        email: result.rows[0].email,
                        is_admin: result.rows[0].is_admin
                    };

                    req.session.save(err => {
                        if (err) {
                            console.log(err);
                            return res.send("Session error");
                        } else {
                            if (req.session.user.is_admin) {
                                res.redirect('/admin');
                            } else {
                                res.redirect('/report');
                            }
                        }
                    });
                } else {
                    res.render("login.ejs", {
                        error: "Invalid Credentials"
                    });
                }
            } catch (innerError) {
                console.error("Error inside bcrypt.compare:", innerError);
                res.status(500).send("Internal Server Error");
            }
        });

    } catch (error) {
        console.error("Login route error:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.post('/report', async (req, res) => {
    const { name, applicationId, mobileNumber, hostel_block, Room_number, Type_of_problem, Report_your_problem } = req.body
    await db.query(`INSERT INTO problems (name, application_id, mobile_number, hostel_block, room_number, type_of_problem, problem_description) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [name, applicationId, mobileNumber, hostel_block, Room_number, Type_of_problem, Report_your_problem]
    )
    res.render("report.ejs", {
        complaint: "Complaint Submitted Successfully"
    })
})



app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
