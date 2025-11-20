import mysql2 from 'mysql2'

const con = mysql2.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "employeeDb"
})
 
con.connect(function(err){
    if(err){
        console.log("connection error", err)
    } else{
        console.log("Connection")
    }
});
export default con;
