require("dotenv").config();
var crypto = require('crypto');
var uuid = require('uuid');
var express = require('express');
var mysql = require('mysql');
var bodyParser = require('body-parser');

//Connect to mysql

var con = mysql.createConnection({
    host:process.env.DB_HOST,
    user:process.env.DB_USER,
    password:process.env.DB_PASS,
    database:process.env.MYSQL_DB
});

//PASSWORD
var getRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex')
    .slice(0,length);
};

var sha512 = function(password,salt){
    var hash = crypto.createHmac('sha512',salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };

};

function saltHashPassword(userPassword){
    var salt = getRandomString(16);
    var passwordData = sha512(userPassword,salt);
    return passwordData;
};

function chechHashPassword(userPassword,salt){
    var passwordData = sha512(userPassword,salt);
    return passwordData;
}

var app=express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));


app.post('/register/',(req,res,next)=>{
    var post_data = req.body;
    var uid = uuid.v4();
    var plaint_password = post_data.password;
    var hash_data = saltHashPassword(plaint_password);
    var password = hash_data.passwordHash;
    var salt = hash_data.salt;
    var username = post_data.username;
    var email = post_data.email;
    var dateofbirth = post_data.dateofbirth;
    
    con.query('select * from user_account where email=?',[email],function(err,result,fields){   
        con.on('error',function(err){
            console.log("[MYSQL ERROR]", err)
        });
        if(result && result.length)
        res.json('User already exist');
    else{
        con.query('insert into user_account (`email`, `username`, `password`, `salt`, `date_of_birth`, `date_join`) VALUES (?,?,?,?,?,NOW())',[email,username,password,salt,dateofbirth],function(err,result,fields){
            con.on('error',function(err){
                console.log("[MYSQL ERROR]", err);
                res.json('Register Error');
            });   
            res.json('Register  successful');
        });
        }
    });
    
});

app.post('/login/',(req,res,next)=>{
    var post_data = req.body;
    var user_password = post_data.password;
    var email = post_data.email;
    con.query('select * from USER_ACCOUNT where email=?',[email],function(err,result,fields){
    con.on('error',function(err){
        console.log("[MYSQL ERROR]", err)
    });
    if(result && result.length){
    var salt = result[0].salt;
    var encrypted_password = result[0].encrypted_password;
    var hashed_password = chechHashPassword(user_password,salt).passwordHash; 
    if(encrypted_password == hashed_password)
    res.end(JSON.stringify(result[0]));
        else
        res.end(JSON.stringify('Wrong Password'));

    }
else{

            res.json('Regitser Error');
        } 
  

    });
});

app.listen(3000,() =>{
    console.log("API RUNNING");
});
