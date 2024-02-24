    const dotenv = require("dotenv").config();
    const {GoogleGenerativeAI} = require("@google/generative-ai");
    var crypto = require('crypto');
    var express = require('express');
    var uuid = require('uuid');
    var mysql = require('mysql');
    var bodyParser = require('body-parser');
    const { stringify } = require("querystring");

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

    //GEMINI API 
    const genAI = new GoogleGenerativeAI(process.env.API_KEY);
    async function generate(params) {
        var generated_text = [];
        const prompt = "Simplify the this text and limit the words below 1000: " + params;
        const model = await genAI.getGenerativeModel({ model: "gemini-pro" }); 
        const result = await model.generateContentStream([prompt]);
        for await(var chunk of result.stream){
        var chunkText = chunk.text();
        console.log(chunkText);
        generated_text.push(chunkText);
        }
        return generated_text.join('').trimStart();
    }
        



    //Commands
    app.post('/register/',(req,res,next)=>{
        var post_data = req.body;
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
            con.query('insert into user_account (`email`, `username`, `password`, `salt`, `date_of_birth`, `date_joined`) VALUES (?,?,?,?,?,NOW())',[email,username,password,salt,dateofbirth],function(err,result,fields){
                con.on('error',function(err){
                    console.log("[MYSQL ERROR]", err);
                    res.json('Register Error');
                });     
                res.json('Register  Successful');
            });
            }
        });
        
    });


    app.post('/login/',(req,res,next)=>{
        var post_data = req.body;
        var user_password = post_data.password;
        var email = post_data.email;
        con.query('select * from user_account where email=?',[email],function(err,result,fields){
        con.on('error',function(err){
            console.log("[MYSQL ERROR]", err)
        });
        if(result && result.length){
        var salt = result[0].salt;
        var encrypted_password = result[0].password;
        var hashed_password = chechHashPassword(user_password,salt).passwordHash; 
        if(encrypted_password == hashed_password)
        res.end(JSON.stringify(result[0]));
            else
            res.end(JSON.stringify('Wrong Passwordddddd'));

        }
    else{

                res.json('[Login Error]');
            } 
    

        });
    });


    app.post('/generate/', async(req,res,next)=>{
        var post_data = req.body;
        var input_text = post_data.input_text;
        var generated = await generate(input_text);
        res.send(generated);

    });

    app.post('/addcollection/',(req,res,next)=>{
        var post_data = req.body;
        var email = post_data.email;
        var title = post_data.title;
        var author = post_data.author;
        var type = post_data.type;
        var genre = post_data.genre;
    
    con.query('select * from user_collection where user_email=?',[email],function(err,result,fields){   
            con.on('error',function(err){
                console.log("[MYSQL ERROR]", err);
            });
            if(result && result.length){
            con.query('update `user_collection` set `num_of_titles` = `num_of_titles` + 1 where user_email=?',[email]);
                
            con.query('select collection_id from user_collection where user_email=?',[email],function(err,result,fields){
                var collection_id = result[0].collection_id;
                con.query('select * from collection_overview where title_name=?'[title],function(err,result){
                    if(result && result.length){
                        res.send("Title taken");
                    }
                    else{
                        con.query('insert into collection_overview (`collection_id`, `title_name`, `author`, `type`,`genre`, `last_updated`) VALUES (?,?,?,?,?,NOW())',[collection_id,title,author,type,genre]);
            res.send("Succesfully added with +1");
                    }
                })
            })
            }

        else{
        //  Creating new User Collection
            con.query('insert into user_collection (`user_email`,`num_of_titles`) VALUES (?,?,NOW())',[email,1]);
            //Creating new Collection_Overview
            con.query('select collection_id from user_collection where user_email=?',[email],function(err,result,fields){
            con.query('insert into collection_overview (`collection_id`, `title_name`, `author`, `type`,`genre`, `last_updated`) VALUES (?,?,?,?,?,NOW())',[result[0].collection_id,title,author,type,genre]);
            res.send("Succesfully added without +1");
            })
        }
        });


    });

    app.post('/getcollection/',(req,res)=>{
        var post_data = req.body;
        var email = post_data.email;

        con.query('select collection_id from user_collection where user_email=?',[email],function(err,result,fields) {
            
            con.query('select * from collection_overview where collection_id=?',[result[0].collection_id],function(err,result,fields) {
            
                res.send(JSON.stringify(result));
                console.log(result);
                
            });

        });
    })

    app.post('/getcollection_information/',(req,res)=>{
        var post_data = req.body;
        var title_name = post_data.title_name;

        con.query('select title_id from collection_overview where title_name=?',[title_name],function(err,result,fields) {
            
            con.query('select * from title_details where title_id=?',[result[0].title_id],function(err,result,fields) {
            
                res.send(JSON.stringify(result));
                console.log(result);
                
            });

        });
    })

    app.listen(3000,() =>{
        console.log("API RUNNING");
    }); 
