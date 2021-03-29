require('dotenv').config();

const cors=require('cors');


const express=require('express');
const app=express();
app.use(cors());
const PORT=process.env.PORT || 3000;

const base64=require('base-64');

const bcrypt=require('bcrypt');
const SR=process.env.SALT_ROUNDS;

const hashPass=async(password)=>{
    try{
        const salt=await bcrypt.genSalt(+SR);
        const hash=await bcrypt.hash(password,salt);
        return hash;
    }
    catch(err)
    {
        throw err;
    }

}

const nodeMailer=require('nodemailer');
const transporter=nodeMailer.createTransport({
    host:process.env.HOST,
    auth:{
        user:process.env.USER,
        pass:process.env.PASS
    },
    tls:{
        rejectUnauthorized:false
    }

})

app.use(express.json());
app.use(express.urlencoded({extended:true}))



const {checkEmail,addUser,login,checkUsername} =require('./db.js');


app.post('/register',async(req,res)=>{
    try{
        let email=req.body.email;
        let check=await checkEmail(email);
        if(check)
        {
            console.log("exists")
            res.json({
                message:"User Already Exists!"
            })
        }
        else
        {
           const encrypted_mail=base64.encode(email);
           const href=`${process.env.FRONT_URL}/register/${encrypted_mail}`;
           let html=`<a href=${href}>Click Here</a> to verify your E-Mail`;
           
           let info =await transporter.sendMail({
               from:"Sahil Alam",
               to:email,
               subject:"Verify your mail!",
               text:"Please Click on the below link to verify your mail.",
               html:`${html}`
           });

           res.status(200).json({
               message:"Mail Sent !!! Please Check your mail",
               info
           })

        }
    }
    catch(err)
    {
        console.log(err);
        res.status(400).json({
            message:err.message
        });
    } 
});


app.post('/register/:encrypted_mail',async(req,res)=>{
    try
    {
        let encrypted_mail=req.params.encrypted_mail;
        const email=base64.decode(encrypted_mail);
        const username=req.body.username;
        const password=req.body.password;
        if(username.length && password.length)
        {
            const hash= await hashPass(password);
            const data=await addUser(username,hash,email);
            const check_username=await checkUsername(username);
            if(check_username)
            {
                res.json(
                    {
                        message:"Username already taken! Try again with different username.."
                    }
                )
            }
            else
            {
                res.status(201).json({
                    message:"User Created!",
                    info:data
                });
            }
        }
        else
        {
            res.status(400).json({
                message:"Either Username or password is empty!"
            });
        }
            
        

    }
    catch(err)
    {
        console.log(err);
        res.status(404).json({
            message:err.message
        });
    }
})
app.post('/login',async(req,res)=>{
    let username=req.body.username;
    let password=req.body.password;
    try{
        const data=await login(username);
        if(data)
        {
            const result=await bcrypt.compare(password,data.password);
            if(result)
            {
                res.status(200).json({
                    data
                })
            }
            else
            {
                res.status(404).json({
                    message:"Invalid Password"
                })   
            }

        }
        else
        {
            res.status(404).json({
                message:"User Not Found!"
            });
        }
    }
    catch(err)
    {
        console.log(err);
        res.status(400).json({
            message:err.message
        });
    }
}) 


app.listen(PORT,()=>{
    console.log("SERVER STARTED",PORT)
})
