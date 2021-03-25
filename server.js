require('dotenv').config();


const express=require('express');
const app=express();
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



const {checkEmail,addUser,login} =require('./db.js');


app.post('/register',async(req,res)=>{
    try{
        let email=req.body.email;
        let check=await checkEmail(email);
        if(check)
        {
            console.log("exists")
            res.json({
                error:"User Already Exists!"
            })
        }
        else
        {
           const encrypted_mail=base64.encode(email);
           const href=`"${process.env.FRONT_URL}/login/${encrypted_mail}"`;
           let html=`<a href="${href}">Click Here</a>`;
           
           let info =await transporter.sendMail({
               from:"Sahil Alam",
               to:email,
               subject:"Verify your mail!",
               text:"Please Click on the below link to verify your mail.",
               html:`${html}`
           });

           res.status(200).json({
               message:"Mail Sent !!!",
               info
           })

        }
    }
    catch(err)
    {
        console.log(err);
        res.status(400).json({
            error:err.message
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
        const hash= await hashPass(password);
        const data=await addUser(username,hash,email);
        res.status(201).json(data);

    }
    catch(err)
    {
        console.log(err);
        res.status(404).json(
            {
                error:err.message
            }
        );
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
        res.status(400).json(
            {
                error:err.message
            }
        );
    }
}) 


app.listen(PORT,()=>{
    console.log("SERVER STARTED",PORT)
})
