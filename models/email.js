const nodemailer= require("nodemailer");
require('dotenv').config();
const sendemail = async (Option) => {
    const transporter = nodemailer.createTransport({   // transporter for sending email
        host: process.env.email_host,
        port: process.env.email_port,
        auth: {
            user:process.env.email_user,
            pass: process.env.email_pass
        }
    });
    //email options
    const mailOptions = {
        from: "smtp@mailchk.com",
        to: Option.email,
        subject: Option.subject,
        text: Option.message
    };
    await transporter.sendMail(mailOptions);  //transport mail by sendmail() fnc
};

module.exports = sendemail;



  