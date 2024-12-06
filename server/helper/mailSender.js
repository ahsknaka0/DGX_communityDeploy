import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();
const pass = process.env.GMAIL_PASSWORD_KEY;

export async function mailSender(receiver, message, htmlContent = "thank You") {
  var transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "666.akanksha@gmail.com",
      pass: pass,
    },
  });

  var mailOptions = {
    from: "666.akanksha@gmail.com",
    to: receiver,
    subject: "Yours DGX Community",
    text: message,
    html: htmlContent,
  };

  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        reject({ success: false, error: error.message });
      } else {
        // console.log('Email sent: ' + info.response);
        resolve({ success: true, response: info.response });
      }
    });
  });
}
