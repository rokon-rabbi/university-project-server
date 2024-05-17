
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'rokon2514@student.nstu.edu.bd',
    pass: 'dzya lxxp qtvf ofry'// Use the App Password generated
  }
});

const sendResetEmail = (email, token) => {
  console.log(`Sending email to: ${email}, with token: ${token}`);
  const resetLink = `http://localhost:5173/reset-password?token=${token}`;
  const mailOptions = {
    from: 'your-email@gmail.com',
    to: email,
    subject: 'Password Reset',
    html: `<p>To reset your password, please click the link below:</p>
           <a href="${resetLink}">Reset Password</a>`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

module.exports = { sendResetEmail };
