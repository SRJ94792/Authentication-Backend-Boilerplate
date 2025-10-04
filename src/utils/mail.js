import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendEmail = async (options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager",
      link: "https://taskmanager.com",
    },
  });
  const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent);
  const emailHtml = mailGenerator.generate(options.mailgenContent);
  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  });

  const mail = {
    from: "mail.taskmanager@tm.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error(
      "Email service failed siliently. Make sure you have provided you Mailtrap credentials in the .env file!",
    );
    console.error("Error:", error);
  }
  // const mail = async () => {
  //   const info = await transporter.sendMail({
  //     from: '"Maddison Foo Koch" <maddison53@ethereal.email>',
  //     to: "bar@example.com, baz@example.com",
  //     subject: "Hello ✔",
  //     text: "Hello world?", // plain‑text body
  //     html: "<b>Hello world?</b>", // HTML body
  //   });
  //   console.log("Message sent:", info.messageId);
  // };
};

const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcom to our App! we're happy to have you on board.",
      action: {
        instructions:
          "To verify your email please click on the following button",
        button: {
          color: "#1aaaaa",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help! ",
    },
  };
};

const forgotPasswordMailgenContent = (username, passwordRestUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcom to our App! we're happy to have you on board.",
      action: {
        instructions: "To forgot password press the following button",
        button: {
          color: "#1aaaaa",
          text: "Verify your email",
          link: passwordRestUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help! ",
    },
  };
};

export {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
};
