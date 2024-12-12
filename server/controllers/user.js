import { validationResult } from "express-validator";
import bcrypt from "bcryptjs";
import { connectToDatabase, closeConnection } from "../database/mySql.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import {
  generatePassword,
  referCodeGenerator,
  encrypt,
} from "../utility/index.js";
import {
  queryAsync,
  mailSender,
  logError,
  logInfo,
  logWarning,
} from "../helper/index.js";

dotenv.config();
const JWT_SECRET = process.env.JWTSECRET;
const SIGNATURE = process.env.SIGNATURE;

//Route 0) To verify if User already exists

export const databaseUserVerification = async (req, res) => {
  let success = false;

  // Validate request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

    logWarning(warningMessage); // Log the warning
    res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
    return;
  }

  try {
    const userEmail = req.body.email;
    // Connect to the database
    connectToDatabase(async (err, conn) => {
      if (err) {
        const errorMessage = "Failed to connect to database";
        logError(err); // Log the error
        res
          .status(500)
          .json({ success: false, data: err, message: errorMessage });
        return;
      }

      try {
        // Query the database for the user
        //const query = `SELECT * FROM Community_User WHERE EmailId=?`;
        const query =
          "SELECT Name,EmailId,MobileNumber,FlagPasswordChange, Category FROM Community_User WHERE isnull(delStatus,0) = 0 and EmailId=?";
        const rows = await queryAsync(conn, query, [userEmail]);

        if (rows.length > 0) {
          // User found
          if (rows[0].FlagPasswordChange == 0) {
            try {
              // Generate a new password and current date/time
              const password = await generatePassword(10);
              // const date = await getCurrentDateTime();

              // Generate a secure password hash
              const salt = await bcrypt.genSalt(10);
              const secPass = await bcrypt.hash(password, salt);

              let referCode;
              while (!success) {
                // Generate a unique referral code
                referCode = await referCodeGenerator(
                  rows[0].Name,
                  rows[0].EmailId,
                  rows[0].MobileNumber
                );
                // console.log(referCode)

                // Check if the referral code already exists
                const checkQuery = `SELECT COUNT(UserID) AS userReferCount FROM Community_User WHERE isnull(delStatus,0) = 0 and  ReferalNumber = ?`;
                const checkRows = await queryAsync(conn, checkQuery, [
                  referCode,
                ]);

                // console.log(checkRows[0].Column0)

                if (checkRows[0].userReferCount === 0) {
                  const referCount = rows[0].Category === "F" ? 10 : 2;
                  // Update user record with new password, date, and referral code
                  const updateQuery = `UPDATE Community_User SET Password = ?, AuthLstEdit = ?, editOnDt = GETDATE(), ReferalNumber = ?, ReferalNumberCount = ? WHERE isnull(delStatus,0)=0 and  EmailId = ?`;
                  await queryAsync(conn, updateQuery, [
                    secPass,
                    rows[0].Name,
                    referCode,
                    referCount,
                    userEmail,
                  ]);

                  // Close connection after query execution
                  closeConnection();
                  const message = `Hello,

                    Welcome to the DGX Community! Below are your login credentials:

                    Username: ${userEmail}
                    Password: ${password}

                    Please keep your credentials secure and do not share them with anyone. If you encounter any issues, feel free to contact our support team.

                    Best regards,  
                    The DGX Community Team`;

                    const htmlContent = `<!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            .container {
                                font-family: Arial, sans-serif;
                                color: #333;
                                line-height: 1.6;
                                padding: 20px;
                            }
                            .credentials {
                                margin: 20px 0;
                                font-size: 16px;
                            }
                            .footer {
                                font-size: 12px;
                                color: #777;
                                margin-top: 20px;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <p>Hello,</p>
                            <p>Welcome to the DGX Community! Below are your login credentials:</p>
                            <div class="credentials">
                                <p><b>Username:</b> ${userEmail}</p>
                                <p><b>Password:</b> ${password}</p>
                            </div>
                            <p>Please keep your credentials secure and do not share them with anyone. If you encounter any issues, feel free to contact our support team.</p>
                            <p>Best regards,<br/>The DGX Community Team</p>
                            <div class="footer">
                                <p>This is an automated message. Please do not reply directly to this email.</p>
                            </div>
                        </div>
                    </body>
                    </html>`;
                    
                  const mailsent = await mailSender(
                    userEmail,
                    message,
                    htmlContent
                  );

                  // console.log(mailsent.success)
                  // Respond with success message
                  if (mailsent.success) {
                    success = true;
                    logInfo(`Mail sent successfully to ${userEmail}`); // Log the success
                    return res.status(200).json({
                      success: true,
                      data: { username: userEmail },
                      message: "Mail send successfully",
                    });
                  } else {
                    const errorMessage = "Mail isn't sent successfully";
                    logError(new Error(errorMessage)); // Log the error
                    return res.status(200).json({
                      success: false,
                      data: { username: userEmail },
                      message: errorMessage,
                    });
                  }
                }
              }
            } catch (error) {
              const errorMessage = "Error generating password";
              logError(error); // Log the error
              closeConnection();
              return res
                .status(500)
                .json({ success: false, data: error, message: errorMessage });
            }
          } else {
            // User's password change flag is not 0
            const warningMessage = "Credentials already generated, go to login";
            logWarning(warningMessage); // Log the warning
            closeConnection();
            return res
              .status(200)
              .json({ success: false, data: {}, message: warningMessage });
          }
        } else {
          // User not found
          const warningMessage = 
            "Access denied. You are not yet a part of this community. Please request a referral from an existing member to join.";

          logWarning(warningMessage); // Log the warning
          closeConnection();
          return res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }
      } catch (error) {
        const errorMessage = "Database query error";
        logError(error); // Log the error
        closeConnection();
        return res.status(500).json({
          success: false,
          data: {},
          message: "Something went wrong, please try again",
        });
      }
    });
  } catch (error) {
    const errorMessage = "Failed to connect to database";
    logError(error); // Log the error
    closeConnection();
    return res.status(500).json({
      success: false,
      data: {},
      message: "Something went wrong, please try again",
    });
  }
};

//Route 1) create a User using : POST '/api/auth/createuser'. Doesn't require Auth

export const registration = async (req, res) => {
  let success = false;

  // Validate request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

    logWarning(warningMessage); // Log the warning
    return res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
  }

  const {
    inviteCode,
    name,
    email,
    password,
    collegeName,
    phoneNumber,
    category,
    designation,
  } = req.body;
  const referalNumberCount = category === "F" ? 10 : 2;
  const FlagPasswordChange = 1;

  // const date = await getCurrentDateTime();

  try {
    // Connect to the SQL Server using the provided function
    connectToDatabase(async (err, conn) => {
      if (err) {
        logError(err); // Log the error
        return res.status(500).json({
          success: false,
          data: err,
          message: "Failed to connect to database",
        });
      }

      try {
        // Check if user already exists with the same email
        const existingUserQuerry = `SELECT COUNT(UserID) AS userEmailCount FROM Community_User WHERE ISNULL(delStatus,0)=0 AND EmailId = ?`;
        const existingUsers = await queryAsync(conn, existingUserQuerry, [
          email,
        ]);

        if (existingUsers[0].userEmailCount > 0) {
          // User with this email already exists
          const warningMessage =  "An account with this email address already exists. Please log in or use a different email to register.";

          logWarning(warningMessage);
          closeConnection();
          return res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }

        // If user does not exist, hash the password
        const salt = await bcrypt.genSalt(10);
        const secPass = await bcrypt.hash(password, salt);

        const checkCreditQuerry = `SELECT ReferalNumberCount, UserID FROM Community_User WHERE ISNULL(delStatus,0)=0 AND ReferalNumber = ?`;
        const checkCredit = await queryAsync(conn, checkCreditQuerry, [
          inviteCode,
        ]);
        // console.log(checkCredit[0].ReferalNumberCount)

        if (checkCredit[0].ReferalNumberCount > 0) {
          const referedBy = checkCredit[0].UserID;
          const RNC = checkCredit[0].ReferalNumberCount - 1;
          // console.log(RNC)
          const referCreditDeductionQuerry = `UPDATE Community_User SET ReferalNumberCount = ${RNC} WHERE ISNULL(delStatus,0)=0 AND ReferalNumber = ?`;
          const referCreditDeduction = await queryAsync(
            conn,
            referCreditDeductionQuerry,
            [inviteCode]
          );
          // console.log(referCreditDeduction)

          let referCode;
          do {
            // Generate a unique referral code
            referCode = await referCodeGenerator(name, email, phoneNumber);
            // console.log(referCode);

            // Check if the referral code already exists
            const checkQuery = `SELECT COUNT(UserID) AS userReferCount FROM Community_User WHERE isnull(delStatus,0) = 0 AND  ReferalNumber = ?`;
            const checkRows = await queryAsync(conn, checkQuery, [referCode]);

            if (checkRows[0].userReferCount === 0) {
              // Insert new user into the database
              // console.log("hi")
              const insertQuerry = `INSERT INTO Community_User (Name, EmailId, CollegeName, MobileNumber, Category, Designation, ReferalNumberCount, ReferalNumber, Password, FlagPasswordChange, ReferedBy, AuthAdd, AddOnDt, delStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE(), ?)`;
              const insertResult = await queryAsync(conn, insertQuerry, [
                name,
                email,
                collegeName,
                phoneNumber,
                category,
                designation,
                referalNumberCount,
                referCode,
                secPass,
                FlagPasswordChange,
                referedBy,
                name,
                0,
              ]);

              success = true;

              const infoMessage = "User created successfully";
              logInfo(`infoMessage with ${email}`);
              // Close connection after query execution
              closeConnection();

              // Respond with success message
              return res.status(200).json({
                success: success,
                data: {
                  user: {
                    EmailID: email,
                  },
                },
                message: infoMessage,
              });
            }
          } while (!success);
        } else {
          const warningMessage =  "This referral code has no remaining credits. Please try again with a different referral code.";

          logWarning(warningMessage);
          closeConnection();
          return res
            .status(200)
            .json({ success: success, data: {}, message: warningMessage });
        }
      } catch (error) {
        logError(error); // Log the error
        closeConnection();
        return res.status(500).json({
          success: false,
          data: error,
          message: "Error generating password or referral code",
        });
      }
    });
  } catch (error) {
    logError(error); // Log the error
    closeConnection();
    return res.status(500).json({
      success: false,
      data: {},
      message: "Internal server error. Please try again",
    });
  }
};

//Route 2) Authenticate a user using POST '/api/auth/login' - no login required

export const login = async (req, res) => {
  let success = false;
  // console.log(req.body)
  // if there are errors, return bad request and the errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

    logWarning(warningMessage); // Log the warning
    return res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
  }

  const { email, password } = req.body;
  // console.log(req.body)

  try {
    connectToDatabase(async (err, conn) => {
      if (err) {
        logError(err); // Log the error
        return res.status(500).json({
          success: false,
          data: err,
          message: "Failed to connect to database",
        });
      }

      try {
        const query =
          "SELECT EmailId, Password, FlagPasswordChange, isAdmin FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?";

        const result = await queryAsync(conn, query, [email]);

        if (result.length === 0) {
          const warningMessage = "Please try to login with correct credentials";
          logWarning(warningMessage);
          closeConnection();
          return res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }
        const passwordCompare = await bcrypt.compare(
          password,
          result[0].Password
        );
        if (!passwordCompare) {
          const warningMessage = "Please try to login with correct credentials";
          logWarning(warningMessage);
          closeConnection();
          return res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }

        const data = {
          user: {
            id: result[0].EmailId,
            isAdmin: result[0].isAdmin,
          },
        };
        const authtoken = jwt.sign(data, JWT_SECRET);
        success = true;
        const infoMessage = "You login successfully";
        logInfo(infoMessage);
        closeConnection();
        return res.status(200).json({
          success: true,
          data: {
            authtoken,
            flag: result[0].FlagPasswordChange,
            isAdmin: result[0].isAdmin,
          },
          message: infoMessage,
        });
      } catch (queryErr) {
        logError(queryErr);
        closeConnection();
        return res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong please try again",
        });
      }
    });
  } catch (error) {
    logError(error);
    closeConnection();
    return res.status(500).json({
      success: false,
      data: {},
      message: "Something went wrong please try again",
    });
  }
};

// export const login = async (req, res) => {
//   let success = false;
//   const errors = validationResult(req);
//   if (!errors.isEmpty()) {
//     const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

//     logWarning(warningMessage);
//     return res.status(400).json({ success, data: errors.array(), message: warningMessage });
//   }

//   const { email, password } = req.body;
//   console.log(req.body);

//   try {
//     connectToDatabase(async (err, conn) => {
//       if (err) {
//         logError(err);
//         return res.status(500).json({ success: false, data: err, message: "Failed to connect to database" });
//       }

//       try {
//         const query = "SELECT EmailId, Password, FlagPasswordChange, IsAdmin FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?";
//         const result = await queryAsync(conn, query, [email]);

//         if (result.length === 0) {
//           const warningMessage = "Please try to login with correct credentials";
//           logWarning(warningMessage);
//           closeConnection();
//           return res.status(200).json({ success: false, data: {}, message: warningMessage });
//         }

//         const passwordCompare = await bcrypt.compare(password, result[0].Password);
//         if (!passwordCompare) {
//           const warningMessage = "Please try to login with correct credentials";
//           logWarning(warningMessage);
//           closeConnection();
//           return res.status(200).json({ success: false, data: {}, message: warningMessage });
//         }

//         const data = {
//           user: {
//             id: result[0].EmailId,
//             isAdmin: result[0].IsAdmin === 1  // Check if the user is an admin
//           }
//         };
//         const authtoken = jwt.sign(data, JWT_SECRET);
//         success = true;
//         const infoMessage = result[0].IsAdmin === 1 ? "Admin login successful" : "User login successful";
//         console.log("i am admin");
//         logInfo(infoMessage);
//         closeConnection();

//         return res.status(200).json({
//           success: true,
//           data: { authtoken, flag: result[0].FlagPasswordChange, isAdmin: result[0].IsAdmin === 1 },
//           message: infoMessage
//         });

//       } catch (queryErr) {
//         logError(queryErr);
//         closeConnection();
//         return res.status(500).json({ success: false, data: queryErr, message: 'Something went wrong please try again' });
//       }
//     });
//   } catch (error) {
//     logError(error);
//     closeConnection();
//     return res.status(500).json({ success: false, data: {}, message: 'Something went wrong please try again' });
//   }
// };

//Route 3) To change the password of the user

export const changePassword = async (req, res) => {
  let success = false;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

    logWarning(warningMessage); // Log the warning
    return res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
  }

  try {
    const userId = req.user.id;
    // console.log(req.body)
    // console.log(userId);
    const { currentPassword, newPassword } = req.body;

    connectToDatabase(async (err, conn) => {
      if (err) {
        logError(err);
        res.status(500).json({
          success: false,
          data: err,
          message: "Failed to connect to database",
        });
        return;
      }

      try {
        const query = `SELECT Name, Password FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;
        const rows = await queryAsync(conn, query, [userId]);

        if (rows.length > 0) {
          try {
            const passwordCompare = await bcrypt.compare(
              currentPassword,
              rows[0].Password
            );
            if (!passwordCompare) {
              const warningMessage =
                "Please try to login with correct credentials";
              logWarning(warningMessage);
              closeConnection();
              return res
                .status(200)
                .json({ success: false, data: {}, message: warningMessage });
            }

            const salt = await bcrypt.genSalt(10);
            const secPass = await bcrypt.hash(newPassword, salt);
            // console.log(secPass)
            const updateQuery = `UPDATE Community_User SET Password = ?, FlagPasswordChange = 1, AuthLstEdit = ?, editOnDt = GETDATE() WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;
            const updatePassword = await queryAsync(conn, updateQuery, [
              secPass,
              rows[0].Name,
              userId,
            ]);
            closeConnection();
            success = true;
            const infoMessage = "Password Change Successfully ";
            logInfo(infoMessage);
            res
              .status(200)
              .json({ success: true, data: {}, message: infoMessage });
          } catch (queryErr) {
            closeConnection();
            logError(queryErr);
            return res.status(401).json({
              success: false,
              data: queryErr,
              message: "Something went wrong please try again",
            });
          }
        } else {
          const warningMessage = "User not found";
          logWarning(warningMessage);
          closeConnection();
          res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }
      } catch (queryErr) {
        logError(queryErr);
        closeConnection();
        res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong please try again",
        });
      } finally {
        closeConnection();
      }
    });
  } catch (error) {
    logError(error);
    closeConnection();
    return res.status(500).json({
      success: false,
      data: {},
      message: "Something went wrong please try again",
    });
  }
};

//Route 4) Get loggedin user detail using POST "/getuser"  - Login required

export const getuser = async (req, res) => {
  let success = false;

  try {
    const userId = req.user.id;
    // console.log(userId);

    connectToDatabase(async (err, conn) => {
      if (err) {
        logError(err);
        res.status(500).json({
          success: false,
          data: err,
          message: "Failed to connect to database",
        });
        return;
      }

      try {
        const query = `SELECT UserID, Name, EmailId, CollegeName, MobileNumber, Category, Designation,isAdmin, ReferalNumberCount, ReferalNumber, ReferedBy,  FlagPasswordChange, AddOnDt FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;
        const rows = await queryAsync(conn, query, [userId]);

        if (rows.length > 0) {
          success = true;
          closeConnection();
          const infoMessage = "User data";
          logInfo(infoMessage);
          res
            .status(200)
            .json({ success, data: rows[0], message: infoMessage });
          return;
        } else {
          closeConnection();
          const warningMessage = "User not found";
          logWarning(warningMessage);
          res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
          return;
        }
      } catch (queryErr) {
        closeConnection();
        logError(queryErr);
        res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong please try again",
        });
        return;
      }
    });
  } catch (error) {
    logError(queryErr);
    return res.status(500).json({
      success: false,
      data: {},
      message: "Something went wrong please try again",
    });
  }
};

export const getAllUser = async (req, res) => {
  let success = false;

  // Get the HTTP method (GET for fetching users, DELETE for deleting a user)
  const method = req.method;

  // DELETE method to handle user deletion
  if (method === "DELETE") {
    const { userId } = req.body;

    if (!userId) {
      return res
        .status(400)
        .json({ success: false, message: "User ID is required for deletion" });
    }

    try {
      connectToDatabase(async (err, conn) => {
        if (err) {
          logError(err);
          return res
            .status(500)
            .json({ success: false, message: "Failed to connect to database" });
        }

        try {
          const deleteQuery = `DELETE FROM Community_User WHERE UserID = ?`;
          const result = await queryAsync(conn, deleteQuery, [userId]);

          closeConnection();

          if (result.affectedRows > 0) {
            const successMessage = "User deleted successfully";
            logInfo(successMessage);
            return res
              .status(200)
              .json({ success: true, message: successMessage });
          } else {
            const notFoundMessage = "User not found";
            logWarning(notFoundMessage);
            return res
              .status(404)
              .json({ success: false, message: notFoundMessage });
          }
        } catch (deleteErr) {
          closeConnection();
          logError(deleteErr);
          return res
            .status(500)
            .json({ success: false, message: "Error deleting user" });
        }
      });
    } catch (error) {
      logError(error);
      return res.status(500).json({ success: false, message: "Server error" });
    }

    // Return after handling DELETE method to prevent further execution
    return;
  }

  // GET method to fetch all users
  if (method === "GET") {
    try {
      connectToDatabase(async (err, conn) => {
        if (err) {
          logError(err);
          return res.status(500).json({
            success: false,
            data: err,
            message: "Failed to connect to database",
          });
        }

        try {
          const query = `SELECT UserID, Name, EmailId, CollegeName, MobileNumber, Category, Designation, ReferalNumberCount, ReferalNumber, ReferedBy, FlagPasswordChange, AddOnDt FROM Community_User`;
          const rows = await queryAsync(conn, query);

          closeConnection();

          if (rows.length > 0) {
            success = true;
            const infoMessage = "User data retrieved";
            logInfo(infoMessage);
            return res
              .status(200)
              .json({ success, data: rows, message: infoMessage });
          } else {
            const warningMessage = "No users found";
            logWarning(warningMessage);
            return res
              .status(404)
              .json({ success: false, data: {}, message: warningMessage });
          }
        } catch (queryErr) {
          closeConnection();
          logError(queryErr);
          return res.status(500).json({
            success: false,
            message: "Something went wrong with the query",
          });
        }
      });
    } catch (error) {
      logError(error);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    return res
      .status(405)
      .json({ success: false, message: "Method not allowed" });
  }
};

//Route 5) Sending Invite to mail "/sendinvite" - Login required

export const sendInvite = async (req, res) => {
  let success = false;

  // Validate request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

    logWarning(warningMessage); // Log the warning
    return res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
  }

  try {
    const userId = req.user.id;

    connectToDatabase(async (err, conn) => {
      if (err) {
        logError(err);
        res.status(500).json({
          success: false,
          data: err,
          message: "Failed to connect to database",
        });
        return;
      }

      try {
        const baseLink = process.env.RegistrationLink;
        const query = `SELECT ReferalNumber FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;
        const rows = await queryAsync(conn, query, [userId]);

        if (rows.length > 0) {
          const email = await encrypt(req.body.email);
          const refercode = await encrypt(rows[0].ReferalNumber);

          const registrationLink = `${baseLink}Register/?email=${email}&refercode=${refercode}`;

          const message = `Welcome to the DGX Community!

          Welcome to the DGX Community! We’re thrilled to have you join us. To complete your registration, please click the link below:

          Complete your registration: ${registrationLink}

          If you did not sign up for the DGX Community, you can safely disregard this email.

          Thank you,  
          The DGX Community Team`;

          const htmlContent = `<!DOCTYPE html>
          <html>
          <head>
              <style>
                  .button {
                      display: inline-block;
                      padding: 10px 20px;
                      background-color: #28a745;
                      color: white;
                      text-decoration: none;
                      border-radius: 5px;
                      font-size: 16px;
                  }
                  .footer {
                      font-size: 12px;
                      color: #777;
                      margin-top: 20px;
                  }
              </style>
          </head>
          <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
              <p>Welcome to the DGX Community!,</p>
              <p>Welcome to the DGX Community! We’re thrilled to have you join us. To complete your registration, please click the button below:</p>
              <p><a href="${registrationLink}" class="button">Complete Your Registration</a></p>
              <p>If you did not sign up for the DGX Community, you can safely disregard this email.</p>
              <p>Thank you,<br>The DGX Community Team</p>
              <div class="footer">
                  <p>This is an automated message. Please do not reply directly to this email.</p>
              </div>
          </body>
          </html>`;


          closeConnection();
          const mailsent = await mailSender(
            req.body.email,
            message,
            htmlContent
          );
          if (mailsent.success) {
            success = true;
            const infoMessage =
              "Invite Link send successfuly to ${req.body.email}";
            logInfo(infoMessage); // Log the success
            return res.status(200).json({
              success: true,
              data: { registrationLink },
              message: "Mail send successfully",
            });
          } else {
            const errorMessage = "Mail isn't sent successfully";
            logError(new Error(errorMessage)); // Log the error
            return res.status(200).json({
              success: false,
              data: { username: userEmail },
              message: errorMessage,
            });
          }
        } else {
          closeConnection();
          const warningMessage = "User not found";
          logWarning(warningMessage);
          res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }
      } catch (queryErr) {
        logError(queryErr);
        res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong please try again",
        });
      }

      // res.json({ success: true, data: { BaseLink }, message:  })
    });
  } catch (queryErr) {
    logError(queryErr);
    res.status(500).json({
      success: false,
      data: queryErr,
      message: "Something went wrong please try again",
    });
  }
};

//Route 6) Sending password recovery mail "/passwordrecovery"

export const passwordRecovery = async (req, res) => {
  let success = false;

  // Validate request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

    logWarning(warningMessage); // Log the warning
    return res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
  }

  try {
    connectToDatabase(async (err, conn) => {
      if (err) {
        logError(err);
        res.status(500).json({
          success: false,
          data: err,
          message: "Failed to connect to database",
        });
        return;
      }

      try {
        const baseLink = process.env.RegistrationLink;
        const query = `SELECT EmailId, Name FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;
        const rows = await queryAsync(conn, query, [req.body.email]);

        if (rows.length > 0) {
          const email = await encrypt(req.body.email);
          const signature = await encrypt(SIGNATURE);

          try {
            const updateQuery = `UPDATE Community_User SET FlagPasswordChange = 2, AuthLstEdit= ?, editOnDt = GETDATE() WHERE isnull(delStatus,0) = 0 AND EmailId= ?`;
            const update = await queryAsync(conn, updateQuery, [
              "Server",
              req.body.email,
            ]);

            const registrationLink = `${baseLink}ResetPassword/?email=${email}&signature=${signature}`;

            const message = `Hello,

              We received a request to reset the password for your DGX Community account. Please click the link below to create a new password:

              Reset your password: ${registrationLink}

              If you did not request a password reset, please disregard this email. Your account remains secure.

              For questions, contact us at support@yourdomain.com.

              Thank you,
              The DGX Community Team`;


            const htmlContent = `<!DOCTYPE html>
              <html>
              <head>
                  <style>
                      .button {
                          display: inline-block;
                          padding: 10px 15px;
                          background-color: #0056b3;
                          color: white;
                          text-decoration: none;
                          border-radius: 5px;
                          font-size: 16px;
                      }
                      .footer {
                          font-size: 12px;
                          color: #777;
                          margin-top: 20px;
                      }
                  </style>
              </head>
              <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
                  <p>Hello,</p>
                  <p>We received a request to reset the password for your DGX Community account. Please click the button below to create a new password:</p>
                  <p><a href="${registrationLink}" class="button">Reset Your Password</a></p>
                  <p>If you did not request a password reset, you can safely ignore this message. Your account remains secure.</p>
                  <p>For questions, contact us at <a href="mailto:support@yourdomain.com">support@yourdomain.com</a>.</p>
                  <p>Thank you,<br>The DGX Community Team</p>
                  <div class="footer">
                      <p>This is an automated message. Please do not reply directly to this email.</p>
                  </div>
              </body>
              </html>`;


            closeConnection();
            const mailsent = await mailSender(
              req.body.email,
              message,
              htmlContent
            );
            if (mailsent.success) {
              success = true;
              const infoMessage =
                "Password Reset Link send successfuly to ${req.body.email}";
              logInfo(infoMessage); // Log the success
              return res.status(200).json({
                success: true,
                data: { registrationLink },
                message: "Mail send successfully",
              });
            } else {
              const errorMessage = "Mail isn't sent successfully";
              logError(new Error(errorMessage)); // Log the error
              return res.status(200).json({
                success: false,
                data: { username: req.body.email },
                message: errorMessage,
              });
            }
          } catch (Err) {
            closeConnection();
            logError(Err);
            res.status(500).json({
              success: false,
              data: Err,
              message: "Something went wrong please try again",
            });
          }
        } else {
          closeConnection();
          const warningMessage = "User not found";
          logWarning(warningMessage);
          res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }
      } catch (queryErr) {
        closeConnection();
        logError(queryErr);
        res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong please try again",
        });
      }
    });
  } catch (Err) {
    closeConnection();
    logError(Err);
    res.status(500).json({
      success: false,
      data: Err,
      message: "Something went wrong please try again",
    });
  }
};

//Route 7) Reset Password from password recovery mail "/resetpassword"
export const resetPassword = async (req, res) => {
  let success = false;

  // Validate request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "The data format is incorrect. Please ensure it meets the required format and try again.";

    logWarning(warningMessage); // Log the warning
    return res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
  }

  try {
    connectToDatabase(async (err, conn) => {
      if (err) {
        logError(err);
        res.status(500).json({
          success: false,
          data: err,
          message: "Failed to connect to database",
        });
        return;
      }

      try {
        const { email, signature, password } = req.body;
        const query = `SELECT Name, FlagPasswordChange FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;
        const rows = await queryAsync(conn, query, [email]);

        if (rows.length > 0 && rows[0].FlagPasswordChange == 2) {
          try {
            if (signature == SIGNATURE) {
              const salt = await bcrypt.genSalt(10);
              const secPass = await bcrypt.hash(password, salt);
              const updateQuery = `UPDATE Community_User SET Password = ?, AuthLstEdit= ?, editOnDt = GETDATE(), FlagPasswordChange = 1 WHERE isnull(delStatus,0) = 0 AND EmailId= ?`;
              const update = await queryAsync(conn, updateQuery, [
                secPass,
                rows[0].Name,
                email,
              ]);
              closeConnection();
              success = true;
              const infoMessage = "Password Reset successfully";
              logInfo(infoMessage); // Log the success
              return res
                .status(200)
                .json({ success: true, data: {}, message: infoMessage });
            } else {
              closeConnection();
              const warningMessage = "This link is not valid";
              logWarning(warningMessage);
              return res
                .status(200)
                .json({ success: false, data: {}, message: warningMessage });
            }
          } catch (Err) {
            closeConnection();
            logError(Err);
            res.status(500).json({
              success: false,
              data: Err,
              message: "Something went wrong please try again",
            });
          }
        } else {
          closeConnection();
          const warningMessage = "invalid link";
          logWarning(warningMessage);
          res
            .status(200)
            .json({ success: false, data: {}, message: warningMessage });
        }
      } catch (queryErr) {
        closeConnection();
        logError(queryErr);
        res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong please try again",
        });
      }
    });
  } catch (Err) {
    closeConnection();
    logError(Err);
    res.status(500).json({
      success: false,
      data: Err,
      message: "Something went wrong please try again",
    });
  }
};
