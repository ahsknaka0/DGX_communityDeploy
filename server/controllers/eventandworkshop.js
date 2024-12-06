import { body, validationResult } from "express-validator";
import { connectToDatabase, closeConnection } from "../database/mySql.js";
import dotenv from "dotenv";
import { queryAsync, logError, logInfo, logWarning } from "../helper/index.js";

dotenv.config();

export const addEvent = async (req, res) => {
  let success = false;

  // Extract user ID from the authenticated request (assuming it's added by authentication middleware)
  const userId = req.user.id;

  // Validate request data
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const warningMessage = "Data is not in the right format";
    logWarning(warningMessage); // Log the warning
    res
      .status(400)
      .json({ success, data: errors.array(), message: warningMessage });
    return;
  }

  try {
    // Destructure form data
    // console.log("hi",req.body)
    // let data = JSON.parse(req.body)
    let {
      title,
      start,
      end,
      category,
      companyCategory,
      venue,
      host,
      registerLink,
      poster,
      description,
    } = req.body;

    // console.log(title,start,end,category,companyCategory,venue,host,registerLink,description)
    // Set defaults if necessary
    title = title ?? null;
    start = start ?? null;
    end = end ?? null;
    category = category ?? null;
    companyCategory = companyCategory ?? null;
    venue = venue ?? null;
    host = host ?? null;
    registerLink = registerLink ?? null;
    description = description ?? null;

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
        const query = `SELECT UserID, Name FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;

        const rows = await queryAsync(conn, query, [userId]);

        if (rows.length > 0) {
          console.log("yaha hu bss ek kadam door bss thoda or");
          // Insert event into the Events table
          const insertEventQuery = `
            INSERT INTO Community_Event 
            (EventTitle, StartDate, EndDate, EventType, Category, Venue, Host, RegistrationLink, EventImage, EventDescription, AuthAdd, AddOnDt, delStatus) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE(), 0);
          `;

          console.log(category);

          // Insert event details
          const insertEvent = await queryAsync(conn, insertEventQuery, [
            title,
            start,
            end,
            category,
            companyCategory,
            venue,
            host,
            registerLink,
            poster, // You may need to handle file upload separately, storing the file URL or path
            description,
            rows[0].Name, // AuthAdd (user who added the event)
          ]);

          console.log("last hai", insertEvent);
          // Fetch last inserted event ID
          const lastInsertedIdQuery = `SELECT TOP 1 EventID FROM Community_Event WHERE ISNULL(delStatus, 0) = 0 ORDER BY EventID DESC;`;
          const lastInsertedId = await queryAsync(conn, lastInsertedIdQuery);

          success = true;
          closeConnection();

          const infoMessage = "Event added successfully!";
          logInfo(infoMessage);

          // Send success response
          res.status(200).json({
            success,
            data: { eventId: lastInsertedId[0].EventID },
            message: infoMessage,
          });
        } else {
          closeConnection();
          const warningMessage = "User not found, please login first.";
          logWarning(warningMessage);
          res
            .status(400)
            .json({ success: false, data: {}, message: warningMessage });
        }
      } catch (queryErr) {
        closeConnection();
        logError(queryErr);
        res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong, please try again",
        });
      }
    });
  } catch (error) {
    logError(error);
    res.status(500).json({
      success: false,
      data: {},
      message: "Something went wrong, please try again",
    });
  }
};

export const getEvent = async (req, res) => {
  let success = false;
  try {
    connectToDatabase(async (err, conn) => {
      if (err) {
        const errorMessage = "Failed to connect to database";
        logError(err);
        res
          .status(500)
          .json({ success: false, data: err, message: errorMessage });
        return;
      }
      try {
        const EventWorkshopGetQuery = `SELECT EventID, EventTitle, AuthAdd as UserName, StartDate, EndDate, EventType, Venue, RegistrationLink, EventDescription, Category, AddOnDt as timestamp, EventImage FROM Community_Event WHERE ISNULL(delStatus, 0) = 0  ORDER BY AddOnDt DESC`;
        const EventWorkshopGet = await queryAsync(conn, EventWorkshopGetQuery);
        success = true;
        closeConnection();
        const infoMessage = "Event and Workshop Got Successfully";
        logInfo(infoMessage);
        res
          .status(200)
          .json({ success, data: EventWorkshopGet, message: infoMessage });
      } catch (queryErr) {
        logError(queryErr);
        closeConnection();
        res.status(500).json({
          success: false,
          data: queryErr,
          message: "Something went wrong please try again",
        });
      }
    });
  } catch (error) {
    logError(error);
    res.status(500).json({
      success: false,
      data: {},
      message: "Something went wrong please try again",
    });
  }
};
