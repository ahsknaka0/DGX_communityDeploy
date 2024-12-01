import { body, validationResult } from 'express-validator';
import { connectToDatabase, closeConnection } from '../database/mySql.js';
import dotenv from 'dotenv'
import { queryAsync, mailSender, logError, logInfo, logWarning } from '../helper/index.js';

dotenv.config()


export const blogpost = async (req, res) => {
    let success = false;

    const userId = req.user.id;
    // console.log(userId)

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const warningMessage = "Data is not in the right format";
        logWarning(warningMessage); // Log the warning
        res.status(400).json({ success, data: errors.array(), message: warningMessage });
        return;
    }

    try {
        // console.log(req.body)
        let { title, author, content, image, publishedDate } = req.body;
        title = title ?? null
        content = content ?? null
        image = image ?? null
        author = author ?? null
        publishedDate = publishedDate ?? null

        // Connect to the database
        connectToDatabase(async (err, conn) => {
            if (err) {
                const errorMessage = "Failed to connect to database";
                logError(err); // Log the error
                res.status(500).json({ success: false, data: err, message: errorMessage });
                return;
            }

            try {
                const query = `SELECT UserID, Name FROM Community_User WHERE isnull(delStatus,0) = 0 AND EmailId = ?`;
                const rows = await queryAsync(conn, query, [userId]);
                // console.log(rows)

                if (rows.length > 0) {
                    const blogPostQuery = `
                    INSERT INTO Community_Blog 
                    (title, author, Content, image, publishedDate, AuthAdd, AddOnDt, delStatus) 
                    VALUES (?, ?, ?, ?, ?, ?, GETDATE(), 0); 
                    `;
                    const blogPost = await queryAsync(conn, blogPostQuery, [title, author, content, image, publishedDate, rows[0].Name, 0])
                    const lastInsertedIdQuerry = `select top 1 BlogID from Community_Blog where ISNULL(delStatus,0)=0 order by BlogID desc;`
                    const lastInsertedId = await queryAsync(conn, lastInsertedIdQuerry)
                    success = true;
                    closeConnection();
                    const infoMessage = "Blog Posted Successfully"
                    logInfo(infoMessage)
                    res.status(200).json({ success, data: { postId: lastInsertedId[0].BlogID }, message: infoMessage });
                    return
                } else {
                    closeConnection();
                    const warningMessage = "User not found login first"
                    logWarning(warningMessage)
                    res.status(200).json({ success: false, data: {}, message: warningMessage });
                    return
                }
            } catch (queryErr) {
                closeConnection();
                logError(queryErr)
                res.status(500).json({ success: false, data: queryErr, message: 'Something went wrong please try again' });
                return
            }
        });
    } catch (error) {
        logError(error)
        return res.status(500).json({ success: false, data: {}, message: 'Something went wrong please try again' });

    }
}

export const getBlog = async (req, res) => {
    let success = false;
    try {
        connectToDatabase(async (err, conn) => {
            if (err) {
                const errorMessage = "Failed to connect to database";
                logError(err);
                res.status(500).json({ success: false, data: err, message: errorMessage });
                return;
            }
            try {
                const BlogQuery = `SELECT BlogID, title, AuthAdd as UserName, author, content, publishedDate, AddOnDt as timestamp, image FROM Community_Blog WHERE ISNULL(delStatus, 0) = 0  ORDER BY AddOnDt DESC`;
                const BlogGet = await queryAsync(conn, BlogQuery);
                success = true;
                closeConnection();
                const infoMessage = "Blog Got Successfully";
                logInfo(infoMessage);
                res.status(200).json({ success, data: BlogGet, message: infoMessage });
            }
            catch (queryErr) {
                logError(queryErr);
                closeConnection();
                res.status(500).json({ success: false, data: queryErr, message: 'Something went wrong please try again' });
            }
        })
    }
    catch (error) {
        logError(error);
        res.status(500).json({ success: false, data: {}, message: 'Something went wrong please try again' });
    }
}