import express from "express";
import { fetchUser } from '../middleware/fetchUser.js';


import { blogpost, getBlog } from "../controllers/blog.js";

const router = express.Router();

router.post('/blogpost', fetchUser, blogpost)
router.post('/getBlog', getBlog)


export default router;