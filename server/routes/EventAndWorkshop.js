import express from "express";
// import { body } from 'express-validator';
import { fetchUser } from '../middleware/fetchUser.js'; // Optional, if you need user authentication
import { addEvent, getEvent } from "../controllers/eventandworkshop.js"; // Import your addEvent controller

const router = express.Router();

router.post('/addEvent', fetchUser, addEvent); 
router.get('/getEvent', getEvent); 

export default router; 