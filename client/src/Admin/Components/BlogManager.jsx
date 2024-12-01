import React, { useState } from 'react';
import BlogForm from './BlogComponents/BlogForm';
import BlogTable from './BlogComponents/BlogTable';

const initialBlogs = [
  {
    id: 1,
    title: "Making wearable medical devices more patient-friendly",
    image: "https://techcrunch.com/wp-content/uploads/2022/05/found-2022-featured.jpg?w=430&h=230&crop=1",
    category: "Health",
    author: "Darrell Etherington",
    // authorPic: "author1.jpg",
    published_date: "October 4, 2023",
    reading_time: "8 minutes",
    content: "Welcome back to Found...",
    tags: ["Biotech", "Health"],
  },
  {
    "id": 4,
    "title": "Rainforest raises $8.5M to help software companies embed financial services, payments",
    "image": "https://techcrunch.com/wp-content/uploads/2015/02/shutterstock_128451140.jpg?w=430&h=230&crop=1",
    "category": "Fintech",
    "author": "Mary Ann Azevedo",
    // "authorPic": "author1.jpg",
    "published_date": "2023-10-01",
    "reading_time": "5 minutes",
    "content": "In November 2019, Andreessen Horowitz General Partner Angela Strange famously declared that, “Every company will be a fintech company.” Specifically, Strange projected that — in the not-too-d...",
    "tags": ["Fintech", "Writing"]
  },
  {
    "id": 5,
    "title": "Pow.bio says biomanufacturing is broken and its continuous fermentation tech will fix it",
    "image": "https://techcrunch.com/wp-content/uploads/2023/10/Pow-Lab2.jpg?w=430&h=230&crop=1",
    "category": "Startups",
    "author": "Christine Hall",
    // "authorPic": "author1.jpg",
    "published_date": "2023-10-01",
    "reading_time": "5 minutes",
    "content": "Pow.bio intends to bring down the costs associated with biomanufacturing by reimagining of fermentation facility operations.",
    "tags": ["Startups", "Writing"]
  },
  {
    "id": 6,
    "title": "Recapitalization, $60M Series D support growth of e-commerce financier Clearco",
    "image": "https://techcrunch.com/wp-content/uploads/2022/07/GettyImages-1314165902.jpg?w=430&h=230&crop=1",
    "category": "Fintech",
    "author": "Christine Hall",
    // "authorPic": "author1.jpg",
    "published_date": "2023-10-01",
    "reading_time": "5 minutes",
    "content": "Today is news marks a turnaround for a company that is had its share of ups and downs over the past year.",
    "tags": ["Blogging", "Writing"]
  },
  {
    "id": 7,
    "title": "Rabbit is building an AI model that understands how software works",
    "image": "https://techcrunch.com/wp-content/uploads/2023/05/GettyImages-1325174870.jpg?w=430&h=230&crop=1",
    "category": "AI",
    "author": "Kyle Wiggers",
    // "authorPic": "author1.jpg",
    "published_date": "2023-10-01",
    "reading_time": "5 minutes",
    "content": "What if you could interact with any piece of software using natural language? Imagine typing in a prompt and having AI translate the instructions into machine-comprehendable commands, executing tas...",
    "tags": ["AI", "Writing"]
  }
];

const BlogManager = () => {
  const [isTableView, setIsTableView] = useState(true);
  const [blogs, setBlogs] = useState(initialBlogs);
  const toggleView = () => setIsTableView(!isTableView);

  return (
    <div className="container mx-auto p-4">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-xl font-bold">{isTableView ? "Blog Posts" : "Add New Blog Post"}</h1>
        <button onClick={toggleView} className="bg-DGXgreen text-white py-2 px-4 rounded-lg">{isTableView ? "Add New Blog" : "View Blogs"}</button>
      </div>
      {isTableView ? ( <BlogTable blogs={blogs} />) : ( <BlogForm blogs={blogs} setBlogs={setBlogs} setIsTableView={setIsTableView} /> )}
    </div>
  );
};

export default BlogManager;
