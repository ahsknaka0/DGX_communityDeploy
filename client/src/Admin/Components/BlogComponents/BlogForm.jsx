import React, { useState } from 'react';
import ReactQuill from 'react-quill';
import 'react-quill/dist/quill.snow.css';

const BlogForm = () => {
  const [title, setTitle] = useState('');
  const [author, setAuthor] = useState('');
  const [publishedDate, setPublishedDate] = useState('');
  const [content, setContent] = useState('');
  const [image, setImage] = useState(null);




 

  return (
    <form onSubmit={handleSubmit} className=" mx-auto mt-4 bg-white p-6 rounded shadow border-2">
      <div className="mb-4">
        <label className="block text-sm font-bold mb-2" htmlFor="title">Blog Title</label>
        <input
          type="text"
          id="title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="border rounded w-full py-2 px-3 text-gray-700 focus:outline-none focus:ring focus:ring-DGXblack"
          required
        />
      </div>
      
      <div className="mb-4">
        <label className="block text-sm font-bold mb-2" htmlFor="author">Author</label>
        <input
          type="text"
          id="author"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          className="border rounded w-full py-2 px-3 text-gray-700 focus:outline-none focus:ring focus:ring-DGXblack"
          required
        />
      </div>
      
      <div className="mb-4">
        <label className="block text-sm font-bold mb-2" htmlFor="publishedDate">Published Date</label>
        <input
          type="date"
          id="publishedDate"
          value={publishedDate}
          onChange={(e) => setPublishedDate(e.target.value)}
          className="border rounded w-full py-2 px-3 text-gray-700 focus:outline-none focus:ring focus:ring-DGXblack"
          required
        />
      </div>
      
      <div className="mb-4">
        <label className="block text-sm font-bold mb-2" htmlFor="content">Blog Content</label>
        <div className="border rounded w-full py-2 px-3 text-gray-700 focus:outline-none focus:ring focus:ring-DGXblack">
        <ReactQuill
            
            style={{ height: '200%', width: '100%  ' }}
            modules={{
              toolbar: [
                ['bold', 'italic', 'underline'],
                [{ list: 'ordered' }, { list: 'bullet' }],
                ['link', 'image'],
                ['clean'],
              ],
            }}
          />
        </div>
      </div>
      
      <div className="mb-4">
        <label className="block text-sm font-bold mb-2" htmlFor="image">Upload Image</label>
        <input
          type="file"
          id="image"
          accept="image/*"
          onChange={(e) => setImage(e.target.files[0])}
          className="border rounded w-full py-2 px-3 text-gray-700 focus:outline-none focus:ring focus:ring-DGXblack"
        />
      </div>
      
      <button
        type="submit"
        className="w-full bg-DGXblue text-white py-2 rounded hover:bg-DGXblack-dark focus:outline-none focus:ring focus:ring-DGXblack"
      >
        Submit
      </button>
    </form>
  );
};

export default BlogForm;
