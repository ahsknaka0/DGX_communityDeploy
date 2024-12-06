import React, { useState, useContext } from 'react';
import { ToastContainer, toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import "react-toastify/dist/ReactToastify.css";
import ApiContext from '../context/ApiContext.jsx';
import { images } from '../constant/index.js'; // Adjust the path relative to the component file
import LoadPage from './LoadPage.jsx';

const ForgotPassword = () => {
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate();
  const { fetchData } = useContext(ApiContext);
  const [email, setEmail] = useState('');
  const handleSubmit = async (e) => {
    e.preventDefault()
    const endpoint = "user/passwordrecovery";
    const method = "POST"
    const body = {
      "email": email,
    }

    // console.log(body)
    setLoading(true)

    try {

      const data = await fetchData(endpoint, method, body);

      if (!data.success) {
        setLoading(false)
        toast.error("Error in Password Reset try again", {
          position: "top-center",
          autoClose: 3000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "light",
        });
        return
      } else if (data.success) {
        setLoading(false)
        toast.success("Password Reset mail has sent to your mail ", {
          position: "top-center",
          autoClose: 3000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "light",
        });
        setTimeout(() => {
          navigate('/SignInn');
        }, 3500);
      }
    } catch (error) {
      setLoading(false)
      toast.error(`Something went wrong try again`, {
        position: "top-center",
        autoClose: 3000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light",
      });
      return
    }
  }


  return (
    loading ? < LoadPage /> : <div className="min-h-screen flex flex-col lg:flex-row items-center justify-center relative">
      <ToastContainer />
      {/* Left side with form */}
      <div className="w-full lg:w-1/2 min-h-screen py-20 px-8 lg:rounded-r-full bg-DGXblue flex items-center justify-center">
        <div className="w-full max-w-md">
          <div className="rounded-xl mx-auto shadow-lg overflow-hidden bg-DGXwhite shadow-DGXgreen p-8">
            <h1 className="text-DGXblue text-3xl mb-10 font-bold text-center">Forgot Password</h1>

            <form onSubmit={handleSubmit} className="w-full">
              <div className="mb-4">
                <input
                  type="text"
                  placeholder="Email or Username"
                  className="border border-DGXgreen py-2 px-3 w-full rounded"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div>
                <button type="submit" className="w-full text-lg bg-DGXgreen hover:bg-DGXblue rounded-full py-3 text-center font-medium text-DGXwhite">
                  Verify Email
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
      {/* Right side with background image */}
      <div className="lg:w-3/4  hidden lg:flex justify-center items-center lg:pl-1">
        <img
          src={images.secure}
          alt="Background"
          className="max-w-full max-h-full object-contain"
        />
      </div>
    </div>
  );
};

export default ForgotPassword;
