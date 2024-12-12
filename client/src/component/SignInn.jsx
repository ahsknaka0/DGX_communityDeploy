import React, { useState, useContext } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { images } from '../constant/index.js';
import { FaEye } from "react-icons/fa";
import { FaEyeLowVision } from "react-icons/fa6";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Cookies from 'js-cookie';
import ApiContext from '../context/ApiContext.jsx';
import LoadPage from './LoadPage.jsx';
import { validateRequired } from '../utils/formValidation.js';

const SignIn = () => {
  const { fetchData, logIn } = useContext(ApiContext);
  const [loading, setLoading] = useState(false);
  const [usernameFocus, setUsernameFocus] = useState(false);
  const [passwordFocus, setPasswordFocus] = useState(false);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [userID, setUserID] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleFocus = (event) => {
    const { id } = event.target;
    if (id === 'username') setUsernameFocus(true);
    if (id === 'password') setPasswordFocus(true);
  };

  const handleBlur = (event) => {
    const { id, value } = event.target;
    if (id === 'username' && !value) setUsernameFocus(false);
    if (id === 'password' && !value) setPasswordFocus(false);
  };

  const handleInputChange = (event) => {
    const { id, value } = event.target;
    if (id === 'username') setUserID(value);
    if (id === 'password') setPassword(value);
  };

  const validateForm = (elements) => {
    const inputAndSelectElements = elements.filter(element =>
      element.tagName === 'INPUT' || element.tagName === 'SELECT'
    );
    inputAndSelectElements.forEach((formElemment) => {
      // console.log(formElemment.id);
      validateRequired(formElemment.id);
    })
    return document.querySelector('.is-invalid') === null;
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    const formElements = Array.from(event.target.elements);
    const isValid = validateForm(formElements);
    if (!isValid) {
      return;
    }
    const endpoint = "user/login";
    const method = "POST";
    const body = {
      "email": userID,
      "password": password,
    };
    setLoading(true);
    try {
      const data = await fetchData(endpoint, method, body);
      if (!data.success) {
        setLoading(false);
        toast.error(`Error in Login: ${data.message}`, {
          position: "top-center",
          autoClose: 1000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          theme: "light",
        });
      } else {
        logIn(data.data.authtoken)
        // Cookies.set('userToken', JSON.stringify(data.data.authtoken), { expires: 7 });
        setLoading(false);
        if (data.data.flag === 0) {
          toast.success("Welcome for first time. Please change your password", {
            position: "top-center",
            autoClose: 1000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            theme: "light",
          });
          setTimeout(() => {
            navigate('/ChangePassword');
          }, 1500);
        } else if (data.data.isAdmin) {
          toast.success("Welcome to the admin panel", {
            position: "top-center",
            autoClose: 3000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            theme: "light",
          });
          setTimeout(() => {
            navigate('/AdminDashboard'); // Change this to your actual admin route
          }, 3500);
        } else {
          toast.success("Welcome to DGX Community", {
            position: "top-center",
            autoClose: 3000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            theme: "light",
          });
          console.log(data)
          setTimeout(() => {
            navigate('/');
          }, 3500);
        }
      }
    } catch (error) {
      setLoading(false);
      toast.error(`Something went wrong. Try again`, {
        position: "top-center",
        autoClose: 3000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        theme: "light",
      });
    }
  };

  const togglePasswordVisibility = () => {
    setPasswordVisible(!passwordVisible);
  };

  return (
    loading ? < LoadPage /> :
      <div className="min-h-screen flex flex-col lg:flex-row items-center justify-center bg-gray-100">
        <ToastContainer />
        {/* Background image for large screens */}
        <div className="lg:w-3/4 xl:w-4/5 2xl:w- hidden lg:flex justify-start items-center p-4 lg:pl-40">
          <img
            src={images.secure}
            alt="Background"
            className="max-w-full max-h-full object-cover"
          />
        </div>
        {/* Sign in form container */}


        <div className="w-full xl:w-6/12 2xl:w-6/12 lg:w-6/12 lg:rounded-l-full h-screen flex justify-center items-center bg-DGXblue">
          <div className="w-full max-w-sm lg:max-w-md p-6 bg-DGXwhite rounded-lg shadow-lg border border-DGXgreen">
            <div className='text-center text-3xl mb-4 text-DGXgreen font-bold'>Sign In</div>
            <div className="flex justify-center items-center mb-4">
              <img src={images.robot} alt="Logo" className="logo-image " />
            </div>
            <h1 className="text-center text-xl mb-4">Welcome to <span className="text-DGXgreen font-bold">DGX Community</span></h1>

            <form className="space-y-4" onSubmit={handleSubmit}>
              <div className="relative">
                <label
                  htmlFor="username"
                  className={`absolute opacity-60 left-4 transition-all duration-300 ${usernameFocus ? 'top-0 text-xs text-DGXgreen' : 'top-1/2 transform -translate-y-1/2'}`}
                >
                  Username or email address
                </label>
                <input
                  id="username"
                  type="text"
                  className="w-full px-4 py-2 border border-DGXgreen rounded-md focus:outline-none focus:border-DGXgreen"
                  onFocus={handleFocus}
                  onBlur={handleBlur}
                  onChange={handleInputChange}
                  value={userID}
                />
                <div id="usernameVerify" className="invalid-feedback"></div>
              </div>
              <div className="relative">
                <label
                  htmlFor="password"
                  className={`absolute opacity-60 left-4 transition-all duration-300 ${passwordFocus ? 'top-0 text-xs text-DGXgreen' : 'top-1/2 transform -translate-y-1/2'}`}
                >
                  Password
                </label>
                <input
                  id="password"
                  type={passwordVisible ? "text" : "password"}
                  className="w-full px-4 py-2 border border-DGXgreen rounded-md focus:outline-none focus:border-DGXgreen"
                  onFocus={handleFocus}
                  onBlur={handleBlur}
                  onChange={handleInputChange}
                  value={password}
                />
                <div id="passwordVerify" className="invalid-feedback"></div>
                <button
                  type="button"
                  onClick={togglePasswordVisibility}
                  className="absolute inset-y-0 right-0 flex items-center px-4 text-DGXgreen focus:outline-none"
                >
                  {passwordVisible ? <FaEye />
                    : <FaEyeLowVision />}
                </button>
              </div>
              <div className="text-right mb-4">
                <Link to="/ForgotPassword" className="text-DGXgreen font-bold">Forgot Password?</Link>
              </div>
              <button type="submit" className="w-full py-2 bg-DGXgreen text-DGXwhite rounded-md text-lg focus:outline-none hover:bg-DGXblue">Sign in</button>
            </form>
            <div className="text-center mt-4 py-4">
              Signing in for the first time? <Link to="/VerifyEmail" className="text-DGXgreen font-semibold">Verify here</Link>
            </div>
          </div>
        </div>
      </div>
  );
};

export default SignIn;
