// src/App.jsx
import { Routes, Route } from 'react-router-dom';
import Home from './container/Home.jsx';
import Navbar from './component/Navbar.jsx';
import VerifyEmail from './component/VerifyEmail.jsx';
import Register from './component/Register.jsx';
import SignInn from './component/SignInn';
import ForgotPassword from './component/ForgotPassword';
import ChangePassword from './component/ChangePassword.jsx';
import UserProfile from './component/UserProfile.jsx';
import Discussion from './container/Discussion.jsx';
import Blog from './container/Blog.jsx';
import ContactUs from './container/ContactUs.jsx';
import DiscussionModal from './component/DiscussionModal.jsx';
import Notfound from './component/Notfound.jsx';
import ResetPassword from './component/ResetPassword.jsx';
// import images from './constant/images.js';
import CommunityGuidelines from './component/CommunityGuidelines.jsx';
import Resources from './component/Resources.jsx';
import Footer from './component/Footer.jsx';
import Survey from './component/Survey.jsx';
import Quiz from './component/Quiz.jsx';
import EventWorkshopPage from './container/EventWorkshopPage.jsx';
// import MyStoryboard from './component/MyStoryboard.jsx';
// import LoadPage from './component/LoadPage.jsx';
import LoadPage from './component/LoadPage.jsx';
import Calendar from './component/Calendar.jsx';
import EventRegistrationPage from './component/EventRegistrationPage.jsx';
import GeneralUserCalendar from './component/GeneralUserCalendar.jsx';
import AdminDashboard from './Admin/AdminDashboard.jsx';
import HomeAfterLoginComponent from './component/HomeAfterLoginComponent.jsx';
import PostCode from './component/PostCode.jsx';








function App() {
  return (
    <>
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-grow">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route exact path="/VerifyEmail" element={<VerifyEmail />} />
            <Route exact path="/Register" element={<Register />} />
            <Route path="/SignInn" element={<SignInn />} />
            <Route path="/ForgotPassword" element={<ForgotPassword />} />
            <Route path="/ChangePassword" element={<ChangePassword />} />
            <Route path="/UserProfile" element={<UserProfile />} />
            <Route path='/Discussion' element={<Discussion />} />
            <Route path='/ContactUs' element={<ContactUs />} />
            <Route path='/Blog' element={<Blog />} />
            <Route path='/DiscussionModal' element={<DiscussionModal />} />
            <Route path='/ResetPassword' element={<ResetPassword />} />
            <Route path='/CommunityGuidelines' element={<CommunityGuidelines />} />
            <Route path='/Resources' element={<Resources />} />
            <Route path='/404' element={<Notfound />} />
            <Route path='/Quiz' element={<Quiz />} />
            <Route path='/Survey' element={<Survey />} />
            {/* <Route path='/MyStoryboard' element={<MyStoryboard />} /> */}
            <Route path='/EventWorkshopPage' element={<EventWorkshopPage />} />
            <Route path='/EventRegistrationPage' element={<EventRegistrationPage />} />
            <Route path='/HomeAfterLoginComponent' element={<HomeAfterLoginComponent />} />
            <Route path='/PostCode' element={<PostCode />} />
            


            {  /*-----------ADMIN----------- */}

            <Route path='/AdminDashboard' element={<AdminDashboard />} />
            {/* <Route path='/Admin/Sidebar' element={<Sidebar />} /> */}
            <Route path='/LoadPage' element={<LoadPage />} />
            <Route path='/Calendar' element={<Calendar />} />
            <Route path='/GeneralUserCalendar' element={<GeneralUserCalendar />} />
          </Routes>
        </div>
        <Footer />
      </div>
    </>
  );
}

export default App;
