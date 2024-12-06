import images from '../constant/images.js';

const Footer = () => {
  return (
    <>
      <footer className="footer bg-DGXblue text-DGXwhite text-justify">
        <div className="container mx-auto px-4 lg:px-8 py-4 flex flex-col lg:flex-row lg:items-start justify-around">
          <div className="flex flex-col items-center lg:items-start mb-4 lg:mb-0">
            <a href="/ContactUs" className="flex items-center mb-2 lg:mb-4 space-x-3 rtl:space-x-reverse">
              <img src={images.gilogowhite} className="h-10" alt="GiVenture Logo" />
            </a>
            <div className="text-center lg:text-left">
              <div className="text-sm tracking-wide mt-2 lg:mt-0">
                <p>Community Guideline | Manage My Privacy | Do Not Sell or Share Our Data | Legal | Accessibility | Corporate Policies | Product Security | Contact</p>
              </div>
              <div className="text-sm font-poppins tracking-wide mt-1">
                <p>Copyright © 2024 Global Infoventures Pvt. Ltd. All rights reserved.</p>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </>
  )
}

export default Footer