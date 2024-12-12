import React, { useState, useContext, useEffect } from 'react';
import { FaSearch, FaComment, FaWindowClose, FaTrophy } from 'react-icons/fa';
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import ApiContext from '../context/ApiContext.jsx';
import DiscussionModal from '../component/DiscussionModal';
import { compressImage } from '../utils/compressImage.js';
import { AiFillLike, AiOutlineLike, AiOutlineComment } from "react-icons/ai";
import { useCallback } from 'react';
import Skeleton from 'react-loading-skeleton'; // Import Skeleton
import 'react-loading-skeleton/dist/skeleton.css'; // Import Skeleton styles
import ReactQuill from "react-quill";
import "react-quill/dist/quill.snow.css";

const Discussion = () => {
  const { fetchData, userToken, user } = useContext(ApiContext);
  const [demoDiscussions, setDemoDiscussions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [isLoading, setIsLoading] = useState(true); // Loading state

  useEffect(() => {
    // Simulating data fetching
    const loadEvents = async () => {
      setIsLoading(true);
      // Simulate network delay
      await new Promise((resolve) => setTimeout(resolve, 2000));
      setIsLoading(false);
    };

    loadEvents();
  }, []);
  const [likeCount, setLikeCount] = useState(0);
  const [commentCount, setCommentCount] = useState(0);
  const [isNavOpen, setIsNavOpen] = useState(false);
  const [selectedSection, setSelectedSection] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [modalIsOpen, setModalIsOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [tags, setTags] = useState('');
  const [tagInput, setTagInput] = useState('');
  const [links, setLinks] = useState('');
  const [linkInput, setLinkInput] = useState('');
  const [selectedImage, setSelectedImage] = useState(null);
  const [discussions, setDiscussions] = useState([]);
  const [privacy, setPrivacy] = useState('private');
  const [selectedDiscussion, setSelectedDiscussion] = useState(null);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [communityHighlights, setCommunityHighlights] = useState([])
  const [topUsers, setTopUsers] = useState([])

  const getCommunityHighlights = (discussions) => {
    const sortedDiscussions = discussions.sort((a, b) => b.comment.length - a.comment.length);
    return sortedDiscussions.slice(0, 5);
  }

  const getTopUsersByDiscussions = (discussions) => {
    const userDiscussionCount = {};

    discussions.forEach(discussion => {
      const { UserID, UserName } = discussion;

      if (userDiscussionCount[UserID]) {
        userDiscussionCount[UserID].count++;
      } else {
        userDiscussionCount[UserID] = { userName: UserName, count: 1 };
      }
    });

    const usersArray = Object.keys(userDiscussionCount).map(UserID => ({
      userID: UserID,
      userName: userDiscussionCount[UserID].userName,
      count: userDiscussionCount[UserID].count
    }));

    return usersArray.sort((a, b) => b.count - a.count).slice(0, 5);
  };

  useEffect(() => {
    try {
      const fetchDiscussionData = (userEmail) => {
        try {
          const body = userEmail ? { user: userEmail } : { user: null };
          const endpoint = "discussion/getdiscussion";
          const method = "POST";
          const headers = {
            'Content-Type': 'application/json',
          };

          setLoading(true);

          console.log(endpoint, headers, body)
          fetchData(endpoint, method, body, headers)
            .then(result => {
              if (result && result.data) {
                return result.data;
              } else {
                // return
                throw new Error("Invalid data format");
              }
            })
            .then(data => {
              if (data && data.updatedDiscussions) {
                setDemoDiscussions(data.updatedDiscussions);
                const highlights = getCommunityHighlights(data.updatedDiscussions);
                setCommunityHighlights(highlights)
                const users = getTopUsersByDiscussions(data.updatedDiscussions);
                setTopUsers(users)
              } else {
                // return
                throw new Error("Missing updatedDiscussions in response data");
              }
              setLoading(false);
            })
            .catch(error => {
              setLoading(false);
              toast.error(`Something went wrong: ${error.message}`, {
                position: "top-center",
                autoClose: 3000,
                hideProgressBar: false,
                closeOnClick: true,
                pauseOnHover: true,
                draggable: true,
                progress: undefined,
                theme: "light",
              });
            });
        } catch (error) {
          console.log(error)
        }
      };
      if (userToken && user) {
        fetchDiscussionData(user.EmailId);
      } else {
        fetchDiscussionData(null);
      }
    } catch (error) {
      console.log(error)
    }
  }, [user, userToken, fetchData]);



  const searchDiscussion = useCallback(async (searchTerm, userId) => {
    try {
      const body = { searchTerm, userId }; // Match the backend expected structure
      const endpoint = "discussion/searchdiscussion";
      const method = "POST";
      const headers = {
        'Content-Type': 'application/json',
      };

      setLoading(true);
      const result = await fetchData(endpoint, method, body, headers);
      console.log("API Response:", result);
      if (result && result.data && result.data.updatedDiscussions) {
        setDemoDiscussions(result.data.updatedDiscussions);
      } else {
        toast.error("No discussions found.");
      }
      setLoading(false);
    } catch (error) {
      setLoading(false);
      toast.error(`Something went wrong: ${error.message}`);
    }
  }, [fetchData]);



  const handleAddLike = async (id, userLike) => {
    // console.log(id, userLike)
    if (userToken) {
      const endpoint = "discussion/discussionpost";
      const method = "POST";
      const headers = {
        'Content-Type': 'application/json',
        'auth-token': userToken
      };
      const like = userLike == 1 ? 0 : 1
      const body = {
        "reference": id,
        "likes": like
      };
      console.log(body)
      try {
        const data = await fetchData(endpoint, method, body, headers)
        if (!data.success) {
          // console.log(data)
          console.log("Error occured while liking the post")
        } else if (data.success) {
          // console.log(data);
          const updatedData = demoDiscussions.map((item) =>
            item.DiscussionID === id ? { ...item, userLike: like, likeCount: like === 1 ? item.likeCount + 1 : item.likeCount - 1 } : item
          );
          setDemoDiscussions(updatedData)
          console.log(updatedData)
          console.log(demoDiscussions)
        }
      } catch (error) {
        console.log(error);
      }
    }
  };

  const hotTopics = [
    { title: "NVIDIA Innovations", link: "#", description: "Discover the latest advancements from NVIDIA and how they are shaping the future of technology." },
    { title: "NVIDIA-H100: Performance Unleashed", link: "#", description: "Discuss the performance of the NVIDIA-H100 GPU. Share your experiences, benchmarks, and use cases to help others understand its capabilities and benefits." },
    { title: "NVIDIA Ecosystem", link: "#", description: "Engage with other community members to discuss how various NVIDIA tools and platforms integrate with each other. Share tips, tricks, and best practices for maximizing the NVIDIA ecosystem." },
    { title: "Success Stories with NVIDIA-H100", link: "#", description: "Exchange stories and insights about how the NVIDIA-H100 is being utilized in different industries. Discuss successful projects and explore innovative applications of this powerful GPU." },
    { title: "Future of GPU Technology", link: "#", description: "Speculate on the future of GPU technology and NVIDIA's role in it. What advancements do you anticipate, and how do you see them shaping the tech landscape?" }
  ];

  // const topUsers = [
  //   { name: "User 1", points: 1200 },
  //   { name: "User 2", points: 1100 },
  //   { name: "User 3", points: 1050 },
  //   { name: "User 4", points: 1020 },
  //   { name: "User 5", points: 980 }
  // ];

  const toggleNav = () => setIsNavOpen(!isNavOpen);
  const handleLike = () => setLikeCount(likeCount + 1);

  const handleComment = (discussion) => {
    setCommentCount(prevCount => prevCount + 1);
    openModal(discussion);
  };

  const openModal = (discussion) => {
    setSelectedDiscussion(discussion);
    setModalIsOpen(true);
  };

  const closeModal = () => {
    setModalIsOpen(false);
    setIsFormOpen(false);
  };

  const handleTagInputChange = (e) => setTagInput(e.target.value);

  const handleTagInputKeyPress = (e) => {
    if (e.key === 'Enter' && tagInput.trim() !== '') {
      e.preventDefault();
      setTags(tags + ',' + tagInput.trim());
      setTagInput('');
    }
  };

  const removeTag = (tagToRemove) => {
    const tagArray = tags.split(',');
    const filteredTags = tagArray.filter(tag => tag !== tagToRemove);
    const newTags = filteredTags.join(',');
    setTags(newTags);
  }
  const handleImageChange = async (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file) {
        const compressedFile = await compressImage(file);
        setSelectedImage(compressedFile);
      }
    }
  };

  const handleLinkInputChange = (e) => setLinkInput(e.target.value);

  const handleLinkInputKeyPress = (e) => {
    if (e.key === 'Enter' && linkInput.trim() !== '') {
      e.preventDefault();
      setLinks(links + ',' + linkInput.trim());
      setLinkInput('');
    }
  };

  const removeLink = (linkToRemove) => {
    const linkArray = links.split(',');
    const filteredLinks = linkArray.filter(link => link !== linkToRemove);
    const newLinks = filteredLinks.join(',');
    setLinks(newLinks);
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    const endpoint = "discussion/discussionpost";

    const method = "POST";
    const body = {
      title,
      content,
      tags: tags,
      url: links,
      image: selectedImage,
      visibility: privacy

    };
    const headers = {
      'Content-Type': 'application/json',
      'auth-token': userToken
    };
    setLoading(true);

    try {
      const data = await fetchData(endpoint, method, body, headers);
      if (!data.success) {
        setLoading(false);
        toast.error(`Error in posting discussion try again: ${data.message}`, {
          position: "top-center",
          autoClose: 3000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "light",
        });
      } else if (data.success) {
        console.log(data);
        setLoading(false);
        if (privacy == "private") {
          toast.success("Private Discussion Posted Successfully", {
            position: "center",
            autoClose: 3000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            progress: undefined,
            theme: "light",
          });
        } else {
          const newDiscussion = {
            DiscussionID: data.postID,
            Title: title,
            Content: content,
            Tag: tags,
            ResourceUrl: links,
            Image: selectedImage,
            Visibility: privacy,
            comment: []
          };
          setDemoDiscussions([newDiscussion, ...demoDiscussions]);
          toast.success("Disscussion Post Successfully", {
            position: "top-center",
            autoClose: 3000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            progress: undefined,
            theme: "light",
            style: {
              backgroundColor: 'green',
              color: 'white',
            }
          });
        }
      }
    } catch (error) {
      setLoading(false);
      console.log(error);

      toast.error(`On catching error: Something went wrong, try again`, {
        position: "top-center",
        autoClose: 3000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light",
      });
    }
    setTitle('');
    setContent('');
    setTags('');
    setLinks('');
    setSelectedImage(null);
    setTagInput('');
    setLinkInput('');
    setIsFormOpen(false);
  };

  console.log(demoDiscussions);
  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  const handleKeyDown = async (e) => {
    if (e.key === 'Enter') {
      e.preventDefault(); // Prevent default form submission
      await searchDiscussion(searchQuery); // Trigger the search
    }
  };

  return (
    <div>

      <ToastContainer style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }} />

      <header className="flex flex-wrap sm:justify-start sm:flex-nowrap w-full bg-DGXblue text-sm py-4">
        <nav className="max-w-[85rem] w-full mx-auto px-4 flex flex-wrap basis-full items-center justify-between " aria-label="Global">
          <div className="sm:order-4 flex items-center w-full sm:w-auto mt-0 sm:mt-0 sm:ml-4 ">
            {isLoading ? (
              <Skeleton
                height="2.16rem" // Adjusted to match the height of the input element
                width={250} // Adjusted to match the width of the input element
                className="w-full sm:w-1/2 bg-gray-500 rounded-lg mb-1"
              />
            ) : (
              <div className="relative w-full sm:w-64 mb-2">
                <input
                  type="text"
                  className="w-full py-2 pl-10 pr-4 bg-white border border-gray-200 rounded-lg shadow-sm text-gray-800 focus:border-DGXgreen focus:ring-DGXgreen"
                  placeholder="Search..."
                  value={searchQuery}
                  onChange={handleSearchChange} // Call this directly without the arrow function
                  onKeyDown={handleKeyDown}
                />
                <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                  <FaSearch className="text-gray-400" />
                </div>
              </div>
            )}
          </div>

          {/* <div className="sm:order-3 flex items-center gap-x-2">
            <button
              type="button"
              className="sm:hidden hs-collapse-toggle p-2.5 inline-flex justify-center items-center gap-x-2 rounded-lg border border-gray-200 bg-white text-gray-800 shadow-sm hover:bg-gray-50 disabled:opacity-50 disabled:pointer-events-none"
              aria-controls="navbar-alignment"
              aria-label="Toggle navigation"
              onClick={toggleNav}
            >
              <svg className={`${isNavOpen ? 'hidden' : 'block'} flex-shrink-0 size-4`} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="3" x2="21" y1="6" y2="6" />
                <line x1="3" x2="21" y1="12" y2="12" />
                <line x1="3" x2="21" y1="18" y2="18" />
              </svg>
              <svg className={`${isNavOpen ? 'block' : 'hidden'} flex-shrink-0 size-4`} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6 6 18" />
                <path d="m6 6 12 12" />
              </svg>
            </button>
          </div> */}
          <div id="navbar-alignment" className={`${isNavOpen ? 'block' : 'hidden'} hs-collapse overflow-hidden transition-all duration-300 basis-full grow sm:grow-0 sm:basis-auto sm:block sm:order-2`}>
            {/* <div className="flex flex-col gap-6 mt-5 sm:flex-row sm:items-center sm:mt-0 sm:ps-5">
              <a className="text-lg font-bold text-DGXwhite cursor-pointer" onClick={() => setSelectedSection('all')} aria-current="page">All</a>
              <a className="text-lg font-bold text-DGXwhite cursor-pointer" onClick={() => setSelectedSection('top')}>Top Discussions</a>
              <a className="text-lg font-bold text-DGXwhite cursor-pointer" onClick={() => setSelectedSection('recent')}>Recent Discussions</a>
            </div> */}
          </div>
          {isLoading ? (
            <Skeleton
              height={35} // Adjusted to match the height of the input element
              width={150}
              className="w-full xs:w-full sm:w-64 bg-lime-500 rounded-lg mb-1 sm:mt-4"
            />
          ) : (
            <button
              type="button"
              className="py-2 xs:w-full px-3 gap-x-2 text-sm font-bold rounded-lg bg-DGXgreen text-DGXwhite shadow-sm hover:bg-DGXblue hover:border-DGXgreen border border-DGXblue disabled:opacity-50 disabled:pointer-events-none"
              onClick={() => { setIsFormOpen(true) }}
            >
              Start a New Topic +
            </button>
          )}

        </nav>
      </header>
      {modalIsOpen && selectedDiscussion && (
        <DiscussionModal
          isOpen={modalIsOpen}
          onRequestClose={closeModal}
          discussion={selectedDiscussion}
          setDiscussions={setDiscussions}
          discussions={discussions}
        />
      )}
      <div className="flex flex-col lg:flex-row w-full mx-auto bg-white rounded-md border border-gray-200 shadow-md mt-4 mb-4 p-4">


        <aside className="hidden lg:block lg:w-1/4 px-4">

          <div className="mb-8">
            <h2 className="sm:text-sm md:text-base lg:text-lg font-bold mb-4">
              <AiOutlineComment className="inline-block mr-2" />Community Highlights
            </h2>

            <div className="space-y-4">
              {isLoading ? (
                // Display Skeleton loaders in place of the actual content
                Array.from({ length: 5 }).map((_, index) => (
                  <Skeleton
                    key={index}
                    height="8.5rem" // Adjust height as needed to mimic the card's height
                    className="w-full bg-gray-300 rounded-lg mb-4"
                  />
                ))
              ) : (
                // Display actual content when loading is complete
                communityHighlights.map((topic) => (
                  <div
                    key={topic.DiscussionID}
                    className="rounded-lg shadow-lg p-4 border hover:bg-DGXgreen/50 border-DGXblack transition-transform transform hover:scale-105 hover:shadow-xl"
                    onClick={() => openModal(topic)}
                  >
                    <h3 className="text-xl font-semibold">
                      <a href={topic.link} className="text-DGXblack hover:underline">
                        {topic.Title}
                      </a>
                    </h3>
                    <p
                      className="text-DGXblack mt-2 overflow-hidden"
                      dangerouslySetInnerHTML={{
                        __html: topic.Content.substring(0, 150),
                      }}
                    />

                  </div>
                ))
              )}
            </div>

          </div>

          <div>
            <h2 className="sm:text-sm md:text-base lg:text-lg font-bold mb-4">
              <FaTrophy className="inline-block mr-2" />Top Contributors
            </h2>
            <div className="space-y-2">
              {isLoading ? (
                Array.from({ length: 5 }).map((_, index) => (
                  <Skeleton
                    key={index}
                    height="2.5rem"
                    className="w-full bg-gray-300 rounded-lg mb-4"
                  />
                ))
              ) : (
                topUsers.map((user, index) => (
                  <div
                    key={user.userID}
                    className="flex justify-between items-center bg-DGXblue border border-gray-200 rounded-lg shadow-sm p-3 hover:shadow-xl hover:scale-105 transition-colors"
                  >
                    <span className="font-medium text-white">{user.userName}</span>
                    <span className="text-white">{user.count} Post(s)</span>
                  </div>
                ))
              )}

            </div>
          </div>
        </aside>


        <section className="w-full lg:w-2/3 px-4">
          {/* All Discussions */}
          <h2 className="sm:text-sm md:text-base lg:text-lg font-bold mb-4">{selectedSection.charAt(0).toUpperCase() + selectedSection.slice(1)} Discussions</h2>
          <div className="flex flex-col space-y-4">
            {isFormOpen && (
              <form onSubmit={handleSubmit} className="border border-gray-300 rounded-lg p-4">
                <h3 className="text-lg font-bold mb-4">Start a New Discussion</h3>
                <div className="mb-4">
                  <label className="block text-gray-700 font-bold mb-2" htmlFor="title">Title <span className="text-red-500">*</span></label>
                  <input
                    id="title"
                    type="text"
                    className="w-full px-3 py-2 border rounded-lg"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                <div className="mb-4">
                  <label className="block text-gray-700 font-bold mb-2" htmlFor="content">
                    Content <span className="text-red-500">*</span>
                  </label>
                  <ReactQuill
                    id="content"
                    theme="snow"
                    value={content}
                    onChange={setContent}
                    className="border rounded-lg"
                    modules={{
                      toolbar: [
                        [{ header: [1, 2, 3, false] }],
                        ["bold", "italic", "underline", "strike"],
                        ["blockquote", "code-block"],
                        [{ list: "ordered" }, { list: "bullet" }],
                        ["link", "formula"],
                        ["clean"],
                      ]
                    }}
                  />
                </div>

                <div className="mb-4">
                  <label className="block text-gray-700 font-bold mb-2">
                    Tags
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border rounded-lg"
                    value={tagInput}
                    onChange={handleTagInputChange}
                    onKeyPress={handleTagInputKeyPress}
                    placeholder="Press Enter to add a tag"
                  />
                  <div className="mt-2 flex flex-wrap">
                    {tags.split(',').filter(tag => tag).map((tag, index) => (
                      <div key={index} className="flex items-center bg-DGXgreen text-white rounded-full px-3 py-1 mr-2 mt-2">
                        <span>{tag}</span>
                        <button
                          type="button"
                          className="ml-2 focus:outline-none"
                          onClick={() => removeTag(tag)}
                        >
                          <FaWindowClose />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mb-4">
                  <label className="block text-gray-700 font-bold mb-2">
                    Links
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border rounded-lg"
                    value={linkInput}
                    onChange={handleLinkInputChange}
                    onKeyPress={handleLinkInputKeyPress}
                    placeholder="Press Enter to add a link"
                  />
                  <div className="mt-2 flex flex-wrap">
                    {links.split(',').filter(link => link).map((link, index) => (
                      <div key={index} className="flex items-center bg-DGXgreen text-white rounded-full px-3 py-1 mr-2 mt-2">
                        <span>{link}</span>
                        <button
                          type="button"
                          className="ml-2 focus:outline-none"
                          onClick={() => removeLink(link)}
                        >
                          <FaWindowClose />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mb-4">
                  <label className="block text-gray-700 font-bold mb-2">
                    Image
                  </label>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleImageChange}
                  />
                  {selectedImage && (
                    <div className="mt-2">
                      <img src={selectedImage} alt="Selected" className="max-h-40" />
                    </div>
                  )}
                </div>

                <div className="mb-4">
                  <label className="block text-gray-700 font-bold mb-2">
                    Privacy
                  </label>
                  <select
                    value={privacy}
                    onChange={(e) => setPrivacy(e.target.value)}
                    className="w-full px-3 py-2 border rounded-lg"
                  >
                    <option value="private">Private</option>
                    <option value="public">Public</option>
                  </select>
                </div>

                <div className="flex justify-end space-x-2">
                  <button
                    type="button"
                    className="bg-gray-200 text-gray-700 py-2 px-4 rounded-lg"
                    onClick={closeModal}
                  >
                    Close
                  </button>
                  <button
                    type="submit"
                    className="bg-DGXgreen text-white py-2 px-4 rounded-lg"
                  >
                    Submit
                  </button>
                </div>
              </form>
            )}

            <div className="two-h-screen scrollbar scrollbar-thin  overflow-y-auto px-6">
              {isLoading ? (
                // Display a skeleton for each item based on the length of demoDiscussions
                demoDiscussions.map((_, index) => (
                  <div
                    key={index}
                    className="relative shadow my-4 border border-gray-300 rounded-lg p-4 w-full max-w-screen-sm sm:max-w-screen-md md:max-w-screen-lg lg:max-w-screen-xl xl:max-w-screen-2xl bg-gray-200 animate-pulse"
                  >
                    <div className="h-10 bg-gray-300 rounded w-3/4 mb-2"></div>
                    <div className="h-24 bg-gray-300 rounded w-full mb-2"></div>
                    <div className="h-40 w-60 bg-gray-300 rounded mb-2"></div>
                    <div className="flex gap-2">
                      {Array.from({ length: 3 }).map((_, tagIndex) => (
                        <span key={tagIndex} className="h-8 w-20 bg-gray-300 rounded" ></span>
                      ))}
                    </div>
                    <div className="mt-4 h-5 bg-gray-300 rounded w-1/2"></div>
                    <div className="mt-4 h-8 bg-gray-300 rounded w-52"></div>
                  </div>
                ))
              ) : (
                demoDiscussions.map((discussion, i) => (
                  <div
                    key={i}
                    className="relative shadow my-4 border border-gray-300 rounded-lg p-4 w-full max-w-screen-sm sm:max-w-screen-md md:max-w-screen-lg lg:max-w-screen-xl xl:max-w-screen-2xl transition-transform transform hover:scale-105 hover:shadow-lg hover:bg-gray-100 cursor-pointer focus-within:z-10 hover:z-10"
                  // Moved onClick to the entire div for easier interaction
                  >
                    <div>
                      <h3 className="text-lg font-bold md:text-lg lg:text-xl xl:text-2xl">
                        {discussion.Title}
                      </h3>
                      <p className="text-gray-600 text-sm md:text-base lg:text-lg xl:text-xl xs:overflow-hidden">
                        {discussion.Content.length > 500 ? (
                          <>
                            <span
                              dangerouslySetInnerHTML={{
                                __html: discussion.Content.substring(0, 497),
                              }}
                            />
                            <span
                              className="text-blue-700 cursor-pointer"
                              onClick={() => openModal(discussion)}
                            >
                              ...see more
                            </span>
                          </>
                        ) : (
                          <span
                            dangerouslySetInnerHTML={{
                              __html: discussion.Content,
                            }}
                          />
                        )}

                      </p>
                    </div>
                    {discussion.Image && (
                      <div className="mt-2" onClick={() => openModal(discussion)}>
                        <img src={discussion.Image} alt="Discussion" className="max-h-40 w-auto object-cover" />
                      </div>
                    )}
                    <div className="mt-2 flex flex-wrap gap-2" onClick={() => openModal(discussion)}>
                      {discussion.Tag.split(',').filter(tag => tag).map((tag, tagIndex) => (
                        <span key={tagIndex} className="bg-DGXgreen text-white rounded-full px-3 py-1 text-xs md:text-sm lg:text-base">
                          {tag}
                        </span>
                      ))}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2" onClick={() => openModal(discussion)}>
                      {discussion.ResourceUrl.split(',').map((link, linkIndex) => (
                        <a key={linkIndex} href={link} className="text-DGXgreen hover:underline text-xs md:text-sm lg:text-base">
                          {link}
                        </a>
                      ))}
                    </div>
                    <div className="mt-4 flex items-center space-x-4">
                      <button className="flex items-center text-sm md:text-base lg:text-lg" onClick={() => { handleAddLike(discussion.DiscussionID, discussion.userLike) }}>
                        {discussion.userLike == 1 ? <AiFillLike /> : <AiOutlineLike />} {discussion.likeCount} Likes
                      </button>
                      <button
                        className="flex items-center text-DGXgreen text-sm md:text-base lg:text-lg"
                        onClick={() => handleComment(discussion)}
                      >
                        <FaComment className="mr-2" /> {discussion.comment.length} Comments
                      </button>
                    </div>
                  </div>
                ))
              )}

            </div>

          </div>
        </section>
        {isLoading ? (
          <Skeleton
            height="2.5rem"
            className="w-full bg-gray-300 rounded-lg mb-4"
          />
        ) : (
          <div className="lg:hidden mt-8">
            <button
              onClick={() => setIsDropdownOpen(!isDropdownOpen)}
              className="bg-DGXblue text-white py-2 px-4 rounded-lg w-full"
            >
              {isDropdownOpen ? 'Hide' : 'Show'} Community Highlights and Top Contributors
            </button>
            {isDropdownOpen && (
              <aside className="mt-4 px-4">
                <div className="mb-8">
                  <h2 className="text-2xl font-bold mb-4">Community Highlights</h2>
                  <div className="space-y-4">
                    {communityHighlights.map((topic) => (
                      <div
                        key={topic.DiscussionID}
                        className="rounded-lg shadow-lg p-4 border hover:bg-DGXgreen/50 border-DGXblack transition-transform transform hover:scale-105 hover:shadow-xl"
                        onClick={() => openModal(topic)}
                      >
                        <h3 className="text-xl font-semibold">
                          <a href={topic.link} className="text-DGXblack hover:underline">
                            {topic.Title}
                          </a>
                        </h3>
                        <p
                          className="text-DGXblack mt-2 overflow-hidden"
                          dangerouslySetInnerHTML={{
                            __html: topic.Content.substring(0, 150),
                          }}
                        />
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h2 className="text-2xl font-bold mb-4">Top Contributors</h2>
                  <div className="space-y-2">
                    {topUsers.map((user, index) => (
                      <div
                        key={user.userID}
                        className="flex justify-between items-center bg-DGXblue border border-gray-200 rounded-lg shadow-sm p-3 hover:shadow-xl hover:scale-105 transition-colors"
                      >
                        <span className="font-medium text-white">{user.userName}</span>
                        <span className="text-white">{user.count} Post(s)</span>
                      </div>
                    ))}
                  </div>
                </div>
              </aside>
            )}
          </div>
        )}

      </div>
    </div>
  );
};

export default Discussion;
