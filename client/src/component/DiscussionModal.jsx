import React, { useState, useContext } from "react";
// import { FaThumbsUp, FaComment } from "react-icons/fa";
import { AiFillLike, AiOutlineLike } from "react-icons/ai"
// import { images } from "../constant/index.js";
import ApiContext from '../context/ApiContext.jsx';
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const DiscussionModal = ({ isOpen, onRequestClose, discussion }) => {
  const [dissComments, setDissComments] = useState([]);
  const [demoDiscussions, setDemoDiscussions] = useState([]);

  const [newComment, setNewComment] = useState("");
  const [replyTexts, setReplyTexts] = useState({});

  const { fetchData, userToken, user } = useContext(ApiContext);


  const [loading, setLoading] = useState(false);

  const handleAddComment = async (id) => {
    if (userToken) {
      const endpoint = "discussion/discussionpost";
      const method = "POST";
      const headers = {
        'Content-Type': 'application/json',
        'auth-token': userToken
      };
      const body = {
        "reference": id,
        "comment": newComment
      };
      setLoading(true);
      // console.log(headers, endpoint)

      try {
        // console.log("Inside Try");

        const data = await fetchData(endpoint, method, body, headers)
        // console.log(data);
        if (!data.success) {
          setLoading(false);
          toast.error(`Error in posting comment try again: ${data.message}`, {
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
          console.log(data.postId);

          const newCommentObj = {
            UserID: user.UserID,
            UserName: user.Name,
            DiscussionID: data.postId,
            timestamp: new Date().toLocaleString(),
            Comment: newComment,
            comment: [],
            likeCount: 0,
            UserLike: 0,
          };
          // console.log(discussion.comment);
          discussion.comment = [newCommentObj, ...discussion.comment]
          console.log(discussion.comment);
          setLoading(false);
          toast.success("Comment Post Successfully", {
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
      } catch (error) {
        setLoading(false);
        toast.error(`Something went wrong`, {
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
    }

    if (newComment.trim() !== "") {
      const newCommentObj = {
        username: "New User",
        discussion: discussion.DiscussionID,
        timestamp: new Date().toLocaleString(),
        commentData: newComment,
        likes: 0,
        replies: [],
      };

      setDissComments([...dissComments, newCommentObj]);
      setNewComment("");
    }
  };

  const handleReplyTextChange = (index, text) => {
    setReplyTexts((prevState) => ({
      ...prevState,
      [index]: text,
    }));
  };

  const handleAddReply = async (commentIndex, replyText, id) => {
    if (userToken) {
      const endpoint = "discussion/discussionpost";
      const method = "POST";
      const headers = {
        'Content-Type': 'application/json',
        'auth-token': userToken,
      };
      const body = {
        reference: id,
        comment: replyText,
      };
      setLoading(true);

      try {
        const data = await fetchData(endpoint, method, body, headers);

        if (!data.success) {
          setLoading(false);
          toast.error(`Error in posting reply: ${data.message}`, {
            position: "top-center",
            autoClose: 3000,
          });
          return;
        }

        const newReplyObj = {
          Comment: replyText,
          DiscussionID: id,
          UserName: user.Name,
          UserID: user.UserID,
          likeCount: 0,
          timestamp: new Date().toISOString(),
          userLike: 0,
          comment: [],
        };

        // Update the discussion with the new reply
        const updatedDemoDiscussions = demoDiscussions.map((discussionItem) => {
          if (discussionItem.DiscussionID === id) {
            const updatedComments = discussionItem.comment.map((comment, index) => {
              if (index === commentIndex) {
                return {
                  ...comment,
                  comment: [...comment.comment, newReplyObj], // Add new reply to the comment's replies
                };
              }
              return comment;
            });

            return {
              ...discussionItem,
              comment: updatedComments,
            };
          }
          return discussionItem;
        });

        setDemoDiscussions(updatedDemoDiscussions);
        setReplyTexts((prevState) => ({
          ...prevState,
          [commentIndex]: "",
        }));
        setLoading(false);
        toast.success("Reply posted successfully", {
          position: "top-center",
          autoClose: 3000,
        });
      } catch (error) {
        setLoading(false);
        toast.error(`Error posting reply: ${error.message}`, {
          position: "top-center",
          autoClose: 3000,
        });
      }
    }
  };


  // const handleAddLike = async (id, userLike) => {
  //   // console.log(id, userLike)

  //   if (userToken) {
  //     const endpoint = "discussion/discussionpost";
  //     const method = "POST";
  //     const headers = {
  //       'Content-Type': 'application/json',
  //       'auth-token': userToken
  //     };
  //     const like = userLike == 1 ? 0 : 1
  //     const body = {
  //       "reference": id,
  //       "likes": like
  //     };
  //     console.log(body)
  //     try {
  //       const data = await fetchData(endpoint, method, body, headers)
  //       if (!data.success) {
  //         // console.log(data)
  //         console.log("Error occured while liking the post")
  //       } else if (data.success) {
  //         // console.log(data);
  //         const updatedData = demoDiscussions.map((item) =>
  //           item.DiscussionID === id ? { ...item, userLike: like, likeCount: like === 1 ? item.likeCount + 1 : item.likeCount - 1 } : item
  //         );
  //         setDemoDiscussions(updatedData)
  //         console.log(updatedData)
  //       }
  //     } catch (error) {
  //       console.log(error);
  //     }
  //   }
  // };
  // const handleAddLike = () => setLikeCount(likeCount + 1);







  return (
    <div>
      {/* Background Overlay */}
      <ToastContainer />

      {isOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 backdrop-blur-sm z-50 transition-opacity duration-300 flex justify-center items-center">
          {/* Modal */}
          <div
            className={`w-[calc(100%-1rem)] h-[calc(100%-1rem)] sm:w-[calc(100%-2rem)] sm:h-[calc(100%-2rem)] lg:w-[calc(100%-4rem)] lg:h-[calc(100%-4rem)] xl:w-[calc(100%-6rem)] xl:h-[calc(100%-6rem)] bg-DGXwhite transition-transform shadow-lg transform ${isOpen ? "translate-y-0" : "translate-y-full"} z-50 flex flex-col overflow-auto`}
          >
            <div className="px-2 sm:px-5 w-full flex flex-col flex-grow overflow-auto">
              <div className="flex justify-between">
                <div className="border-l-4 border-DGXblue flex items-center justify-between p-2 sm:p-4">
                  <img
                    src={discussion.Image}
                    className="w-16 sm:w-24 object-cover rounded-full aspect-square"
                    alt=""
                  />
                  <div className="p-4">
                    <div className="text-3xl">{discussion.Title}</div>
                    <div className="flex flex-col">
                      <span>{new Date(discussion.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
                <button
                  className="text-2xl sm:text-4xl self-start"
                  onClick={onRequestClose}
                >
                  {" "}
                  ×{" "}
                </button>
              </div>

              {/* Post/Discussion Section */}
              <div className="flex flex-col sm:flex-row flex-grow h-full overflow-auto">
                {/* Content Section (Top part) */}
                <div className="w-full sm:w-1/2 p-2 sm:p-4 border-b sm:border-b-0 sm:border-r border-gray-200 overflow-auto flex-grow">
                  <h2 className="text-lg sm:text-xl font-semibold mb-2 sm:mb-4">
                    {discussion.title}
                  </h2>

                  {/* Image */}
                  {discussion.Image && (
                    <div className="max-w-sm mx-auto mb-4 sm:mb-4">
                      <img
                        src={discussion.Image}
                        alt="Post"
                        className="w-full h-auto rounded-lg"
                      />
                    </div>
                  )}

                  {/* Content */}
                  {discussion.Content && (
                    <div
                      className="mb-2 sm:mb-4"
                      dangerouslySetInnerHTML={{ __html: discussion.Content }}
                    />
                  )}

                  {/* Tags */}
                  {discussion.Tag && (
                    <div className="mb-2 sm:mb-4">
                      <h3 className="text-md sm:text-lg font-semibold">Tags:</h3>
                      <ul className="flex flex-wrap mt-1 sm:mt-2">
                        {discussion.Tag.split(',').filter(tag => tag).map((tag, index) => (
                          <li
                            key={index}
                            className="bg-DGXblue text-DGXwhite py-1 px-2 rounded-full text-xs sm:text-sm mr-2 mb-2"
                          >
                            {tag}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Links */}
                  {discussion.ResourceUrl && (
                    <div>
                      <h3 className="text-md sm:text-lg font-semibold">Links:</h3>
                      <ul className="list-disc list-inside">
                        {discussion.ResourceUrl.split(',').filter(link => link).map((link, index) => (
                          <li key={index}>
                            <a
                              href={link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-DGXblue"
                            >
                              {link}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Comments Section (Bottom part) */}
                <div className="w-full sm:w-1/2 p-2 sm:p-4 overflow-auto flex flex-col flex-grow">
                  <div className="p-4 w-full flex items-center space-x-4">
                    <textarea
                      rows={3}
                      value={newComment}
                      onChange={(e) => setNewComment(e.target.value)}
                      className="flex-grow rounded border-2 border-DGXblue p-2"
                      placeholder="Add a comment..."
                    />
                    <button
                      onClick={() => handleAddComment(discussion.DiscussionID)}
                      className="flex-shrink-0 w-2/5 lg:w-1/5 bg-DGXgreen hover:bg-DGXblue rounded xs:text-sm md:text-base text-white text-xl p-2"
                    >
                      Add Comment
                    </button>
                  </div>

                  <h2 className="text-lg sm:text-xl font-semibold mb-2 sm:mb-4">
                    Comments
                  </h2>
                  <ul className="space-y-4 overflow-auto flex-grow">
                    {discussion.comment.map((comment, index) => (
                      <li key={index} className="p-2 sm:p-4 border rounded-lg space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-md sm:text-lg font-semibold">{comment.UserName}</span>
                          <span className="text-xs sm:text-sm text-gray-500">{comment.timestamp}</span>
                        </div>
                        <div className="text-md sm:text-lg">{comment.Comment}</div>
                        <div className="flex items-center gap-2">
                          {comment.userLike == 1 ? <AiFillLike /> : <AiOutlineLike />}
                          <span>{comment.likeCount}</span>
                        </div>

                        {/* Rendering Replies */}
                        <div>
                          {comment.comment &&
                            comment.comment.map((reply, replyIndex) => (
                              <div key={replyIndex} className="ml-4 p-2 sm:p-4 border-l border-gray-200">
                                <div className="flex items-center justify-between">
                                  <span className="text-md sm:text-lg font-semibold">{reply.UserName}</span>
                                  <span className="text-xs sm:text-sm text-gray-500">{reply.timestamp}</span>
                                </div>
                                <div className="text-md sm:text-lg">{reply.Comment}</div>
                                <div className="flex items-center gap-2">
                                  {reply.userLike == 1 ? <AiFillLike /> : <AiOutlineLike />}
                                  <span>{reply.likeCount}</span>
                                </div>
                              </div>
                            ))}
                        </div>

                        {/* Reply Input */}
                        <div className="p-2 sm:p-4 border-t border-gray-200 flex flex-wrap">
                          <textarea
                            rows={1}
                            value={replyTexts[index] || ""}
                            onChange={(e) => handleReplyTextChange(index, e.target.value)}
                            className="w-2/3 sm:w-2/3  md:w-auto rounded border-2 border-DGXblue p-2 xl:w-full"
                            placeholder="Reply to this comment..."
                          />
                          <button
                            onClick={() => handleAddReply(index, replyTexts[index], comment.DiscussionID)}
                            className="w-1/3 sm:w-1/3 md:w-auto my-2 bg-DGXgreen hover:bg-DGXblue rounded text-white text-xl p-2 xs:text-sm"
                          >
                            Add Reply
                          </button>
                        </div>

                      </li>
                    ))}
                  </ul>

                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
``;

export default DiscussionModal;