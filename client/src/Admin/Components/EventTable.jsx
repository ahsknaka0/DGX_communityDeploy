import React, { useRef } from 'react';
import { useState, useContext, useEffect } from 'react';
import { Calendar as BigCalendar, momentLocalizer } from 'react-big-calendar';
import moment from 'moment';
import 'react-big-calendar/lib/css/react-big-calendar.css';
import ReactQuill from 'react-quill';
import 'react-quill/dist/quill.snow.css';
import ApiContext from '../../context/ApiContext.jsx';
import { compressImage } from '../../utils/compressImage.js';

const eventColors = {
    workshop: '#013D54',
    event: '#76B900',
};

const EventTable = () => {
    const localizer = momentLocalizer(moment);
    const { fetchData, userToken, user } = useContext(ApiContext);
    const [events, setEvents] = useState([]);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [newEvent, setNewEvent] = useState({
        title: '',
        start: '',
        end: '',
        category: 'Select one',
        companyCategory: 'Select one',
        poster: null,
        venue: '',
        description: '',
        host: '',
        registerLink: '', // Add registerLink to state
    });

    const [selectedEvent, setSelectedEvent] = useState(null);
    const [errors, setErrors] = useState({});
    const fileInputRef = useRef(null);
    // Create refs for input fields
    const titleRef = useRef(null);
    const startRef = useRef(null);
    const endRef = useRef(null);
    const categoryRef = useRef(null);
    const companyCategoryRef = useRef(null);
    const venueRef = useRef(null);
    const hostRef = useRef(null);
    const descriptionRef = useRef(null);
    const registerLinkRef = useRef(null);


    useEffect(() => {
        const fetchEvents = async () => {
            const response = await fetch("/api/getEvents"); // Replace with your API endpoint
            const data = await response.json();
            setEvents(data);
        };
        fetchEvents();
    }, []);

    const addEvent = async () => {
        const response = await fetch("/api/addEvent", { method: 'POST' }); // Add data to the event
        const result = await response.json();
        setEvents(prevEvents => [...prevEvents, result]); // Add the new event to the table
    };
    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => {
                setNewEvent({ ...newEvent, poster: reader.result });
            };
            reader.readAsDataURL(file);
        }
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        setNewEvent({ ...newEvent, [name]: value });
    };

    const handleDescriptionChange = (value) => {
        setNewEvent({ ...newEvent, description: value });
    };


    const handleImageChange = async (e) => {
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0];
            if (file) {
                const compressedFile = await compressImage(file);
                setNewEvent({ ...newEvent, [poster]: compressedFile });
            }
        }
    };



    const handleSubmit = async (events) => {
        const errors = {};

        // Validate form fields
        if (!newEvent.title) errors.title = 'Event title is required.';
        if (!newEvent.start) errors.start = 'Start date is required.';
        if (!newEvent.end) errors.end = 'End date is required.';
        if (newEvent.category === 'Select one') errors.category = 'Please select a category.';
        if (newEvent.companyCategory === 'Select one') errors.companyCategory = 'Please select a company category.';
        if (!newEvent.venue) errors.venue = 'Venue is required.';
        if (!newEvent.description) errors.description = 'Description is required.';
        if (!newEvent.host) errors.host = 'Host is required.';
        if (!newEvent.registerLink) errors.registerLink = 'Register link is required.';

        // Check for errors
        if (Object.keys(errors).length > 0) {
            setErrors(errors);
            const firstErrorField = Object.keys(errors)[0];
            const refMap = {
                title: titleRef,
                start: startRef,
                end: endRef,
                category: categoryRef,
                companyCategory: companyCategoryRef,
                venue: venueRef,
                host: hostRef,
                description: descriptionRef,
                registerLink: registerLinkRef,
            };
            const element = refMap[firstErrorField].current;
            if (element) {
                element.focus();
                element.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            return;
        }

        const endpoint = 'eventandworkshop/addEvent';
        const method = 'POST';
        const headers = {
            'Content-Type': 'application/json',
            'auth-token': userToken
        };
        const body = {
            title: newEvent.title,
            start: newEvent.start,
            end: newEvent.end,
            category: newEvent.category,
            companyCategory: newEvent.companyCategory,
            venue: newEvent.venue,
            host: newEvent.host,
            registerLink: newEvent.registerLink,
            poster: newEvent.poster, // Ensure you handle the poster appropriately
            description: newEvent.description,
        };


        try {
            const data = await fetchData(endpoint, method, body, headers);
            if (data.success) {
                setEvents([
                    ...events,
                    {
                        ...newEvent,
                        start: new Date(newEvent.start),
                        end: new Date(newEvent.end),
                    },
                ]);
                resetForm();
                setIsModalOpen(false);
                console.log('Event added successfully!', data.message);
            } else {
                console.error(`Server Error: ${data.message}`);
                alert(`Error: ${data.message}`);
            }
        } catch (error) {
            console.error('Error adding event:', error);
        }
    };

    const handleCloseModal = () => {
        resetForm();
        setIsModalOpen(false);
    };

    const resetForm = () => {
        setNewEvent({
            title: '',
            start: '',
            end: '',
            category: 'Select one',
            companyCategory: 'Select one',
            poster: null,
            venue: '',
            description: '',
            host: '',
            registerLink: '', // Reset registerLink
        });
        setErrors({});
        if (fileInputRef.current) {
            fileInputRef.current.value = ''; // Clear the file input
        }
    };


    return (


        <div className="container mx-auto mt-10">
            <div>
                <h1 className='flex justify-center items-center font-bold text-3xl mb-10'>Events and Workshops Calendar</h1>
                <p className="mt-1 flex text-md justify-center items-center font-normal text-gray-500 dark:text-gray-400">Browse and manage Events in the DGX community.</p>
            </div>

            <div className="mb-5">
                <button
                    onClick={() => setIsModalOpen(true)}
                    className="bg-DGXgreen text-white p-2 rounded"
                >
                    Add Event
                </button>
            </div>

            

            {isModalOpen && (
                <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-70 z-50">
                    <div className="bg-white rounded-lg shadow-lg p-5 max-w-7xl w-full max-h-[90vh] overflow-y-auto z-50">
                        <h2 className="text-xl font-bold mb-4">Add New Event</h2>
                        <input
                            type="text"
                            name="title"
                            placeholder="Event Title"
                            value={newEvent.title}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.title ? 'border-red-500' : ''}`}
                            ref={titleRef}
                        />
                        {errors.title && <p className="text-red-500 text-sm mb-2">{errors.title}</p>}

                        <input
                            type="date"
                            name="start"
                            placeholder="Start Date"
                            value={newEvent.start}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.start ? 'border-red-500' : ''}`}
                            ref={startRef}
                        />
                        {errors.start && <p className="text-red-500 text-sm mb-2">{errors.start}</p>}

                        <input
                            type="date"
                            name="end"
                            placeholder="End Date"
                            value={newEvent.end}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.end ? 'border-red-500' : ''}`}
                            ref={endRef}
                        />
                        {errors.end && <p className="text-red-500 text-sm mb-2">{errors.end}</p>}

                        <select
                            name="category"
                            value={newEvent.category}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.category ? 'border-red-500' : ''}`}
                            ref={categoryRef}
                        >
                            <option value="Select one">Select one</option>
                            <option value="workshop">Workshop</option>
                            <option value="event">Event</option>
                        </select>
                        <select
                            name="companyCategory"
                            value={newEvent.companyCategory}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.companyCategory ? 'border-red-500' : ''}`}
                            ref={companyCategoryRef}
                        >
                            <option value="Select one">Category</option>
                            <option value="giEvent">Global Infoventures Event</option>
                            <option value="nvidiaEvent">NVIDIA Event</option>
                        </select>
                        {errors.category && <p className="text-red-500 text-sm mb-2">{errors.category}</p>}

                        <input
                            type="text"
                            name="venue"
                            placeholder="Venue"
                            value={newEvent.venue}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.venue ? 'border-red-500' : ''}`}
                            ref={venueRef}
                        />
                        {errors.venue && <p className="text-red-500 text-sm mb-2">{errors.venue}</p>}

                        <input
                            type="text"
                            name="host"
                            placeholder="Host"
                            value={newEvent.host}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.host ? 'border-red-500' : ''}`}
                            ref={hostRef}
                        />
                        {errors.host && <p className="text-red-500 text-sm mb-2">{errors.host}</p>}

                        <input
                            type="text"
                            name="registerLink"
                            placeholder="Registration Link"
                            value={newEvent.registerLink}
                            onChange={handleChange}
                            className={`p-2 border border-gray-300 rounded mb-2 w-full ${errors.registerLink ? 'border-red-500' : ''}`}
                            ref={registerLinkRef}
                        />
                        {errors.registerLink && <p className="text-red-500 text-sm mb-2">{errors.registerLink}</p>}

                        <input
                            type="file"
                            ref={fileInputRef}
                            onChange={handleFileChange}
                            className="p-2 border border-gray-300 rounded mb-2 w-full"
                        />
                        {newEvent.poster && (
                            <img
                                onChange={handleImageChange}
                                src={newEvent.poster}
                                alt="Event Poster"
                                className="w-32 h-32 object-cover mb-2"
                            />
                        )}

                        <ReactQuill
                            value={newEvent.description}
                            onChange={handleDescriptionChange}
                            className={`mb-2 ${errors.description ? 'border-red-500' : ''}`}
                            ref={descriptionRef}
                            modules={{
                                toolbar: [
                                    ['bold', 'italic', 'underline', 'strike'], // toggled buttons
                                    [{ 'list': 'ordered' }, { 'list': 'bullet' }],
                                    [{ 'script': 'sub' }, { 'script': 'super' }], // superscript/subscript
                                    [{ 'indent': '-1' }, { 'indent': '+1' }], // outdent/indent
                                    [{ 'direction': 'rtl' }], // text direction
                                    [{ 'size': ['small', false, 'large', 'huge'] }], // custom dropdown
                                    [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
                                    [{ 'color': [] }, { 'background': [] }], // dropdown with defaults from theme
                                    [{ 'font': [] }],
                                    [{ 'align': [] }],
                                    ['clean'] // remove formatting button
                                ]
                            }}
                            formats={[
                                'header', 'font', 'size',
                                'bold', 'italic', 'underline', 'strike',
                                'blockquote', 'list', 'bullet', 'indent',
                                'link', 'image', 'color', 'background', 'align',
                                'script'
                            ]}
                        />
                        {errors.description && <p className="text-red-500 text-sm mb-2">{errors.description}</p>}

                        <div className="flex justify-end">
                            <button
                                onClick={handleCloseModal}
                                className="bg-red-500 text-white p-2 rounded mr-2"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={async (events) => {
                                    await handleSubmit(events);  // Ensure handleSubmit is completed
                                    await addEvent();
                                }
                            }
                                className="bg-DGXgreen text-white p-2 rounded"
                            >
                                Add Event
                            </button>
                        </div>
                    </div>
                </div>
            )}

        </div>

    );
};

export default EventTable;
