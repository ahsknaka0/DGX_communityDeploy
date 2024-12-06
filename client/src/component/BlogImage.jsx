import React, { useEffect, useState } from "react";

const BlogImage = () => {
	const [currentImageIndex, setCurrentImageIndex] = useState(0);
	const images = [
		"public/bg1.jpg",
		"public/bg2.jpg",
		"public/bg3.jpg",
	];

	useEffect(() => {
		const interval = setInterval(() => {
			setCurrentImageIndex((prevIndex) => (prevIndex + 1) % images.length);
		}, 5000);
		return () => clearInterval(interval);
	}, [images.length]);
	return (
		<div> <div
			className="py-20 md:py-40 bg-black text-center text-DGXgreen px-4 relative"
			style={{
				backgroundImage: `url(${images[currentImageIndex]})`,
				backgroundSize: 'cover',
				backgroundPosition: 'center',
				transition: 'background-image 1s ease-in-out',
			}}
		>
			<div className="absolute inset-0 bg-black opacity-50"></div>
			<div className="relative z-10">
				<h1 className="text-3xl md:text-5xl lg:text-7xl font-bold leading-snug mb-5">
					Welcome to Our Blog
				</h1>
				<p className="text-gray-100 lg:w-3/5 mx-auto mb-5 text-sm md:text-base">
					Start your blog today and join a community of writers and readers who are passionate about
					sharing their stories and ideas. We offer everything you need to get started, from helpful tips
					and tutorials.
				</p>
			</div>
		</div>
		</div>
	)
}

export default BlogImage