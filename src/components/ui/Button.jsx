import React from 'react';

export function Button({ children, className, ...props }) {
  return (
    <button 
      className={`
        px-6 py-3 
        bg-gradient-to-r from-purple-600 to-blue-600 
        text-white 
        rounded-lg 
        hover:from-purple-700 hover:to-blue-700 
        transition-all 
        duration-300 
        ease-in-out 
        transform 
        hover:scale-105 
        focus:outline-none 
        focus:ring-2 
        focus:ring-purple-500 
        ${className}
      `} 
      {...props}
    >
      {children}
    </button>
  );
}