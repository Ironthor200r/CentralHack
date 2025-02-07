import React from 'react';

export function Input({ className, ...props }) {
  return (
    <input 
      className={`
        w-full 
        px-4 py-3 
        bg-[#0f0f1a] 
        border 
        border-purple-900/50 
        rounded-lg 
        text-gray-100 
        placeholder-gray-500 
        focus:outline-none 
        focus:ring-2 
        focus:ring-purple-600 
        focus:border-transparent 
        ${className}
      `} 
      {...props}
    />
  );
}