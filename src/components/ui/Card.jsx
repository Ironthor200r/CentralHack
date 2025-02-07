import React from 'react';

export function Card({ children, className, ...props }) {
  return (
    <div 
      className={`
        bg-gradient-to-br from-[#1a1a2e] to-[#16213e] 
        border border-purple-900/50 
        rounded-xl 
        shadow-2xl 
        shadow-purple-900/30 
        text-gray-100 
        ${className}
      `} 
      {...props}
    >
      {children}
    </div>
  );
}

export function CardContent({ children, className, ...props }) {
  return (
    <div 
      className={`
        p-6 
        space-y-4 
        backdrop-blur-sm 
        bg-black/20 
        ${className}
      `} 
      {...props}
    >
      {children}
    </div>
  );
}