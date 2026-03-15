import React from 'react';
import { Github, Mail, Globe } from 'lucide-react';

const Footer = () => {
  return (
    <footer className="bg-white border-t mt-10">
      <div className="max-w-7xl mx-auto px-4 py-6 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Left */}
        <p className="text-sm text-slate-600">
          © {new Date().getFullYear()}{' '}
          <span className="font-semibold">SKNEXUS</span>. All rights reserved.
        </p>

        {/* Center */}
        <div className="flex items-center gap-6 text-sm text-slate-600">
          <a href="#" className="hover:text-sky-600 transition">
            Privacy
          </a>
          <a href="#" className="hover:text-sky-600 transition">
            Terms
          </a>
          <a href="#" className="hover:text-sky-600 transition">
            Support
          </a>
        </div>

        {/* Right Icons */}
        <div className="flex items-center gap-4 text-slate-600">
          <a href="#" className="hover:text-sky-600">
            <Mail size={18} />
          </a>

          <a href="#" className="hover:text-sky-600">
            <Globe size={18} />
          </a>

          <a href="#" className="hover:text-sky-600">
            <Github size={18} />
          </a>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
