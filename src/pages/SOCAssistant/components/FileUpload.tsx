import React, { useState, useRef } from 'react';
import { UploadCloudIcon, FileIcon, XIcon } from 'lucide-react';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  // Future: Add more props like accepted file types, size limits, etc.
}

const FileUpload: React.FC<FileUploadProps> = ({ onFileSelect }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    const file = event.target.files?.[0];
    if (file) {
      if (file.type === 'application/json') {
        setSelectedFile(file);
        onFileSelect(file);
      } else {
        setError('Invalid file type. Please upload a JSON file.');
        setSelectedFile(null);
        // Optionally clear the input
        if (fileInputRef.current) {
          fileInputRef.current.value = "";
        }
      }
    }
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = ""; // Clear the file input
    }
    // Potentially call a prop function if parent needs to know file was removed
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="w-full max-w-lg mx-auto">
      <div 
        className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center transition-colors cursor-pointer
                    ${error ? 'border-red-500 bg-red-50' : 'border-gray-300 hover:border-blue-500 bg-gray-50 hover:bg-blue-50'}`}
        onClick={triggerFileInput} // Allow clicking the whole area if no file is selected
        onDragOver={(e) => e.preventDefault()} // Basic for enabling drop
        onDrop={(e) => { // Basic drag and drop
          e.preventDefault();
          if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            if (fileInputRef.current) {
              fileInputRef.current.files = e.dataTransfer.files;
              // Manually trigger change event for the input
              const event = new Event('change', { bubbles: true });
              fileInputRef.current.dispatchEvent(event);
            }
          }
        }}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          className="hidden"
          accept=".json,application/json"
        />
        {!selectedFile && !error && (
          <>
            <UploadCloudIcon className="w-12 h-12 text-gray-400 mb-3" />
            <p className="text-gray-500 text-sm mb-1">
              <span className="font-semibold text-blue-600">Click to upload</span> or drag and drop
            </p>
            <p className="text-xs text-gray-400">JSON files only (e.g., ELK alert export)</p>
          </>
        )}
        {selectedFile && (
          <div className="text-center">
            <FileIcon className="w-10 h-10 text-blue-500 mb-2 mx-auto" />
            <p className="text-sm font-medium text-gray-700">{selectedFile.name}</p>
            <p className="text-xs text-gray-500">{(selectedFile.size / 1024).toFixed(2)} KB</p>
            <button
              onClick={(e) => {
                e.stopPropagation(); // Prevent re-triggering file input
                handleRemoveFile();
              }}
              className="mt-3 text-xs text-red-500 hover:text-red-700 flex items-center justify-center gap-1"
            >
              <XIcon size={14}/> Remove
            </button>
          </div>
        )}
        {error && (
            <div className="text-center">
                <UploadCloudIcon className="w-12 h-12 text-red-400 mb-3" />
                <p className="text-red-500 text-sm mb-1">
                <span className="font-semibold">Upload Failed</span>
                </p>
                <p className="text-xs text-red-400">{error}</p>
                 <p className="text-xs text-gray-400 mt-2">
                    <span className="font-semibold text-blue-600 cursor-pointer hover:underline" onClick={triggerFileInput}>
                        Try again
                    </span>
                </p>
            </div>
        )}
      </div>
    </div>
  );
};

export default FileUpload; 