import os

import fitz
from docx import Document

from .image_validator import ImageValidator
import zipfile


class FileValidator:

    SUPPORTED_EXTENSIONS = [

        ".pdf",

        ".docx",

        ".txt",
        
        ".zip",

        ".jpg",

        ".jpeg",

        ".png",

        ".bmp",

        ".webp"

    ]

    MAX_FILE_SIZE = 20 * 1024 * 1024   # 20 MB

    @staticmethod
    def validate(file_path):

        # ==========================================
        # File Exists
        # ==========================================

        if not os.path.exists(file_path):

            return {

                "valid": False,

                "error": "FILE_NOT_FOUND",

                "message": "Uploaded file does not exist.",

                "recommendation": "Upload the file again."

            }

        # ==========================================
        # Empty File
        # ==========================================

        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        if file_size == 0:

            return {

                "valid": False,

                "error": "EMPTY_FILE",

                "message": "Uploaded file is empty.",

                "recommendation": "Upload a valid file."

            }

        # ==========================================
        # File Size Limit
        # ==========================================

        if file_size > FileValidator.MAX_FILE_SIZE:

            return {

                "valid": False,

                "error": "FILE_TOO_LARGE",

                "message": "File exceeds the maximum allowed size (20 MB).",

                "recommendation": "Upload a smaller file."

            }

        extension = os.path.splitext(file_path)[1].lower()

        # ==========================================
        # Supported File Type
        # ==========================================

        if extension not in FileValidator.SUPPORTED_EXTENSIONS:

            return {

                "valid": False,

                "error": "UNSUPPORTED_FILE",

                "message": f"{extension} files are not supported.",

                "recommendation": "Supported formats: PDF, DOCX, TXT, JPG, JPEG, PNG, BMP and WEBP."

            }

        # ==========================================
        # IMAGE VALIDATION
        # ==========================================

        if extension in [

            ".jpg",

            ".jpeg",

            ".png",

            ".bmp",

            ".webp"

        ]:

            return ImageValidator.validate(file_path)

        # ==========================================
        # PDF VALIDATION
        # ==========================================

        if extension == ".pdf":

            try:

                pdf = fitz.open(file_path)

                try:

                    if pdf.is_encrypted:

                        return {
                            "valid": False,
                            "error": "PASSWORD_PROTECTED",
                            "needs_password": True,
                            "message": "This document is encrypted and requires a password before it can be analyzed.",
                            "recommendation": "Please enter the document password. SentinelX AI will decrypt the document in memory and continue the security scan."    
                        }

                finally:

                    pdf.close()

            except Exception:

                return {

                    "valid": False,

                    "error": "CORRUPTED_PDF",

                    "message": "PDF appears to be corrupted.",

                    "recommendation": "Upload another PDF."

                }

        # ==========================================
        # DOCX VALIDATION
        # ==========================================

        elif extension == ".docx":

            try:

                Document(file_path)

            except Exception:

                return {

                    "valid": False,

                    "error": "CORRUPTED_DOCX",

                    "message": "DOCX file appears to be corrupted.",

                    "recommendation": "Upload another DOCX file."

                }

        # ==========================================
        # TXT VALIDATION
        # ==========================================

        elif extension == ".txt":

            try:

                with open(

                    file_path,

                    "r",

                    encoding="utf-8",

                    errors="ignore"

                ) as file:

                    file.read()

            except Exception:

                return {

                    "valid": False,

                    "error": "CORRUPTED_TEXT",

                    "message": "Text file cannot be read.",

                    "recommendation": "Upload another TXT file."

                }
                
        # ==========================================
        # ZIP VALIDATION
        # ==========================================

        elif extension == ".zip":

            try:

                with zipfile.ZipFile(file_path) as zip_file:

                    for info in zip_file.infolist():

                        if info.flag_bits & 0x1:

                            return {

                                "valid": False,

                                "error": "PASSWORD_PROTECTED_ZIP",

                                "needs_password": True,

                                "message": "ZIP archive is password protected.",

                                "recommendation": "Enter the ZIP password to continue scanning."

                            }

            except zipfile.BadZipFile:

                return {

                    "valid": False,

                    "error": "CORRUPTED_ZIP",

                    "message": "ZIP archive appears to be corrupted.",

                    "recommendation": "Upload another ZIP archive."

                }

        # ==========================================
        # Validation Passed
        # ==========================================

        return {

        "valid": True,

        "status": "VALID",

        "extension": extension,

        "size": file_size,

        "message": "File passed all validation checks."

    }