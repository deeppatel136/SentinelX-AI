import os

from PIL import Image
from PIL import UnidentifiedImageError


class ImageValidator:

    SUPPORTED_FORMATS = [

        "JPEG",

        "PNG",

        "BMP",

        "WEBP"

    ]

    @staticmethod
    def validate(image_path):

        # ---------------------------------------
        # File exists
        # ---------------------------------------

        if not os.path.exists(image_path):

            return {

                "valid": False,

                "error": "FILE_NOT_FOUND",

                "message": "Image file does not exist.",

                "recommendation": "Upload the image again."

            }

        # ---------------------------------------
        # Empty file
        # ---------------------------------------

        if os.path.getsize(image_path) == 0:

            return {

                "valid": False,

                "error": "EMPTY_IMAGE",

                "message": "Uploaded image is empty.",

                "recommendation": "Upload a valid image."

            }

        # ---------------------------------------
        # Image verification
        # ---------------------------------------

        try:

            img = Image.open(image_path)

            img.verify()

        except UnidentifiedImageError:

            return {

                "valid": False,

                "error": "INVALID_IMAGE",

                "message": "Uploaded file is not a valid image.",

                "recommendation": "Upload JPG, PNG, BMP or WEBP."

            }

        except Exception:

            return {

                "valid": False,

                "error": "CORRUPTED_IMAGE",

                "message": "Image appears to be corrupted.",

                "recommendation": "Upload another image."

            }

        # ---------------------------------------
        # Re-open image
        # verify() closes image
        # ---------------------------------------

        try:

            img = Image.open(image_path)

        except Exception:

            return {

                "valid": False,

                "error": "IMAGE_READ_ERROR",

                "message": "Unable to read image.",

                "recommendation": "Upload another image."

            }

        # ---------------------------------------
        # Supported format
        # ---------------------------------------

        if img.format not in ImageValidator.SUPPORTED_FORMATS:

            return {

                "valid": False,

                "error": "UNSUPPORTED_FORMAT",

                "message": f"{img.format} images are not supported.",

                "recommendation": "Use JPG, PNG, BMP or WEBP."

            }

        # ---------------------------------------
        # Everything OK
        # ---------------------------------------

        return {

            "valid": True,

            "message": "Image validation successful."

        }