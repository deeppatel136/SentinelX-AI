import cv2
from pyzbar.pyzbar import decode
from .utils import QRUtils


class QRScanner:

    @staticmethod
    def scan_qr(image_path):
        """
        Scan QR Code from an image.

        Returns
        -------
        {
            success: bool,
            message: str,
            data: str,
            qr_type: str
        }
        """

        try:

            image = cv2.imread(image_path)

            if image is None:

                return {
                    "success": False,
                    "message": "Unable to read image.",
                    "data": None,
                    "qr_type": None
                }

            qr_codes = decode(image)

            if len(qr_codes) == 0:

                return {
                    "success": False,
                    "message": "No QR Code found.",
                    "data": None,
                    "qr_type": None
                }

            # First QR Code
            qr = qr_codes[0]

            qr_data = qr.data.decode("utf-8").strip()

            qr_type = QRUtils.detect_qr_type(qr_data)

            return {

                "success": True,

                "message": "QR Code detected successfully.",

                "data": qr_data,

                "qr_type": qr_type

            }

        except Exception as e:

            return {

                "success": False,

                "message": str(e),

                "data": None,

                "qr_type": None

            }