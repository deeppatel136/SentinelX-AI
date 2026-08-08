import os
import fitz
from docx import Document


def extract_text_from_file(file_path, password=None):

    extension = os.path.splitext(file_path)[1].lower()

    # ==========================
    # PDF
    # ==========================

    if extension == ".pdf":

        pdf = fitz.open(file_path)

        if pdf.is_encrypted:

            if password is None:

                pdf.close()

                raise Exception("Password required")

            if not pdf.authenticate(password):

                pdf.close()

                raise Exception("Incorrect password")

        text = ""

        for page in pdf:

            text += page.get_text()

        pdf.close()

        return text

    # ==========================
    # DOCX
    # ==========================

    elif extension == ".docx":

        document = Document(file_path)

        text = ""

        for paragraph in document.paragraphs:

            text += paragraph.text + "\n"

        return text

    # ==========================
    # TXT
    # ==========================

    elif extension == ".txt":

        with open(

            file_path,

            "r",

            encoding="utf-8",

            errors="ignore"

        ) as file:

            return file.read()

    return ""