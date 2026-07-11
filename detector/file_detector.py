import os

from PyPDF2 import PdfReader

from docx import Document

from pptx import Presentation


def extract_text_from_file(file_path):

    extension = os.path.splitext(
        file_path
    )[1].lower()

    text = ""

    # =====================
    # TXT
    # =====================

    if extension == '.txt':

        with open(
            file_path,
            'r',
            encoding='utf-8',
            errors='ignore'
        ) as file:

            text = file.read()

    # =====================
    # PDF
    # =====================

    elif extension == '.pdf':

        pdf = PdfReader(
            file_path
        )

        for page in pdf.pages:

            page_text = page.extract_text()

            if page_text:

                text += page_text + "\n"

    # =====================
    # DOCX
    # =====================

    elif extension == '.docx':

        doc = Document(
            file_path
        )

        for para in doc.paragraphs:

            text += para.text + "\n"

    # =====================
    # PPTX
    # =====================

    elif extension == '.pptx':

        presentation = Presentation(
            file_path
        )

        for slide in presentation.slides:

            for shape in slide.shapes:

                if hasattr(
                    shape,
                    "text"
                ):

                    text += (
                        shape.text + "\n"
                    )

    return text.strip()
