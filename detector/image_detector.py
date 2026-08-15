_reader = None


def get_reader():
    global _reader
    if _reader is None:
        import easyocr
        _reader = easyocr.Reader(['en'], gpu=False)
    return _reader


def extract_text_from_image(image_path):
    reader = get_reader()
    results = reader.readtext(image_path, detail=0)
    extracted_text = " ".join(results)
    return extracted_text