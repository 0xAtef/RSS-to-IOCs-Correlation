from googletrans import Translator, LANGUAGES
import logging
import time

translator = Translator()

def translate_to_english(text, retries=3, delay=2):
    """
    Translate the given text to English using Google Translate.

    Args:
        text (str): The text to translate.
        retries (int): Number of retry attempts for translation failures.
        delay (int): Delay in seconds between retries.

    Returns:
        str: Translated text in English, or the original text if translation fails.
    """
    if not text:
        return text

    for attempt in range(1, retries + 1):
        try:
            logging.info(f"Translating text (attempt {attempt}/{retries}): {text}")
            translated = translator.translate(text, dest="en")
            return translated.text
        except Exception as e:
            logging.error(f"Translation failed (attempt {attempt}/{retries}): {e}")
            if attempt < retries:
                time.sleep(delay)

    logging.warning(f"Returning original text after failed translation attempts: {text}")
    return text