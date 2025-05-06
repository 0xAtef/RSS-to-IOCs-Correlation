from googletrans import Translator
import logging

def translate_to_english(text):
    """
    Translate the given text to English if it is not already in English.
    
    Args:
        text (str): The text to translate.
    
    Returns:
        str: Translated text in English.
    """
    translator = Translator()
    try:
        # Detect the language of the text
        detected_lang = translator.detect(text).lang
        if detected_lang != 'en':
            # Translate to English
            translated = translator.translate(text, src=detected_lang, dest='en')
            logging.info(f"Translated from {detected_lang} to English: {translated.text}")
            return translated.text
        else:
            # Return the original text if it's already in English
            return text
    except Exception as e:
        logging.error(f"Translation failed: {e}")
        return text