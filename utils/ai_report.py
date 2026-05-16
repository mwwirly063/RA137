import os

from openai import OpenAI

from utils.database import save_report
from utils.logger import log


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


client = None

if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)


MODULE_PROMPTS = {
    "Subdomain Enumeration": """
    این خروجی مربوط به جمع آوری زیردامنه ها است.

    توضیح بده:
    - چه تعداد زیردامنه پیدا شده
    - این موضوع چه اهمیتی دارد
    - آیا احتمال attack surface گسترده وجود دارد
    """,

    "IP Extraction": """
    این خروجی مربوط به استخراج آی پی ها است.

    توضیح بده:
    - چه تعداد آی پی استخراج شده
    - آیا زیرساخت گسترده به نظر می رسد
    - آیا وجود چندین آی پی اهمیت امنیتی دارد
    """,

    "Certificate Discovery": """
    این خروجی مربوط به تحلیل SSL Certificate ها است.

    توضیح بده:
    - آیا دامنه های مرتبط پیدا شده اند
    - آیا احتمال وجود hidden asset وجود دارد
    - آیا certificate leakage مشاهده می شود
    """
}


def generate_ai_report(module_name, data):

    if not client:

        log("OpenAI API key not found. Skipping AI report.")

        return None

    module_prompt = MODULE_PROMPTS.get(
        module_name,
        "این خروجی را در چند خط کوتاه تحلیل کن."
    )

    prompt = f"""
    {module_prompt}

    خروجی:
    {data}
    """

    try:

        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        report = response.choices[0].message.content.strip()

        save_report(module_name, report)

        return report

    except Exception as e:

        log(f"AI report generation failed: {e}")

        return None