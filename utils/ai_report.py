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
    """,

    "Tech Detection": """
    این خروجی مربوط به تشخیص تکنولوژی های استفاده شده در زیرساخت هدف است.

    توضیح بده:
    - چه وب سرورها و فریمورک هایی شناسایی شده اند
    - آیا WAF فعال وجود دارد و از چه نوعی است
    - آیا صفحات پیش فرض (default page) مشاهده می شود و چه اهمیتی دارد
    - آیا تکنولوژی خاصی وجود دارد که آسیب پذیری های شناخته شده داشته باشد
    """,

    "RIPE Recon": """
    این خروجی مربوط به استعلام از پایگاه داده RIPE و شناسایی رنج آی پی های متعلق به هدف است.

    توضیح بده:
    - چه ASN هایی شناسایی شده و متعلق به چه سازمانی هستند
    - چه پریفیکس های شبکه ای یافت شده و گستردگی زیرساخت چقدر است
    - چه تعداد آی پی جدید متعلق به هدف پیدا شده
    - آیا آی پی های کشف شده می توانند asset های ناشناخته ای را افشا کنند
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