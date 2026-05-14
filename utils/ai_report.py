from openai import OpenAI

from utils.database import save_report


client = OpenAI(api_key="YOUR_API_KEY")


def generate_ai_report(module_name, data):

    prompt = f"""
    این خروجی مربوط به ماژول {module_name} است.

    خروجی:
    {data}

    در چند خط کوتاه به فارسی توضیح بده این خروجی چه چیزی را نشان می‌دهد.
    """

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