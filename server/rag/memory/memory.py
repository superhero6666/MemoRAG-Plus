import os
from openai import OpenAI
from zhipuai import ZhipuAI

from server.logger.logger_config import my_logger as logger


class Memory:

    # 记忆模型初始化
    def __init__(self) -> None:
        api_key = os.getenv('MEMO_API_KEY')
        self.client = ZhipuAI(api_key=api_key)
        self.model_name = os.getenv('MEMO_GLM_MODEL_NAME')

    # 模型记忆
    def memorize(self,
                 context: str):
        prompt = """
        You are provided with a long article. Read the article carefully. After reading, you will be asked to perform specific tasks based on the content of the article.

        Now, the article begins:
        - **Article Content:** {context}

        The article ends here.

        Next, follow the instructions provided to complete the tasks.""".format(context=context)
        assistant_prompt = """I have read the article. Please provide your question."""

        self.generate(prompt, assistant_prompt, False
                      , False)
        logger.info(
            f"==========\nThe model memorize the context successfully!!\n=========="
        )

    # 模型回忆
    def recall(self,
               query: str) -> str:
        prompt = """
        You are given a question related to the article. To answer it effectively, you need to recall specific details from the article. Your task is to identify and extract one or more specific clue texts from the article that are relevant to the question.

        ### Question: {question}
        ### Instructions:
        1. You have a general understanding of the article. Your task is to generate one or more specific clues that will help in searching for supporting evidence within the article.
        2. The clues are in the form of text spans that will assist in answering the question.
        3. Only output the clues. If there are multiple clues, separate them with a newline.""".format(question=query)

        return self.generate(prompt, "", False, False, False)[0]

    # 模型生成
    def generate(self,
                 prompt: str,
                 assistant_prompt: str,
                 is_streaming: bool = False,
                 is_json: bool = False,
                 is_assistant: bool = False):
        if is_assistant:
            messages = [{
                "role": "user",
                "content": prompt
            },
                {
                    "role": "assistant",
                    "content": assistant_prompt
                }]
        else:
            messages = [{
                "role": "user",
                "content": prompt
            }]
        if is_streaming:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=0,
                # top_p=0.7,
                stream=True)
            return response
        else:
            if is_json:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    response_format={"type": "json_object"},
                    messages=messages,
                    temperature=0,
                    # top_p=0.7,
                    stream=False)
            else:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=0,
                    # top_p=0.7,
                    stream=False)
            return response


memory = Memory()
