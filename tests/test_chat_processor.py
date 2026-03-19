import asyncio
import unittest

import orjson

from app.services.grok.processor import CollectProcessor


async def _ndjson_lines(payloads):
    for payload in payloads:
        yield orjson.dumps(payload)


class ChatProcessorTests(unittest.TestCase):
    def test_collect_processor_keeps_text_when_generated_image_urls_is_empty_list(self):
        payloads = [
            {
                "result": {
                    "response": {
                        "responseId": "resp-123",
                        "llmInfo": {"modelHash": "fp-1"},
                        "modelResponse": {
                            "generatedImageUrls": [],
                            "message": "你好，这是一条文本回复",
                        },
                    }
                }
            }
        ]

        result = asyncio.run(CollectProcessor("grok-4.1-fast").process(_ndjson_lines(payloads)))

        self.assertEqual(result["id"], "resp-123")
        self.assertEqual(result["system_fingerprint"], "fp-1")
        self.assertEqual(result["choices"][0]["message"]["content"], "你好，这是一条文本回复")
