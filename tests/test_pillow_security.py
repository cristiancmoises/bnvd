"""Dependency regressions for image decoding and BNVD's PDF export stack.

Run with: uv run --locked python -m unittest discover -s tests -v
"""

from io import BytesIO
import unittest
import zlib

from flask import Flask
from PIL import Image, ImageFile, PdfParser, UnidentifiedImageError
from reportlab.lib.utils import ImageReader

from export import ExportManager, HAS_REPORTLAB


class PillowSecurityTests(unittest.TestCase):
    def test_png_and_jpeg_decode_and_resize(self):
        for image_format in ("PNG", "JPEG"):
            with self.subTest(image_format=image_format):
                encoded = BytesIO()
                with Image.new("RGB", (32, 24), (24, 96, 160)) as original:
                    original.save(encoded, format=image_format)
                encoded.seek(0)
                with Image.open(encoded) as decoded:
                    decoded.load()
                    self.assertEqual(decoded.size, (32, 24))
                    decoded.thumbnail((16, 16))
                    self.assertEqual(decoded.size, (16, 12))
                    self.assertEqual(decoded.mode, "RGB")

    def test_invalid_image_is_rejected(self):
        with self.assertRaises(UnidentifiedImageError):
            Image.open(BytesIO(b"not an image"))

    def test_pdf_flate_stream_enforces_decompression_limit(self):
        # Pillow 12.3.0 added this limit; the old locked 12.1.1 accepted it.
        # The fixture expands to only ~1 MiB, keeping this regression bounded.
        stream = PdfParser.PdfStream(
            {b"Filter": b"FlateDecode"},
            zlib.compress(b"x" * (ImageFile.SAFEBLOCK + 1)),
        )
        with self.assertRaisesRegex(ValueError, "Decompressed data too large"):
            stream.decode()
        normal = PdfParser.PdfStream(
            {b"Filter": b"FlateDecode"}, zlib.compress(b"normal PDF content")
        )
        self.assertEqual(normal.decode(), b"normal PDF content")

    def test_reportlab_reads_rgba_png(self):
        encoded = BytesIO()
        with Image.new("RGBA", (8, 6), (40, 120, 200, 128)) as original:
            original.save(encoded, format="PNG")
        encoded.seek(0)
        reader = ImageReader(encoded)
        self.assertEqual(reader.getSize(), (8, 6))
        self.assertEqual(len(reader.getRGBData()), 8 * 6 * 3)

    def test_bnvd_pdf_exports_return_pdf_documents(self):
        self.assertTrue(HAS_REPORTLAB, "PDF export must not fall back to text")
        app = Flask(__name__)
        manager = ExportManager()
        vulnerability = {
            "cve": {
                "id": "CVE-2026-0000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Smoke test."}],
            }
        }
        news = {"title": "Security update", "description": "Smoke test."}
        with app.app_context():
            for response in (
                manager.export_vulnerability(vulnerability, "pdf"),
                manager.export_news(news, "pdf"),
            ):
                with self.subTest(content_type=response.content_type):
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.mimetype, "application/pdf")
                    self.assertTrue(response.data.startswith(b"%PDF-"))
                    self.assertTrue(response.data.rstrip().endswith(b"%%EOF"))
                    self.assertGreater(len(response.data), 1000)


if __name__ == "__main__":
    unittest.main()
