import os
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_RIGHT, TA_LEFT, TA_CENTER
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate
from reportlab.platypus.frames import Frame


def generate_invoice(order) -> bytes:
    from boltmart.config import Config
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CompanyName", parent=styles["Heading1"], fontSize=22,
               textColor=HexColor("#1a56db"), spaceAfter=4))
    styles.add(ParagraphStyle("CompanyDetail", parent=styles["Normal"], fontSize=8,
               textColor=HexColor("#6b7280"), spaceAfter=2))
    styles.add(ParagraphStyle("InvoiceTitle", parent=styles["Heading2"], fontSize=16,
               textColor=HexColor("#111827"), spaceAfter=4))
    styles.add(ParagraphStyle("Label", parent=styles["Normal"], fontSize=9,
               textColor=HexColor("#6b7280")))
    styles.add(ParagraphStyle("Value", parent=styles["Normal"], fontSize=10,
               textColor=HexColor("#111827")))
    styles.add(ParagraphStyle("TableHeader", parent=styles["Normal"], fontSize=9,
               textColor=HexColor("#ffffff")))
    styles.add(ParagraphStyle("TableCell", parent=styles["Normal"], fontSize=9,
               textColor=HexColor("#374151")))
    styles.add(ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7,
               textColor=HexColor("#9ca3af")))

    items = order.get("items", [])
    if isinstance(items, str):
        import json
        items = json.loads(items)

    elements = []

    elements.append(Paragraph("BoltMart", styles["CompanyName"]))
    elements.append(Paragraph("Industrial & Safety Equipment Supply", styles["CompanyDetail"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=HexColor("#e5e7eb")))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("TAX INVOICE", styles["InvoiceTitle"]))
    elements.append(Spacer(1, 8))

    invoice_data = [
        [Paragraph("Invoice #", styles["Label"]), Paragraph(f"INV-{order.get('order_id', 'N/A')[:16]}", styles["Value"])],
        [Paragraph("Order ID", styles["Label"]), Paragraph(str(order.get("order_id", "N/A")), styles["Value"])],
        [Paragraph("Transaction ID", styles["Label"]), Paragraph(str(order.get("transaction_id") or "N/A"), styles["Value"])],
        [Paragraph("Payment Method", styles["Label"]), Paragraph(str(order.get("payment_method", "N/A")).upper(), styles["Value"])],
        [Paragraph("Payment Status", styles["Label"]), Paragraph(str(order.get("payment_status", "N/A")).upper(), styles["Value"])],
        [Paragraph("Invoice Date", styles["Label"]), Paragraph(datetime.now().strftime("%d %b %Y, %I:%M %p"), styles["Value"])],
    ]
    t = Table(invoice_data, colWidths=[110, 280])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 16))

    bill_to = [
        [Paragraph("<b>Bill To:</b>", styles["Label"])],
        [Paragraph(str(order.get("customer_name", "N/A")), styles["Value"])],
        [Paragraph(str(order.get("email", "")), styles["CompanyDetail"])],
        [Paragraph(str(order.get("phone", "")), styles["CompanyDetail"])],
        [Paragraph(f"{order.get('address', '')}, {order.get('city', '')} - {order.get('pincode', '')}", styles["CompanyDetail"])],
    ]
    t2 = Table(bill_to, colWidths=[390])
    t2.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    elements.append(t2)
    elements.append(Spacer(1, 16))

    header_color = HexColor("#1a56db")
    alt_row = HexColor("#f9fafb")
    table_data = [
        [Paragraph("<b>#</b>", styles["TableHeader"]),
         Paragraph("<b>SKU</b>", styles["TableHeader"]),
         Paragraph("<b>Item</b>", styles["TableHeader"]),
         Paragraph("<b>Qty</b>", styles["TableHeader"]),
         Paragraph("<b>Unit Price</b>", styles["TableHeader"]),
         Paragraph("<b>Total</b>", styles["TableHeader"])]
    ]
    for idx, item in enumerate(items, 1):
        table_data.append([
            Paragraph(str(idx), styles["TableCell"]),
            Paragraph(item.get("sku", ""), styles["TableCell"]),
            Paragraph(item.get("name", ""), styles["TableCell"]),
            Paragraph(str(item.get("quantity", 0)), styles["TableCell"]),
            Paragraph(f"\u20b9{item.get('unit_price', 0):,.0f}", styles["TableCell"]),
            Paragraph(f"\u20b9{item.get('line_total', 0):,.0f}", styles["TableCell"]),
        ])

    col_widths = [20, 60, 150, 35, 65, 65]
    t3 = Table(table_data, colWidths=col_widths, repeatRows=1)
    t3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_color),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ALIGN", (2, 1), (2, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [None, alt_row]),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#d1d5db")),
        ("LINEBELOW", (0, 0), (-1, 0), 1, header_color),
    ]))
    elements.append(t3)
    elements.append(Spacer(1, 12))

    total_val = order.get("total_value", 0)
    summary_data = [
        [Paragraph("Subtotal", styles["Label"]), Paragraph(f"\u20b9{total_val:,.0f}", styles["Value"])],
        [Paragraph("GST (18%)", styles["Label"]), Paragraph(f"\u20b9{total_val * 0.18:,.0f}", styles["Value"])],
        [Paragraph("Delivery", styles["Label"]), Paragraph("FREE" if total_val >= 2000 else "\u20b999", styles["Value"])],
    ]
    t4 = Table(summary_data, colWidths=[320, 70])
    t4.setStyle(TableStyle([
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEABOVE", (0, 0), (-1, 0), 0.5, HexColor("#e5e7eb")),
    ]))
    elements.append(t4)

    elements.append(HRFlowable(width="100%", thickness=2, color=HexColor("#1a56db")))
    total_row = [
        [Paragraph("<b>Total Amount</b>", ParagraphStyle("TotalLabel", parent=styles["Label"], fontSize=12)),
         Paragraph(f"<b>\u20b9{total_val:,.0f}</b>", ParagraphStyle("TotalValue", parent=styles["Value"], fontSize=14, alignment=TA_RIGHT))]
    ]
    t5 = Table(total_row, colWidths=[320, 70])
    t5.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t5)

    t6 = Table([[Paragraph(f"Amount in words: <b>{number_to_words(int(total_val))} rupees only</b>", styles["CompanyDetail"])]], colWidths=[390])
    elements.append(t6)
    elements.append(Spacer(1, 20))

    elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#d1d5db")))
    elements.append(Spacer(1, 6))
    footer_text = (
        f"{Config.COMPANY_NAME} | {Config.COMPANY_ADDRESS} | GST: {Config.COMPANY_GST}<br/>"
        "This is a system-generated invoice. For inquiries, contact support@boltmart.in"
    )
    elements.append(Paragraph(footer_text, styles["Footer"]))

    doc.build(elements)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes


def number_to_words(n):
    if n == 0:
        return "Zero"
    ones = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine",
            "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen",
            "Seventeen", "Eighteen", "Nineteen"]
    tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]

    def _convert(num):
        if num < 20:
            return ones[num]
        elif num < 100:
            return tens[num // 10] + (" " + ones[num % 10] if num % 10 else "")
        elif num < 1000:
            return ones[num // 100] + " Hundred" + (" " + _convert(num % 100) if num % 100 else "")
        elif num < 100000:
            return _convert(num // 1000) + " Thousand" + (" " + _convert(num % 1000) if num % 1000 else "")
        elif num < 10000000:
            return _convert(num // 100000) + " Lakh" + (" " + _convert(num % 100000) if num % 100000 else "")
        else:
            return _convert(num // 10000000) + " Crore" + (" " + _convert(num % 10000000) if num % 10000000 else "")

    return _convert(n)