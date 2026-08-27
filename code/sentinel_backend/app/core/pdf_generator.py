"""
PDF 审计报告生成器
使用 ReportLab 生成可下载的 PDF 格式漏洞审计报告。
此模块负责将数据库中的审计结果序列化为 PDF 字节流，
供 GET /api/v1/tasks/{task_id}/export-pdf 接口调用。

执行手册出处：
  ML 同学 B 任务分配 → "PDF 报告导出：使用 WeasyPrint 或 ReportLab 生成可下载的 PDF 审计报告"
  页面三顶部概览卡片 → "下载 PDF 按钮"
"""
import io
from datetime import UTC, datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.component_risk import Severity
from app.models.task import Task
from app.models.vulnerability import VerifyStatus

# ── 中文字体注册 ──────────────────────────────────────────────────────────────
# Prefer an embedded open-source CJK font. CID fonts rely on viewer-side font
# substitution and can create visibly broken Latin spacing in mixed text.
_CJK_FONT = "Helvetica"        # 西文/默认回退
_CJK_FONT_BOLD = "Helvetica-Bold"
_MONO_FONT = "Courier"

try:
    font_candidates = (
        Path("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"),
        Path("C:/Windows/Fonts/msyh.ttc"),
        Path("C:/Windows/Fonts/simhei.ttf"),
    )
    font_path = next(path for path in font_candidates if path.is_file())
    pdfmetrics.registerFont(TTFont("SentinelCJK", str(font_path), subfontIndex=0))
    _CJK_FONT = "SentinelCJK"
    _CJK_FONT_BOLD = "SentinelCJK"
except Exception:
    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        _CJK_FONT = "STSong-Light"
        _CJK_FONT_BOLD = "STSong-Light"
    except Exception:
        pass

# ── 颜色常量（来自执行手册配色规范） ────────────────────────────────────────────
# Frontend report palette: warm paper, obsidian text, restrained orange accents.
COLOR_DARK_BLUE = colors.HexColor("#0E0D0B")
COLOR_ACCENT    = colors.HexColor("#FF6B35")
COLOR_SUCCESS   = colors.HexColor("#1D8A56")
COLOR_DANGER    = colors.HexColor("#C93B2A")
COLOR_MID       = colors.HexColor("#CF7D1E")
COLOR_LIGHT_BG  = colors.HexColor("#F7F4F0")
COLOR_PAPER     = colors.HexColor("#FDFCFC")
COLOR_BORDER    = colors.HexColor("#E8E4DE")
COLOR_MUTED     = colors.HexColor("#7A7168")

# ── 危险等级颜色映射 ──────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    Severity.CRITICAL: COLOR_DANGER,
    Severity.HIGH:     COLOR_ACCENT,
    Severity.MEDIUM:   COLOR_MID,
    Severity.LOW:      COLOR_SUCCESS,
    Severity.UNKNOWN:  colors.grey,
}

# ── 验证状态文字映射 ──────────────────────────────────────────────────────────
VERIFY_STATUS_LABELS = {
    VerifyStatus.CONFIRMED:     "已确认",
    VerifyStatus.UNVERIFIED:    "待验证",
    VerifyStatus.NOT_REPRODUCED: "当前预算内未复现",
    VerifyStatus.FALSE_POSITIVE: "已排除",
}


def _get_styles():
    """构建 PDF 样式表（使用 CJK 字体 STSong-Light，确保中文不乱码）"""
    base = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SentinelTitle",
        parent=base["Title"],
        fontName=_CJK_FONT_BOLD,
        fontSize=20,
        leading=25,
        textColor=COLOR_DARK_BLUE,
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "SentinelSubtitle",
        parent=base["Normal"],
        fontName=_CJK_FONT,
        fontSize=11,
        textColor=COLOR_MUTED,
        alignment=TA_CENTER,
        spaceAfter=16,
    )
    section_style = ParagraphStyle(
        "SentinelSection",
        parent=base["Heading2"],
        fontName=_CJK_FONT_BOLD,
        fontSize=14,
        leading=19,
        textColor=COLOR_DARK_BLUE,
        spaceBefore=18,
        spaceAfter=8,
        borderPad=0,
    )
    body_style = ParagraphStyle(
        "SentinelBody",
        parent=base["Normal"],
        fontName=_CJK_FONT,
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#3F3933"),
    )
    meta_style = ParagraphStyle(
        "SentinelMeta",
        parent=base["Normal"],
        fontName=_CJK_FONT,
        fontSize=8,
        textColor=COLOR_MUTED,
        alignment=TA_LEFT,
    )
    code_style = ParagraphStyle(
        "SentinelCode",
        parent=base["Code"],
        fontName=_MONO_FONT,
        fontSize=7.5,
        leading=11,
        backColor=colors.HexColor("#F8F6F3"),
        textColor=COLOR_DARK_BLUE,
        borderPad=6,
        leftIndent=6,
        rightIndent=6,
    )
    return {
        "title":    title_style,
        "subtitle": subtitle_style,
        "section":  section_style,
        "body":     body_style,
        "meta":     meta_style,
        "code":     code_style,
    }


def _severity_badge(severity: Severity) -> str:
    """返回带颜色标注的危险等级文字（ReportLab XML 格式）"""
    label_map = {
        Severity.CRITICAL: "严重",
        Severity.HIGH:     "高危",
        Severity.MEDIUM:   "中危",
        Severity.LOW:      "低危",
        Severity.UNKNOWN:  "未知",
    }
    color_map = {
        Severity.CRITICAL: "#D9534F",
        Severity.HIGH:     "#EF9F27",
        Severity.MEDIUM:   "#E8A838",
        Severity.LOW:      "#1D9E75",
        Severity.UNKNOWN:  "#888888",
    }
    label = label_map.get(severity, "未知")
    color = color_map.get(severity, "#888888")
    return f'<font color="{color}"><b>[{label}]</b></font>'


def _display_unknown(value: str | None) -> str:
    """把接口/数据库里的英文占位值统一转换成中文展示。"""
    normalized = (value or "").strip()
    return "未知" if not normalized or normalized.lower() == "unknown" else normalized


def _severity_label(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "严重",
        Severity.HIGH: "高危",
        Severity.MEDIUM: "中危",
        Severity.LOW: "低危",
        Severity.UNKNOWN: "未知",
    }.get(severity, "未知")


def _draw_page(canvas, doc) -> None:
    """Paint the warm report paper and a subtle top accent; intentionally no footer."""
    canvas.saveState()
    canvas.setFillColor(COLOR_PAPER)
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canvas.setFillColor(COLOR_ACCENT)
    canvas.rect(0, A4[1] - 3 * mm, A4[0], 3 * mm, fill=1, stroke=0)
    canvas.restoreState()


def generate_audit_pdf(task: Task) -> bytes:
    """
    接收一个已预加载全部关联数据的 Task ORM 对象，
    生成完整的 PDF 审计报告，返回 bytes 字节流。

    调用前提：task.component_risks 和 task.vulnerabilities（含 ebpf_events）
    均已通过 selectinload 预加载完毕。
    """
    buffer = io.BytesIO()
    styles = _get_styles()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title=f"SC-SENTINEL 漏洞审计报告 - {task.project_name}",
        author="SC-SENTINEL System",
        subject="C/C++ 供应链安全审计报告",
    )

    elements = []

    # ════════════════════════════════════════════════════════════════════════════
    # 封面区域
    # ════════════════════════════════════════════════════════════════════════════
    elements.append(Spacer(1, 20 * mm))
    elements.append(Paragraph("SC-SENTINEL", styles["title"]))
    elements.append(Paragraph("C/C++ 开源供应链安全审计报告", styles["subtitle"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT))
    elements.append(Spacer(1, 4 * mm))

    # 报告元信息表格
    created_str = task.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if task.created_at else "N/A"
    completed_str = "N/A"
    total_time_str = "N/A"
    if task.completed_at:
        completed_str = task.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if task.created_at:
            ca = task.created_at
            co = task.completed_at
            if ca.tzinfo is None:
                ca = ca.replace(tzinfo=UTC)
            if co.tzinfo is None:
                co = co.replace(tzinfo=UTC)
            seconds = (co - ca).total_seconds()
            total_time_str = f"{seconds:.1f} 秒"

    unique_components = {
        (_display_unknown(item.library_name), _display_unknown(item.version))
        for item in task.component_risks
    }
    meta_data = [
        ["项目名称", task.project_name],
        ["任务 ID", str(task.id)],
        ["创建时间", created_str],
        ["完成时间", completed_str],
        ["审计耗时", total_time_str],
        ["动态验证", "已开启 ASan / AFL++ / eBPF 联合验证" if task.is_dynamic else "仅静态分析"],
        ["发现漏洞数", str(len(task.vulnerabilities))],
        ["依赖组件数", str(len(unique_components))],
        ["CVE 风险记录", str(len(task.component_risks))],
    ]
    meta_table = Table(meta_data, colWidths=[40 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), COLOR_LIGHT_BG),
        ("TEXTCOLOR",    (0, 0), (0, -1), COLOR_DARK_BLUE),
        ("FONTNAME",     (0, 0), (-1, -1), _CJK_FONT),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("FONTNAME",     (0, 0), (0, -1), _CJK_FONT_BOLD),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ("GRID",         (0, 0), (-1, -1), 0.35, COLOR_BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 8 * mm))

    # A compact executive triage strip gives reviewers the decision context
    # before they reach the detailed evidence cards.
    confirmed_count = sum(1 for item in task.vulnerabilities if item.verify_status == VerifyStatus.CONFIRMED)
    pending_count = sum(1 for item in task.vulnerabilities if item.verify_status == VerifyStatus.UNVERIFIED)
    not_reproduced_count = sum(1 for item in task.vulnerabilities if item.verify_status == VerifyStatus.NOT_REPRODUCED)
    critical_count = sum(1 for item in task.component_risks if item.severity == Severity.CRITICAL)
    triage_data = [
        ["运行时确认", "待复核", "当前未复现", "组件高危记录"],
        [str(confirmed_count), str(pending_count), str(not_reproduced_count), str(critical_count)],
    ]
    triage_table = Table(triage_data, colWidths=[40 * mm] * 4)
    triage_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), _CJK_FONT_BOLD),
        ("FONTNAME", (0, 1), (-1, 1), _CJK_FONT_BOLD),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT_BG),
        ("TEXTCOLOR", (0, 1), (0, 1), COLOR_SUCCESS),
        ("TEXTCOLOR", (1, 1), (1, 1), COLOR_ACCENT),
        ("TEXTCOLOR", (2, 1), (2, 1), COLOR_DARK_BLUE),
        ("TEXTCOLOR", (3, 1), (3, 1), COLOR_DANGER),
        ("GRID", (0, 0), (-1, -1), 0.35, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(Paragraph("审计结论摘要", styles["section"]))
    elements.append(triage_table)
    elements.append(Spacer(1, 6 * mm))

    # ════════════════════════════════════════════════════════════════════════════
    # 一、漏洞详情清单（对应 Agent b-d 输出） - 移到最前面
    # ════════════════════════════════════════════════════════════════════════════
    elements.append(Paragraph("一、漏洞详情清单", styles["section"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
    elements.append(Spacer(1, 2 * mm))

    if task.vulnerabilities:
        for idx, v in enumerate(task.vulnerabilities, start=1):
            # 漏洞标题行
            verify_label = VERIFY_STATUS_LABELS.get(v.verify_status, "未知")
            title_text = (
                f"<b>#{idx} [{v.vuln_type}]</b> &nbsp;&nbsp; "
                f"<font color='#666666'>{v.file_path or 'N/A'}:{v.line_number or 'N/A'}</font> &nbsp;&nbsp; "
                f"验证状态: <b>{verify_label}</b>"
            )
            elements.append(Paragraph(title_text, styles["body"]))

            # 代码片段
            if v.code_context:
                code_text = v.code_context.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                elements.append(Spacer(1, 1 * mm))
                elements.append(Paragraph(f"<pre>{code_text}</pre>", styles["code"]))

            # 触发条件 + 修复建议
            detail_data = []
            if v.trigger_cond:
                detail_data.append(["触发条件", v.trigger_cond])
            if v.fix_advice:
                detail_data.append(["修复建议", v.fix_advice])
            if detail_data:
                detail_table = Table(detail_data, colWidths=[22 * mm, 138 * mm])
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (0, -1), COLOR_LIGHT_BG),
                    ("FONTNAME",      (0, 0), (0, -1), _CJK_FONT_BOLD),
                    ("FONTNAME",      (1, 0), (1, -1), _CJK_FONT),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8),
                    ("GRID",          (0, 0), (-1, -1), 0.35, COLOR_BORDER),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                    ("TOPPADDING",    (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(Spacer(1, 1 * mm))
                elements.append(detail_table)

            # eBPF 事件日志
            if v.ebpf_events:
                elements.append(Spacer(1, 1 * mm))
                elements.append(Paragraph("<b>eBPF 内核事件日志：</b>", styles["body"]))
                ebpf_header = [["时间戳 (ns)", "事件类型", "函数", "内存地址"]]
                ebpf_rows = [
                    [
                        str(e.timestamp),
                        e.event_type.value,
                        e.function_name or "N/A",
                        e.memory_addr or "N/A",
                    ]
                    for e in v.ebpf_events
                ]
                ebpf_table = Table(ebpf_header + ebpf_rows, colWidths=[40 * mm, 35 * mm, 40 * mm, 45 * mm])
                ebpf_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2D2D2D")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8F6F3")),
                    ("TEXTCOLOR",  (0, 1), (-1, -1), colors.HexColor("#5C534A")),
                    # The header contains Chinese labels and must use the
                    # embedded CJK font.  Keep monospace only for data rows.
                    ("FONTNAME",   (0, 0), (-1, 0), _CJK_FONT_BOLD),
                    ("FONTNAME",   (0, 1), (-1, -1), _MONO_FONT),
                    ("FONTSIZE",   (0, 0), (-1, -1), 7),
                    ("GRID",       (0, 0), (-1, -1), 0.3, COLOR_BORDER),
                    ("LEFTPADDING",  (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING",   (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
                ]))
                elements.append(ebpf_table)

            elements.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor("#EEEEEE")))
            elements.append(Spacer(1, 3 * mm))
    else:
        elements.append(Paragraph("本次审计未发现任何漏洞。", styles["body"]))

    elements.append(Spacer(1, 8 * mm))

    # ════════════════════════════════════════════════════════════════════════════
    # 二、第三方组件风险清单（对应 Agent a 输出）
    # ════════════════════════════════════════════════════════════════════════════
    elements.append(Paragraph("二、第三方组件风险清单", styles["section"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
    elements.append(Spacer(1, 2 * mm))

    if task.component_risks:
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.UNKNOWN: 0,
        }
        sorted_risks = sorted(
            task.component_risks,
            key=lambda item: (
                severity_order.get(item.severity, 0),
                item.cvss_score or 0,
                item.cve_id or "",
            ),
            reverse=True,
        )
        displayed_risks = sorted_risks[:30]
        elements.append(Paragraph(
            f"识别到 {len(unique_components)} 个依赖组件、{len(sorted_risks)} 条风险记录；"
            f"以下按严重度展示前 {len(displayed_risks)} 条，完整数据可在交互式报告中查询。",
            styles["body"],
        ))
        elements.append(Spacer(1, 2 * mm))
        comp_header = [["组件名称", "版本", "CVE 编号", "CVSS", "危险等级"]]
        comp_rows = []
        for c in displayed_risks:
            comp_rows.append([
                _display_unknown(c.library_name),
                _display_unknown(c.version),
                c.cve_id or "无",
                f"{c.cvss_score:.1f}" if c.cvss_score else "N/A",
                _severity_label(c.severity),
            ])
        comp_table = Table(
            comp_header + comp_rows,
            colWidths=[45 * mm, 25 * mm, 35 * mm, 18 * mm, 37 * mm],
            repeatRows=1,
        )

        # 动态行颜色：根据危险等级高亮
        row_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK_BLUE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), _CJK_FONT_BOLD),
            ("FONTNAME",   (0, 1), (-1, -1), _CJK_FONT),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.35, COLOR_BORDER),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ]
        for i, c in enumerate(displayed_risks, start=1):
            sev_color = SEVERITY_COLORS.get(c.severity, colors.grey)
            row_styles.append(("TEXTCOLOR", (4, i), (4, i), sev_color))
            row_styles.append(("FONTNAME",  (4, i), (4, i), _CJK_FONT_BOLD))

        comp_table.setStyle(TableStyle(row_styles))
        elements.append(comp_table)
    else:
        elements.append(Paragraph("本次审计未识别到第三方组件风险。", styles["body"]))

    elements.append(Spacer(1, 6 * mm))

    doc.build(elements, onFirstPage=_draw_page, onLaterPages=_draw_page)
    return buffer.getvalue()
