/**
 * URL Scan Report Generator
 * Generates professional PDF and Excel reports from scan results
 */

// ============================================================
// PDF GENERATION
// ============================================================
export async function generatePDF(result) {
  const { default: jsPDF } = await import("jspdf");
  await import("jspdf-autotable");

  const doc = new jsPDF("p", "mm", "a4");
  const pw = doc.internal.pageSize.getWidth();
  let y = 15;

  const checkPage = (space = 30) => {
    if (y + space > 280) {
      doc.addPage();
      y = 15;
    }
  };

  // ---- HEADER ----
  doc.setFillColor(8, 11, 30);
  doc.rect(0, 0, pw, 42, "F");

  doc.setTextColor(77, 141, 255);
  doc.setFontSize(20);
  doc.setFont("helvetica", "bold");
  doc.text("AI-NIDS URL Safety Report", 14, 18);

  doc.setFontSize(9);
  doc.setTextColor(143, 150, 184);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 26);
  doc.text(
    `Scan Type: ${result.scanType === "deep" ? "Deep Scan" : "Quick Scan"}`,
    14,
    32
  );
  doc.text(`Scanner Version: 3.0`, 14, 38);

  // Verdict badge
  const vc = result.safe ? [0, 180, 100] : [220, 50, 60];
  doc.setFillColor(...vc);
  doc.roundedRect(pw - 52, 10, 40, 16, 3, 3, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(12);
  doc.setFont("helvetica", "bold");
  doc.text(result.safe ? "SAFE" : "UNSAFE", pw - 40, 21);

  // Risk score badge
  doc.setFillColor(40, 40, 70);
  doc.roundedRect(pw - 52, 30, 40, 10, 2, 2, "F");
  doc.setFontSize(9);
  doc.text(
    `Risk: ${result.riskScore}/100 (${(result.riskLevel || "").toUpperCase()})`,
    pw - 50,
    37
  );

  y = 50;

  // ---- SCANNED URL ----
  doc.setTextColor(40, 40, 60);
  doc.setFontSize(11);
  doc.setFont("helvetica", "bold");
  doc.text("Scanned URL", 14, y);
  y += 6;
  doc.setFontSize(8.5);
  doc.setFont("courier", "normal");
  doc.setTextColor(0, 120, 180);
  const urlLines = doc.splitTextToSize(result.url || "", pw - 28);
  doc.text(urlLines, 14, y);
  y += urlLines.length * 4 + 6;

  // ---- SCAN OVERVIEW TABLE ----
  checkPage(40);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(40, 40, 60);
  doc.text("Scan Overview", 14, y);
  y += 4;

  doc.autoTable({
    startY: y,
    head: [["Property", "Value"]],
    body: [
      ["Risk Score", `${result.riskScore} / 100`],
      ["Risk Level", (result.riskLevel || "").toUpperCase()],
      ["Verdict", result.safe ? "SAFE" : "UNSAFE"],
      [
        "Scan Type",
        result.scanType === "deep" ? "Deep Scan" : "Quick Scan",
      ],
      ["Scan Duration", `${result.scanDuration || "N/A"} ms`],
      ["Total Findings", `${result.findings?.length || 0}`],
      [
        "Critical / High / Medium / Low / Info",
        `${result.finding_summary?.critical || 0} / ${
          result.finding_summary?.high || 0
        } / ${result.finding_summary?.medium || 0} / ${
          result.finding_summary?.low || 0
        } / ${result.finding_summary?.info || 0}`,
      ],
      [
        "Threat Categories",
        (result.categories_detected || []).join(", ") || "None",
      ],
      ["Threats", `${result.threats?.length || 0}`],
      ["Warnings", `${result.warnings?.length || 0}`],
      ["Malware Indicators", `${result.malwareIndicators?.length || 0}`],
      ["Phishing Indicators", `${result.phishingIndicators?.length || 0}`],
    ],
    theme: "striped",
    headStyles: {
      fillColor: [13, 17, 48],
      textColor: [200, 210, 240],
      fontSize: 9,
    },
    styles: { fontSize: 8.5, cellPadding: 3 },
    columnStyles: { 0: { fontStyle: "bold", cellWidth: 55 } },
    margin: { left: 14, right: 14 },
  });
  y = doc.lastAutoTable.finalY + 12;

  // ---- DETAILED FINDINGS ----
  if (result.findings?.length > 0) {
    checkPage(20);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(40, 40, 60);
    doc.text(`Detailed Findings (${result.findings.length})`, 14, y);
    y += 4;

    const rows = result.findings.map((f, i) => [
      i + 1,
      (f.severity || "").toUpperCase(),
      f.category || "",
      f.name || "",
      (f.description || "").substring(0, 150) +
        ((f.description || "").length > 150 ? "..." : ""),
      (f.evidence || "").substring(0, 80) || "-",
      (f.recommendation || "").substring(0, 100) || "-",
      f.risk_points || 0,
    ]);

    doc.autoTable({
      startY: y,
      head: [
        [
          "#",
          "Severity",
          "Category",
          "Finding",
          "Description",
          "Evidence",
          "Recommendation",
          "Pts",
        ],
      ],
      body: rows,
      theme: "striped",
      headStyles: {
        fillColor: [13, 17, 48],
        textColor: [200, 210, 240],
        fontSize: 7,
      },
      styles: {
        fontSize: 6,
        cellPadding: 2,
        overflow: "linebreak",
      },
      columnStyles: {
        0: { cellWidth: 7 },
        1: { cellWidth: 14, fontStyle: "bold" },
        2: { cellWidth: 20 },
        3: { cellWidth: 26 },
        4: { cellWidth: 44 },
        5: { cellWidth: 28 },
        6: { cellWidth: 32 },
        7: { cellWidth: 9 },
      },
      margin: { left: 14, right: 14 },
      didParseCell: (data) => {
        if (data.section === "body" && data.column.index === 1) {
          const sev = (data.cell.raw || "").toLowerCase();
          const colors = {
            critical: [168, 85, 247],
            high: [255, 71, 87],
            medium: [255, 152, 0],
            low: [139, 195, 74],
            info: [77, 141, 255],
          };
          if (colors[sev]) data.cell.styles.textColor = colors[sev];
        }
      },
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ---- THREATS ----
  if (result.threats?.length > 0) {
    checkPage(20);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(220, 50, 60);
    doc.text(`Threats (${result.threats.length})`, 14, y);
    y += 4;

    doc.autoTable({
      startY: y,
      head: [["#", "Threat Description"]],
      body: result.threats.map((t, i) => [i + 1, t]),
      theme: "striped",
      headStyles: {
        fillColor: [100, 20, 20],
        textColor: [255, 200, 200],
      },
      styles: { fontSize: 7.5, cellPadding: 3 },
      columnStyles: { 0: { cellWidth: 10 } },
      margin: { left: 14, right: 14 },
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ---- WARNINGS ----
  if (result.warnings?.length > 0) {
    checkPage(20);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(200, 120, 0);
    doc.text(`Warnings (${result.warnings.length})`, 14, y);
    y += 4;

    doc.autoTable({
      startY: y,
      head: [["#", "Warning Description"]],
      body: result.warnings.map((w, i) => [i + 1, w]),
      theme: "striped",
      headStyles: {
        fillColor: [80, 50, 10],
        textColor: [255, 220, 150],
      },
      styles: { fontSize: 7.5, cellPadding: 3 },
      columnStyles: { 0: { cellWidth: 10 } },
      margin: { left: 14, right: 14 },
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ---- RECOMMENDATIONS ----
  if (result.recommendations?.length > 0) {
    checkPage(20);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(0, 150, 80);
    doc.text(`Recommendations (${result.recommendations.length})`, 14, y);
    y += 4;

    doc.autoTable({
      startY: y,
      head: [["#", "Recommendation"]],
      body: result.recommendations.map((r, i) => [i + 1, r]),
      theme: "striped",
      headStyles: {
        fillColor: [10, 60, 40],
        textColor: [150, 255, 200],
      },
      styles: { fontSize: 7.5, cellPadding: 3 },
      columnStyles: { 0: { cellWidth: 10 } },
      margin: { left: 14, right: 14 },
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ---- MALWARE INDICATORS ----
  if (result.malwareIndicators?.length > 0) {
    checkPage(20);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(220, 50, 60);
    doc.text("Malware Indicators", 14, y);
    y += 4;

    doc.autoTable({
      startY: y,
      head: [["#", "Indicator"]],
      body: result.malwareIndicators.map((m, i) => [i + 1, m]),
      theme: "striped",
      headStyles: { fillColor: [100, 20, 20], textColor: [255, 200, 200] },
      styles: { fontSize: 7.5, cellPadding: 3 },
      columnStyles: { 0: { cellWidth: 10 } },
      margin: { left: 14, right: 14 },
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ---- PHISHING INDICATORS ----
  if (result.phishingIndicators?.length > 0) {
    checkPage(20);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(200, 120, 0);
    doc.text("Phishing Indicators", 14, y);
    y += 4;

    doc.autoTable({
      startY: y,
      head: [["#", "Indicator"]],
      body: result.phishingIndicators.map((p, i) => [i + 1, p]),
      theme: "striped",
      headStyles: { fillColor: [80, 50, 10], textColor: [255, 220, 150] },
      styles: { fontSize: 7.5, cellPadding: 3 },
      columnStyles: { 0: { cellWidth: 10 } },
      margin: { left: 14, right: 14 },
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ---- TECHNICAL DETAILS ----
  checkPage(30);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(40, 40, 60);
  doc.text("Technical Details", 14, y);
  y += 4;

  const techRows = [];
  const a = result.analysis || {};

  if (a.domain) {
    techRows.push(["Domain", "Name", a.domain.name || "N/A"]);
    techRows.push(["Domain", "Is IP", a.domain.is_ip ? "Yes" : "No"]);
    techRows.push([
      "Domain",
      "Suspicious TLD",
      a.domain.suspicious_tld ? "Yes" : "No",
    ]);
    techRows.push([
      "Domain",
      "Subdomains",
      `${a.domain.subdomain_count || 0}`,
    ]);
    techRows.push([
      "Domain",
      "Resolved IP",
      a.domain.resolved_ip || "N/A",
    ]);
  }
  if (a.ssl) {
    techRows.push(["SSL", "Protocol", a.ssl.protocol || "N/A"]);
    techRows.push([
      "SSL",
      "Valid",
      a.ssl.valid === true
        ? "Yes"
        : a.ssl.valid === false
        ? "No"
        : "Unknown",
    ]);
    techRows.push(["SSL", "Issuer", a.ssl.issuer || "N/A"]);
    techRows.push(["SSL", "Expires", a.ssl.expires || "N/A"]);
  }
  if (a.headers) {
    techRows.push(["Headers", "Status", `${a.headers.status_code || "N/A"}`]);
    techRows.push(["Headers", "Server", a.headers.server || "N/A"]);
    techRows.push([
      "Headers",
      "Security Present",
      (a.headers.security_headers_present || []).join(", ") || "None",
    ]);
    techRows.push([
      "Headers",
      "Security Missing",
      (a.headers.security_headers_missing || []).join(", ") || "None",
    ]);
  }
  if (a.scripts && a.scripts.total !== undefined) {
    techRows.push(["Scripts", "Total", `${a.scripts.total}`]);
    techRows.push(["Scripts", "External", `${a.scripts.external}`]);
    techRows.push(["Scripts", "Inline", `${a.scripts.inline}`]);
    techRows.push([
      "Scripts",
      "Obfuscation",
      `${a.scripts.obfuscation_score || 0}`,
    ]);
    techRows.push([
      "Scripts",
      "Cryptominer",
      a.scripts.cryptominer_detected ? "DETECTED" : "None",
    ]);
  }
  if (a.redirects) {
    techRows.push(["Redirects", "Count", `${a.redirects.count}`]);
    techRows.push(["Redirects", "Final URL", a.redirects.final_url || "N/A"]);
  }
  if (a.forms && a.forms.total !== undefined) {
    techRows.push(["Forms", "Total", `${a.forms.total}`]);
    techRows.push([
      "Forms",
      "Password Fields",
      `${a.forms.password_fields || 0}`,
    ]);
  }
  if (a.iframes && a.iframes.total !== undefined) {
    techRows.push(["Iframes", "Total", `${a.iframes.total}`]);
    techRows.push([
      "Iframes",
      "Hidden",
      `${a.iframes.hidden_count || 0}`,
    ]);
  }

  if (techRows.length > 0) {
    doc.autoTable({
      startY: y,
      head: [["Section", "Property", "Value"]],
      body: techRows,
      theme: "striped",
      headStyles: {
        fillColor: [13, 17, 48],
        textColor: [200, 210, 240],
        fontSize: 8,
      },
      styles: { fontSize: 7.5, cellPadding: 2.5 },
      columnStyles: {
        0: { cellWidth: 25, fontStyle: "bold" },
        1: { cellWidth: 35 },
      },
      margin: { left: 14, right: 14 },
    });
  }

  // ---- FOOTER ON ALL PAGES ----
  const pages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(143, 150, 184);
    doc.text(
      `AI-NIDS URL Safety Report — Page ${i} of ${pages} — ${new Date().toLocaleString()}`,
      pw / 2,
      292,
      { align: "center" }
    );
  }

  const filename = `url-scan-${result.riskLevel}-${Date.now()}.pdf`;
  doc.save(filename);
  return filename;
}

// ============================================================
// EXCEL GENERATION
// ============================================================
export async function generateExcel(result) {
  const XLSX = await import("xlsx");
  const { saveAs } = await import("file-saver");

  const wb = XLSX.utils.book_new();

  // Sheet 1: Overview
  const overview = [
    ["AI-NIDS URL Safety Report"],
    [],
    ["Property", "Value"],
    ["URL", result.url],
    ["Scan Date", new Date(result.timestamp || Date.now()).toLocaleString()],
    ["Risk Score", `${result.riskScore} / 100`],
    ["Risk Level", (result.riskLevel || "").toUpperCase()],
    ["Verdict", result.safe ? "SAFE" : "UNSAFE"],
    [
      "Scan Type",
      result.scanType === "deep" ? "Deep Scan" : "Quick Scan",
    ],
    ["Scan Duration (ms)", result.scanDuration || "N/A"],
    [],
    ["Finding Summary"],
    ["Total Findings", result.findings?.length || 0],
    ["Critical", result.finding_summary?.critical || 0],
    ["High", result.finding_summary?.high || 0],
    ["Medium", result.finding_summary?.medium || 0],
    ["Low", result.finding_summary?.low || 0],
    ["Info", result.finding_summary?.info || 0],
    [],
    ["Threat Categories", (result.categories_detected || []).join(", ")],
    ["Total Threats", result.threats?.length || 0],
    ["Total Warnings", result.warnings?.length || 0],
    ["Malware Indicators", result.malwareIndicators?.length || 0],
    ["Phishing Indicators", result.phishingIndicators?.length || 0],
    [],
    ["Domain Info"],
    ["Domain", result.analysis?.domain?.name || "N/A"],
    ["Is IP Address", result.analysis?.domain?.is_ip ? "Yes" : "No"],
    [
      "Suspicious TLD",
      result.analysis?.domain?.suspicious_tld ? "Yes" : "No",
    ],
    ["Resolved IP", result.analysis?.domain?.resolved_ip || "N/A"],
    [
      "Trusted Domain",
      result.analysis?.reputation?.trusted ? "Yes" : "No",
    ],
    [],
    ["SSL/TLS"],
    ["Protocol", result.analysis?.ssl?.protocol || "N/A"],
    [
      "Certificate Valid",
      result.analysis?.ssl?.valid === true
        ? "Yes"
        : result.analysis?.ssl?.valid === false
        ? "No"
        : "Unknown",
    ],
    ["Issuer", result.analysis?.ssl?.issuer || "N/A"],
    ["Expires", result.analysis?.ssl?.expires || "N/A"],
  ];

  const ws1 = XLSX.utils.aoa_to_sheet(overview);
  ws1["!cols"] = [{ wch: 25 }, { wch: 80 }];
  XLSX.utils.book_append_sheet(wb, ws1, "Overview");

  // Sheet 2: Findings
  if (result.findings?.length > 0) {
    const hdr = [
      "#",
      "Severity",
      "Category",
      "Finding",
      "Description",
      "Evidence",
      "Recommendation",
      "Risk Points",
    ];
    const rows = result.findings.map((f, i) => [
      i + 1,
      (f.severity || "").toUpperCase(),
      f.category || "",
      f.name || "",
      f.description || "",
      f.evidence || "",
      f.recommendation || "",
      f.risk_points || 0,
    ]);
    const ws2 = XLSX.utils.aoa_to_sheet([hdr, ...rows]);
    ws2["!cols"] = [
      { wch: 5 },
      { wch: 10 },
      { wch: 18 },
      { wch: 35 },
      { wch: 70 },
      { wch: 40 },
      { wch: 50 },
      { wch: 10 },
    ];
    XLSX.utils.book_append_sheet(wb, ws2, "Findings");
  }

  // Sheet 3: Threats
  if (result.threats?.length > 0) {
    const rows = [["#", "Threat"]];
    result.threats.forEach((t, i) => rows.push([i + 1, t]));
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws["!cols"] = [{ wch: 5 }, { wch: 100 }];
    XLSX.utils.book_append_sheet(wb, ws, "Threats");
  }

  // Sheet 4: Warnings
  if (result.warnings?.length > 0) {
    const rows = [["#", "Warning"]];
    result.warnings.forEach((w, i) => rows.push([i + 1, w]));
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws["!cols"] = [{ wch: 5 }, { wch: 100 }];
    XLSX.utils.book_append_sheet(wb, ws, "Warnings");
  }

  // Sheet 5: Recommendations
  if (result.recommendations?.length > 0) {
    const rows = [["#", "Recommendation"]];
    result.recommendations.forEach((r, i) => rows.push([i + 1, r]));
    const ws = XLSX.utils.aoa_to_sheet(rows);
    ws["!cols"] = [{ wch: 5 }, { wch: 100 }];
    XLSX.utils.book_append_sheet(wb, ws, "Recommendations");
  }

  // Sheet 6: Indicators
  const indRows = [["Type", "#", "Indicator"]];
  (result.malwareIndicators || []).forEach((m, i) =>
    indRows.push(["Malware", i + 1, m])
  );
  (result.phishingIndicators || []).forEach((p, i) =>
    indRows.push(["Phishing", i + 1, p])
  );
  if (indRows.length > 1) {
    const ws = XLSX.utils.aoa_to_sheet(indRows);
    ws["!cols"] = [{ wch: 12 }, { wch: 5 }, { wch: 80 }];
    XLSX.utils.book_append_sheet(wb, ws, "Indicators");
  }

  // Sheet 7: Technical
  const techRows = [["Section", "Property", "Value"]];
  const a = result.analysis || {};

  if (a.headers) {
    techRows.push(["Headers", "Status Code", a.headers.status_code]);
    techRows.push(["Headers", "Content Type", a.headers.content_type]);
    techRows.push(["Headers", "Server", a.headers.server]);
    techRows.push([
      "Headers",
      "Security Present",
      (a.headers.security_headers_present || []).join(", "),
    ]);
    techRows.push([
      "Headers",
      "Security Missing",
      (a.headers.security_headers_missing || []).join(", "),
    ]);
  }
  if (a.scripts && a.scripts.total !== undefined) {
    techRows.push(["Scripts", "Total", a.scripts.total]);
    techRows.push(["Scripts", "External", a.scripts.external]);
    techRows.push(["Scripts", "Inline", a.scripts.inline]);
    techRows.push([
      "Scripts",
      "Obfuscation Score",
      a.scripts.obfuscation_score,
    ]);
    techRows.push([
      "Scripts",
      "Cryptominer",
      a.scripts.cryptominer_detected ? "DETECTED" : "None",
    ]);
  }
  if (a.redirects) {
    techRows.push(["Redirects", "Count", a.redirects.count]);
    techRows.push(["Redirects", "Final URL", a.redirects.final_url]);
  }
  if (a.forms && a.forms.total !== undefined) {
    techRows.push(["Forms", "Total", a.forms.total]);
    techRows.push(["Forms", "Password Fields", a.forms.password_fields]);
    techRows.push([
      "Forms",
      "Suspicious",
      a.forms.suspicious?.length || 0,
    ]);
  }
  if (a.iframes && a.iframes.total !== undefined) {
    techRows.push(["Iframes", "Total", a.iframes.total]);
    techRows.push(["Iframes", "Hidden", a.iframes.hidden_count || 0]);
  }
  if (a.content) {
    techRows.push(["Content", "Links", a.content.links]);
    techRows.push([
      "Content",
      "External Domains",
      a.content.external_domain_count,
    ]);
    techRows.push(["Content", "Phishing Score", a.content.phishing_score]);
  }

  if (techRows.length > 1) {
    const ws = XLSX.utils.aoa_to_sheet(techRows);
    ws["!cols"] = [{ wch: 15 }, { wch: 25 }, { wch: 70 }];
    XLSX.utils.book_append_sheet(wb, ws, "Technical");
  }

  const filename = `url-scan-${result.riskLevel}-${Date.now()}.xlsx`;
  const wbout = XLSX.write(wb, { bookType: "xlsx", type: "array" });
  saveAs(
    new Blob([wbout], { type: "application/octet-stream" }),
    filename
  );
  return filename;
}