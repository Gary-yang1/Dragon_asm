package baiyan

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Sheet struct {
	Name    string
	Headers []string
	Rows    [][]string
}

func writeWorkbook(path string, sheets []Sheet) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	if err := addZipFile(zipWriter, "[Content_Types].xml", buildContentTypes(len(sheets))); err != nil {
		return err
	}
	if err := addZipFile(zipWriter, "_rels/.rels", rootRelsXML); err != nil {
		return err
	}
	if err := addZipFile(zipWriter, "xl/workbook.xml", buildWorkbookXML(sheets)); err != nil {
		return err
	}
	if err := addZipFile(zipWriter, "xl/_rels/workbook.xml.rels", buildWorkbookRelsXML(len(sheets))); err != nil {
		return err
	}
	if err := addZipFile(zipWriter, "xl/styles.xml", stylesXML); err != nil {
		return err
	}

	for index, sheet := range sheets {
		name := fmt.Sprintf("xl/worksheets/sheet%d.xml", index+1)
		if err := addZipFile(zipWriter, name, buildSheetXML(sheet)); err != nil {
			return err
		}
	}
	return nil
}

func addZipFile(zipWriter *zip.Writer, name string, content string) error {
	writer, err := zipWriter.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write([]byte(content))
	return err
}

func buildContentTypes(sheetCount int) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	builder.WriteString(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`)
	builder.WriteString(`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`)
	builder.WriteString(`<Default Extension="xml" ContentType="application/xml"/>`)
	builder.WriteString(`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`)
	builder.WriteString(`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`)
	for i := 1; i <= sheetCount; i++ {
		builder.WriteString(fmt.Sprintf(`<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, i))
	}
	builder.WriteString(`</Types>`)
	return builder.String()
}

func buildWorkbookXML(sheets []Sheet) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	builder.WriteString(`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`)
	for i, sheet := range sheets {
		builder.WriteString(fmt.Sprintf(`<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, xmlEscape(sheet.Name), i+1, i+1))
	}
	builder.WriteString(`</sheets></workbook>`)
	return builder.String()
}

func buildWorkbookRelsXML(sheetCount int) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	builder.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i := 1; i <= sheetCount; i++ {
		builder.WriteString(fmt.Sprintf(`<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, i, i))
	}
	builder.WriteString(fmt.Sprintf(`<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`, sheetCount+1))
	builder.WriteString(`</Relationships>`)
	return builder.String()
}

func buildSheetXML(sheet Sheet) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	builder.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	rows := make([][]string, 0, len(sheet.Rows)+1)
	if len(sheet.Headers) > 0 {
		rows = append(rows, sheet.Headers)
	}
	rows = append(rows, sheet.Rows...)

	for rowIndex, values := range rows {
		row := rowIndex + 1
		builder.WriteString(fmt.Sprintf(`<row r="%d">`, row))
		for colIndex, value := range values {
			cell := fmt.Sprintf("%s%d", excelColumnName(colIndex+1), row)
			builder.WriteString(fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`, cell, xmlEscape(sanitizeExcelValue(value))))
		}
		builder.WriteString(`</row>`)
	}
	builder.WriteString(`</sheetData></worksheet>`)
	return builder.String()
}

func excelColumnName(index int) string {
	if index <= 0 {
		return "A"
	}
	var result []byte
	for index > 0 {
		index--
		result = append([]byte{byte('A' + index%26)}, result...)
		index /= 26
	}
	return string(result)
}

func sanitizeExcelValue(value string) string {
	if value == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		if r == 0x9 || r == 0xA || r == 0xD || r >= 0x20 {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func xmlEscape(value string) string {
	var buffer bytes.Buffer
	if err := xml.EscapeText(&buffer, []byte(value)); err != nil {
		return value
	}
	return buffer.String()
}

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`

const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1">
    <font>
      <sz val="11"/>
      <name val="Calibri"/>
    </font>
  </fonts>
  <fills count="2">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
  </fills>
  <borders count="1">
    <border><left/><right/><top/><bottom/><diagonal/></border>
  </borders>
  <cellStyleXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
  </cellStyleXfs>
  <cellXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
  </cellXfs>
  <cellStyles count="1">
    <cellStyle name="Normal" xfId="0" builtinId="0"/>
  </cellStyles>
</styleSheet>`
