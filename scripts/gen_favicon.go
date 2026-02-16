package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

// Draw an anti-aliased line using Xiaolin Wu's algorithm
func drawLineAA(img *image.RGBA, x0, y0, x1, y1 float64, c color.RGBA) {
	steep := math.Abs(y1-y0) > math.Abs(x1-x0)
	if steep {
		x0, y0 = y0, x0
		x1, y1 = y1, x1
	}
	if x0 > x1 {
		x0, x1 = x1, x0
		y0, y1 = y1, y0
	}
	dx := x1 - x0
	dy := y1 - y0
	gradient := dy / dx
	if dx == 0 {
		gradient = 1
	}

	// First endpoint
	xEnd := math.Round(x0)
	yEnd := y0 + gradient*(xEnd-x0)
	xGap := 1 - (x0 + 0.5 - math.Floor(x0+0.5))
	xPx1 := int(xEnd)
	yPx1 := int(math.Floor(yEnd))
	plotAA(img, xPx1, yPx1, (1-(yEnd-math.Floor(yEnd)))*xGap, c, steep)
	plotAA(img, xPx1, yPx1+1, (yEnd-math.Floor(yEnd))*xGap, c, steep)
	intery := yEnd + gradient

	// Second endpoint
	xEnd = math.Round(x1)
	yEnd = y1 + gradient*(xEnd-x1)
	xGap = x1 + 0.5 - math.Floor(x1+0.5)
	xPx2 := int(xEnd)
	yPx2 := int(math.Floor(yEnd))
	plotAA(img, xPx2, yPx2, (1-(yEnd-math.Floor(yEnd)))*xGap, c, steep)
	plotAA(img, xPx2, yPx2+1, (yEnd-math.Floor(yEnd))*xGap, c, steep)

	// Main loop
	for x := xPx1 + 1; x < xPx2; x++ {
		y := int(math.Floor(intery))
		plotAA(img, x, y, 1-(intery-math.Floor(intery)), c, steep)
		plotAA(img, x, y+1, intery-math.Floor(intery), c, steep)
		intery += gradient
	}
}

func plotAA(img *image.RGBA, x, y int, brightness float64, c color.RGBA, steep bool) {
	if steep {
		x, y = y, x
	}
	b := img.Bounds()
	if x < b.Min.X || x >= b.Max.X || y < b.Min.Y || y >= b.Max.Y {
		return
	}
	existing := img.RGBAAt(x, y)
	alpha := uint8(float64(c.A) * brightness)
	// Simple alpha blend
	a := float64(alpha) / 255.0
	nr := uint8(float64(c.R)*a + float64(existing.R)*(1-a))
	ng := uint8(float64(c.G)*a + float64(existing.G)*(1-a))
	nb := uint8(float64(c.B)*a + float64(existing.B)*(1-a))
	na := uint8(math.Min(255, float64(existing.A)+float64(alpha)))
	img.SetRGBA(x, y, color.RGBA{nr, ng, nb, na})
}

func fillCircle(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	for y := int(cy - r - 1); y <= int(cy+r+1); y++ {
		for x := int(cx - r - 1); x <= int(cx+r+1); x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			dist := math.Sqrt(dx*dx+dy*dy) - r
			if dist < -1 {
				blendPixel(img, x, y, c, 1.0)
			} else if dist < 1 {
				alpha := (1 - dist) / 2
				blendPixel(img, x, y, c, alpha)
			}
		}
	}
}

func fillEllipse(img *image.RGBA, cx, cy, rx, ry, angle float64, c color.RGBA) {
	cosA := math.Cos(-angle)
	sinA := math.Sin(-angle)
	maxR := math.Max(rx, ry)
	for y := int(cy - maxR - 2); y <= int(cy+maxR+2); y++ {
		for x := int(cx - maxR - 2); x <= int(cx+maxR+2); x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			// Rotate point into ellipse space
			lx := dx*cosA - dy*sinA
			ly := dx*sinA + dy*cosA
			dist := (lx*lx)/(rx*rx) + (ly*ly)/(ry*ry)
			if dist < 0.85 {
				blendPixel(img, x, y, c, 1.0)
			} else if dist < 1.15 {
				alpha := 1.0 - (dist-0.85)/0.3
				blendPixel(img, x, y, c, alpha)
			}
		}
	}
}

func blendPixel(img *image.RGBA, x, y int, c color.RGBA, alpha float64) {
	b := img.Bounds()
	if x < b.Min.X || x >= b.Max.X || y < b.Min.Y || y >= b.Max.Y {
		return
	}
	existing := img.RGBAAt(x, y)
	a := alpha * float64(c.A) / 255.0
	nr := uint8(float64(c.R)*a + float64(existing.R)*(1-a))
	ng := uint8(float64(c.G)*a + float64(existing.G)*(1-a))
	nb := uint8(float64(c.B)*a + float64(existing.B)*(1-a))
	na := uint8(math.Min(255, float64(existing.A)+float64(alpha)*float64(c.A)/255.0*255+float64(existing.A)*(1-a)))
	img.SetRGBA(x, y, color.RGBA{nr, ng, nb, na})
}

// Draw a thick anti-aliased line
func drawThickLine(img *image.RGBA, x0, y0, x1, y1, thickness float64, c color.RGBA) {
	dx := x1 - x0
	dy := y1 - y0
	length := math.Sqrt(dx*dx + dy*dy)
	if length == 0 {
		return
	}
	// Normal perpendicular to line
	nx := -dy / length * thickness / 2
	ny := dx / length * thickness / 2
	steps := int(thickness) + 2
	for i := 0; i <= steps; i++ {
		t := float64(i)/float64(steps) - 0.5
		ox := nx * t * 2
		oy := ny * t * 2
		drawLineAA(img, x0+ox, y0+oy, x1+ox, y1+oy, c)
	}
}

func drawQuillAndInk32(img *image.RGBA) {
	// Colors
	inkBlack := color.RGBA{30, 30, 40, 255}
	inkDark := color.RGBA{20, 20, 30, 255}
	quillShaft := color.RGBA{180, 150, 100, 255}
	quillDark := color.RGBA{140, 110, 70, 255}
	vaneLight := color.RGBA{220, 210, 190, 255}
	vaneDark := color.RGBA{170, 155, 130, 255}
	inkWellBody := color.RGBA{50, 45, 55, 255}
	inkWellHighlight := color.RGBA{80, 75, 90, 255}
	inkSurface := color.RGBA{25, 25, 60, 255}
	inkDropColor := color.RGBA{20, 20, 50, 255}

	// === INKWELL (bottom right area) ===
	// Body - a squat jar shape
	fillEllipse(img, 21, 24, 8, 5, 0, inkWellBody)
	// Top rim
	fillEllipse(img, 21, 20, 7, 2.5, 0, inkWellHighlight)
	// Ink surface visible in opening
	fillEllipse(img, 21, 20, 5.5, 1.8, 0, inkSurface)

	// === QUILL (diagonal from top-right to inkwell) ===
	// Main shaft - from top-left area down to inkwell
	drawThickLine(img, 5, 3, 19, 21, 1.8, quillShaft)
	drawThickLine(img, 5, 3, 19, 21, 1.0, quillDark)

	// Nib (bottom of quill, dipping into ink)
	drawThickLine(img, 19, 21, 21, 24, 1.2, inkDark)
	// Nib split
	drawLineAA(img, 19.5, 21, 22, 25, inkBlack)

	// === FEATHER VANES ===
	// Left vane barbs
	for i := 0; i < 8; i++ {
		t := float64(i) / 8.0
		// Point on shaft
		sx := 5 + t*10
		sy := 3 + t*13
		// Barb going left/up from shaft
		angle := -math.Pi/2.5 + t*0.3
		bLen := 4.0 - t*2.5
		bx := sx + math.Cos(angle)*bLen
		by := sy + math.Sin(angle)*bLen
		c := vaneLight
		if i%2 == 0 {
			c = vaneDark
		}
		drawLineAA(img, sx, sy, bx, by, c)
	}
	// Right vane barbs
	for i := 0; i < 8; i++ {
		t := float64(i) / 8.0
		sx := 5 + t*10
		sy := 3 + t*13
		angle := math.Pi/6 + t*0.2
		bLen := 3.5 - t*2.0
		bx := sx + math.Cos(angle)*bLen
		by := sy + math.Sin(angle)*bLen
		c := vaneLight
		if i%2 == 1 {
			c = vaneDark
		}
		drawLineAA(img, sx, sy, bx, by, c)
	}

	// === INK DROPS ===
	fillCircle(img, 14, 27, 1.2, inkDropColor)
	fillCircle(img, 11, 29, 0.8, inkDropColor)
}

// Write ICO file with a single 32x32 PNG image
func writeICO(w *bytes.Buffer, img *image.RGBA) {
	// Encode PNG
	var pngBuf bytes.Buffer
	png.Encode(&pngBuf, img)
	pngData := pngBuf.Bytes()

	// ICO header
	binary.Write(w, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(w, binary.LittleEndian, uint16(1)) // ICO type
	binary.Write(w, binary.LittleEndian, uint16(1)) // 1 image

	// ICO directory entry
	w.WriteByte(32)                                            // width
	w.WriteByte(32)                                            // height
	w.WriteByte(0)                                             // color palette
	w.WriteByte(0)                                             // reserved
	binary.Write(w, binary.LittleEndian, uint16(1))            // color planes
	binary.Write(w, binary.LittleEndian, uint16(32))           // bits per pixel
	binary.Write(w, binary.LittleEndian, uint32(len(pngData))) // size
	binary.Write(w, binary.LittleEndian, uint32(22))           // offset (6 header + 16 entry)

	// PNG data
	w.Write(pngData)
}

func main() {
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))

	// Transparent background
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			img.SetRGBA(x, y, color.RGBA{0, 0, 0, 0})
		}
	}

	drawQuillAndInk32(img)

	var buf bytes.Buffer
	writeICO(&buf, img)

	os.WriteFile(os.Args[1], buf.Bytes(), 0644)
}
