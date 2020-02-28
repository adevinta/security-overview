package report

import (
	"bufio"
	"bytes"
	"errors"

	"github.com/danfaizer/go-chart"
	"github.com/danfaizer/go-chart/drawing"
)

// Material design color palette, according to:
// http://htmlcolorcodes.com/color-chart/
var (
	ColorRed        = drawing.ColorFromHex("f44336")
	ColorPurple     = drawing.ColorFromHex("9c27b0")
	ColorIndigo     = drawing.ColorFromHex("3f51b5")
	ColorLightBlue  = drawing.ColorFromHex("03a9f4")
	ColorTeal       = drawing.ColorFromHex("009688")
	ColorLightGreen = drawing.ColorFromHex("8bc34a")
	ColorYellow     = drawing.ColorFromHex("ffeb3b")
	ColorOrange     = drawing.ColorFromHex("ff9800")

	ColorPink       = drawing.ColorFromHex("e91e63")
	ColorDeepPurple = drawing.ColorFromHex("673ab7")
	ColorBlue       = drawing.ColorFromHex("2196f3")
	ColorCyan       = drawing.ColorFromHex("00bcd4")
	ColorGreen      = drawing.ColorFromHex("4caf50")
	ColorLime       = drawing.ColorFromHex("cddc39")
	ColorAmber      = drawing.ColorFromHex("ffc107")
	ColorDeepOrange = drawing.ColorFromHex("ff5722")
	ColorGrey       = drawing.ColorFromHex("9e9e9e")

	ColorBrown    = drawing.ColorFromHex("795548")
	ColorBlueGrey = drawing.ColorFromHex("607d8b")
	ColorWhite    = drawing.ColorFromHex("ffffff")
	ColorBlack    = drawing.ColorFromHex("000000")

	MaterialPalette = []drawing.Color{
		ColorRed,
		ColorPurple,
		ColorIndigo,
		ColorLightBlue,
		ColorTeal,
		ColorLightGreen,
		ColorYellow,
		ColorOrange,

		ColorPink,
		ColorDeepPurple,
		ColorBlue,
		ColorCyan,
		ColorGreen,
		ColorLime,
		ColorAmber,
		ColorDeepOrange,
		ColorGrey,

		ColorBrown,
		ColorBlueGrey,
		ColorWhite,
		ColorBlack,
	}

	BulmaPalette = []drawing.Color{
		drawing.ColorFromHex("00D1B2"), // Teal
		drawing.ColorFromHex("3273DC"), // Blue
		drawing.ColorFromHex("23D160"), // Green
		drawing.ColorFromHex("FFDD57"), // Yellow
		drawing.ColorFromHex("FF3860"), // Red
		drawing.ColorFromHex("363636"), // Black
	}
)

func ChartToBytes(v interface{}) ([]byte, error) {
	var err error
	var chartBuffer bytes.Buffer
	chartWriter := bufio.NewWriter(&chartBuffer)

	switch c := v.(type) {
	case chart.Chart:
		err = c.Render(chart.PNG, chartWriter)
	case chart.PieChart:
		err = c.Render(chart.PNG, chartWriter)
	case chart.StackedBarChart:
		err = c.Render(chart.PNG, chartWriter)
	case chart.BarChart:
		err = c.Render(chart.PNG, chartWriter)
	default:
		err = errors.New("error rendering chart of unknown type")
	}
	if err != nil {
		return []byte{}, err
	}

	err = chartWriter.Flush()
	if err != nil {
		return []byte{}, err
	}

	return chartBuffer.Bytes(), nil
}

func RiskToActionString(risk int) string {
	switch risk {
	case 0:
		return "NO ACTION REQUIRED"
	case 1:
		return "ACTION SUGGESTED"
	case 2:
		return "ACTION SUGGESTED"
	case 3:
		return "ACTION REQUIRED"
	case 4:
		return "ACTION REQUIRED"
	default:
		return "UNKNOWN RISK"
	}
}
