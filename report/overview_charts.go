package report

import (
	"fmt"
	"path/filepath"

	"github.com/danfaizer/go-chart"
	"github.com/danfaizer/go-chart/drawing"

	"github.com/adevinta/security-overview/utils"
)

func (o *Overview) HandleVulnerabilityPerImpact() error {
	chart.DefaultAlternateColors = []drawing.Color{
		drawing.ColorFromHex("9239ff"), // Critical
		drawing.ColorFromHex("ff3860"), // High
		drawing.ColorFromHex("ff943e"), // Medium
		drawing.ColorFromHex("ffdd57"), // Low
		drawing.ColorFromHex("3273dc"), // Info
	}

	values := o.VulnerabilityPerImpact.Values
	newPieChart := chart.PieChart{
		Width:  350,
		Height: 350,
		Values: values,
		Canvas: chart.Style{
			FillColor: chart.ColorTransparent,
		},
		Background: chart.Style{
			FillColor: chart.ColorTransparent,
			Padding: chart.Box{
				Top:    15,
				Left:   5,
				Right:  5,
				Bottom: 125,
			},
		},
	}

	// generate the ouput image file
	currentImage, err := ChartToBytes(newPieChart)
	if err != nil {
		return err
	}

	currentImageURL, err := utils.GenerateLocalFile(currentImage, o.Proxy, o.Bucket, o.Folder, filepath.Join(o.LocalTempDir, o.ScanID, o.Bucket, o.Folder), "", utils.ExtensionPNG)
	if err != nil {
		return err
	}

	// Update the report with the reference to the chart img
	o.VulnerabilityPerImpact.ImageURL = currentImageURL

	return nil
}

func (o *Overview) HandleVulnerabilityPerAsset() error {
	chart.DefaultAlternateColors = BulmaPalette
	values := o.VulnerabilityPerAsset.Values
	if len(values) > 6 {
		values = values[:6]
	}

	for k := range values {
		// in the cases where a report does not contains any vulnerabilities,
		// the pie chart library will complain about not being able to Generate
		// a chart with only zero values. By putting a 0.01 we can work around
		// this situation.
		if values[k].Value == 0 {
			values[k].Value = 0.01
		}
	}

	newPieChart := chart.PieChart{
		Width:  350,
		Height: 350,
		Values: values,
		Canvas: chart.Style{
			FillColor: chart.ColorTransparent,
		},
		Background: chart.Style{
			FillColor: chart.ColorTransparent,
			Padding: chart.Box{
				Top:    15,
				Left:   5,
				Right:  5,
				Bottom: 125,
			},
		},
	}

	// generate the ouput image file
	currentImage, err := ChartToBytes(newPieChart)
	if err != nil {
		return err
	}

	// Upload the output image to S3 (or save it locally)
	currentImageURL, err := utils.GenerateLocalFile(currentImage, o.Proxy, o.Bucket, o.Folder, filepath.Join(o.LocalTempDir, o.ScanID, o.Bucket, o.Folder), "", utils.ExtensionPNG)
	if err != nil {
		return err
	}

	// Update the report with the reference to the chart img
	o.VulnerabilityPerAsset.ImageURL = currentImageURL

	return nil
}

func (o *Overview) HandleVulnerableAssetsChart() error {
	chart.DefaultAlternateColors = BulmaPalette

	max := 0.0
	for _, v := range o.VulnerableAssetsChart.Values {
		if v > max {
			max = v
		}
	}
	max = max + float64(10-int(max)%10)

	historicalChart := chart.Chart{
		Width:  350,
		Height: 350,
		Canvas: chart.Style{
			FillColor: chart.ColorTransparent,
		},
		Background: chart.Style{
			FillColor: chart.ColorTransparent,
			Padding: chart.Box{
				Top:    30,
				Left:   15,
				Right:  25,
				Bottom: 30,
			},
		},

		XAxis: chart.XAxis{
			Style: chart.Style{
				Show: true, //enables / displays the x-axis
			},
		},
		YAxis: chart.YAxis{
			Style: chart.Style{
				Show: true, //enables / displays the y-axis
			},
			Range: &chart.ContinuousRange{
				Min: 0.0,
				Max: max,
			},
			ValueFormatter: func(v interface{}) string {
				return fmt.Sprintf("%d", int(v.(float64)))
			},
		},
		Series: []chart.Series{
			chart.TimeSeries{
				Name:    "Vulnerable Assets",
				XValues: o.VulnerableAssetsChart.Dates,
				YValues: o.VulnerableAssetsChart.Values,
			},
		},
	}

	//historicalChart.Elements = []chart.Renderable{
	//	chart.LegendLeft(&historicalChart),
	//}

	// generate the ouput image file
	currentImage, err := ChartToBytes(historicalChart)
	if err != nil {
		return err
	}

	// Upload the output image to S3 (or save it locally)
	currentImageURL, err := utils.GenerateLocalFile(currentImage, o.Proxy, o.Bucket, o.Folder, filepath.Join(o.LocalTempDir, o.ScanID, o.Folder), "", utils.ExtensionPNG)
	if err != nil {
		return err
	}

	// Update the report with the reference to the chart img
	o.VulnerableAssetsChart.ImageURL = currentImageURL

	return nil
}

func (o *Overview) HandleImpactLevelChart() error {
	chart.DefaultAlternateColors = BulmaPalette

	historicalChart := chart.Chart{
		Width:  350,
		Height: 350,
		Canvas: chart.Style{
			FillColor: chart.ColorTransparent,
		},
		Background: chart.Style{
			FillColor: chart.ColorTransparent,
			Padding: chart.Box{
				Top:    30,
				Left:   15,
				Right:  25,
				Bottom: 30,
			},
		},

		XAxis: chart.XAxis{
			Style: chart.Style{
				Show: true, //enables / displays the x-axis
			},
		},
		YAxis: chart.YAxis{
			Style: chart.Style{
				Show: true, //enables / displays the y-axis
			},
			Range: &chart.ContinuousRange{
				Min: 0.0,
				Max: 3.0,
			},
			Ticks: []chart.Tick{
				chart.Tick{Label: "None", Value: 0.0},
				chart.Tick{Label: "Low", Value: 1.0},
				chart.Tick{Label: "Medium", Value: 2.0},
				chart.Tick{Label: "High", Value: 3.0},
				chart.Tick{Label: "Critical", Value: 4.0},
			},
		},
		Series: []chart.Series{
			chart.TimeSeries{
				Name:    "Impact Level",
				XValues: o.ImpactLevelChart.Dates,
				YValues: o.ImpactLevelChart.Values,
			},
		},
	}

	//historicalChart.Elements = []chart.Renderable{
	//	chart.LegendLeft(&historicalChart),
	//}

	// generate the ouput image file
	currentImage, err := ChartToBytes(historicalChart)
	if err != nil {
		return err
	}

	// Upload the output image to S3 (or save it locally)
	currentImageURL, err := utils.GenerateLocalFile(currentImage, o.Proxy, o.Bucket, o.Folder, filepath.Join(o.LocalTempDir, o.ScanID, o.Folder), "", utils.ExtensionPNG)
	if err != nil {
		return err
	}

	// Update the report with the reference to the chart img
	o.ImpactLevelChart.ImageURL = currentImageURL

	return nil
}
