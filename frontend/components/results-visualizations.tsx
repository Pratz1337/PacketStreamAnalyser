"use client"

import { useEffect, useRef, useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Loader2 } from "lucide-react"

interface ResultsVisualizationsProps {
  results: any
  plots?: { plot1: string; plot2: string } | null
}

export default function ResultsVisualizations({ results, plots }: ResultsVisualizationsProps) {
  const [activeTab, setActiveTab] = useState("distribution")
  const distributionChartRef = useRef<HTMLCanvasElement>(null)
  const confidenceChartRef = useRef<HTMLCanvasElement>(null)
  const timelineChartRef = useRef<HTMLCanvasElement>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // If we have backend-generated plots, we don't need to render our own
    if (plots) {
      setLoading(false)
      return
    }

    // Simulate loading charts
    const timer = setTimeout(() => {
      setLoading(false)
      renderCharts()
    }, 500)

    return () => clearTimeout(timer)
  }, [results, plots])

  const renderCharts = () => {
    // Skip rendering if we have backend plots
    if (plots) return

    // In a real application, you would use a charting library like Chart.js
    // For this demo, we'll draw simple canvas visualizations

    // Distribution Chart
    if (distributionChartRef.current) {
      const ctx = distributionChartRef.current.getContext("2d")
      if (ctx) {
        ctx.clearRect(0, 0, distributionChartRef.current.width, distributionChartRef.current.height)

        const colors = {
          "Normal Traffic": "#10b981",
          DoS: "#ef4444",
          DDoS: "#f97316",
          "Port Scan": "#8b5cf6",
          "Brute Force": "#ec4899",
        }

        const breakdown = results.breakdown
        const total = breakdown.reduce((sum: number, item: any) => sum + item.count, 0)

        let startAngle = 0
        breakdown.forEach((item: any) => {
          if (item.count === 0) return

          const sliceAngle = (item.count / total) * 2 * Math.PI

          ctx.beginPath()
          ctx.moveTo(150, 100)
          ctx.arc(150, 100, 80, startAngle, startAngle + sliceAngle)
          ctx.closePath()

          // @ts-ignore - colors object may not have the key
          ctx.fillStyle = colors[item.type] || "#64748b"
          ctx.fill()

          // Add label
          const labelAngle = startAngle + sliceAngle / 2
          const labelX = 150 + Math.cos(labelAngle) * 100
          const labelY = 100 + Math.sin(labelAngle) * 100

          ctx.fillStyle = "#ffffff"
          ctx.font = "12px sans-serif"
          ctx.textAlign = "center"
          ctx.fillText(`${item.type}`, labelX, labelY)
          ctx.fillText(`${item.percent.toFixed(1)}%`, labelX, labelY + 15)

          startAngle += sliceAngle
        })
      }
    }

    // Confidence Chart
    if (confidenceChartRef.current) {
      const ctx = confidenceChartRef.current.getContext("2d")
      if (ctx) {
        ctx.clearRect(0, 0, confidenceChartRef.current.width, confidenceChartRef.current.height)

        // Create histogram bins
        const bins = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] // 10 bins from 0 to 1

        results.results.forEach((result: any) => {
          const binIndex = Math.min(9, Math.floor(result.confidence * 10))
          bins[binIndex]++
        })

        const maxBin = Math.max(...bins)
        const barWidth = confidenceChartRef.current.width / bins.length

        // Draw bars
        bins.forEach((count, i) => {
          const barHeight = (count / maxBin) * 150

          ctx.fillStyle = `hsl(${210 + i * 15}, 70%, 50%)`
          ctx.fillRect(i * barWidth, confidenceChartRef.current!.height - barHeight, barWidth - 2, barHeight)

          // Add labels
          ctx.fillStyle = "#ffffff"
          ctx.font = "10px sans-serif"
          ctx.textAlign = "center"
          ctx.fillText(
            `${i * 10}-${(i + 1) * 10}%`,
            i * barWidth + barWidth / 2,
            confidenceChartRef.current!.height - 5,
          )
        })
      }
    }

    // Timeline Chart (for live data)
    if (timelineChartRef.current && results.results.some((r: any) => r.timestamp)) {
      const ctx = timelineChartRef.current.getContext("2d")
      if (ctx) {
        ctx.clearRect(0, 0, timelineChartRef.current.width, timelineChartRef.current.height)

        // Get the last 20 results or fewer
        const timelineData = results.results.slice(-20)

        // Draw timeline
        ctx.strokeStyle = "#64748b"
        ctx.beginPath()
        ctx.moveTo(50, 20)
        ctx.lineTo(50, 180)
        ctx.lineTo(290, 180)
        ctx.stroke()

        // Draw points
        const pointSpacing = 240 / (timelineData.length || 1)

        timelineData.forEach((result: any, i: number) => {
          const x = 50 + i * pointSpacing
          const y = result.is_malicious ? 60 : 140

          ctx.beginPath()
          ctx.arc(x, y, 5, 0, 2 * Math.PI)
          ctx.fillStyle = result.is_malicious ? "#ef4444" : "#10b981"
          ctx.fill()

          // Connect points with lines
          if (i > 0) {
            const prevY = timelineData[i - 1].is_malicious ? 60 : 140
            const prevX = 50 + (i - 1) * pointSpacing

            ctx.beginPath()
            ctx.moveTo(prevX, prevY)
            ctx.lineTo(x, y)
            ctx.strokeStyle = "#64748b"
            ctx.stroke()
          }
        })

        // Add labels
        ctx.fillStyle = "#ffffff"
        ctx.font = "12px sans-serif"
        ctx.textAlign = "right"
        ctx.fillText("Malicious", 45, 60)
        ctx.fillText("Normal", 45, 140)
      }
    }
  }

  return (
    <div className="space-y-4">
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-3">
          <TabsTrigger value="distribution">Traffic Distribution</TabsTrigger>
          <TabsTrigger value="confidence">Confidence Levels</TabsTrigger>
          <TabsTrigger value="timeline">Detection Timeline</TabsTrigger>
        </TabsList>

        <TabsContent value="distribution" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Traffic Type Distribution</CardTitle>
              <CardDescription>Breakdown of different types of network traffic detected</CardDescription>
            </CardHeader>
            <CardContent className="flex justify-center">
              {loading ? (
                <div className="h-[200px] flex items-center justify-center">
                  <Loader2 className="h-8 w-8 animate-spin text-primary" />
                </div>
              ) : plots ? (
                <img src={plots.plot1 || "/placeholder.svg"} alt="Traffic Distribution" className="max-w-full h-auto" />
              ) : (
                <canvas ref={distributionChartRef} width="300" height="200" className="max-w-full" />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="confidence" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Confidence Level Distribution</CardTitle>
              <CardDescription>Histogram of confidence levels for all predictions</CardDescription>
            </CardHeader>
            <CardContent className="flex justify-center">
              {loading ? (
                <div className="h-[200px] flex items-center justify-center">
                  <Loader2 className="h-8 w-8 animate-spin text-primary" />
                </div>
              ) : plots ? (
                <img
                  src={plots.plot2 || "/placeholder.svg"}
                  alt="Confidence Distribution"
                  className="max-w-full h-auto"
                />
              ) : (
                <canvas ref={confidenceChartRef} width="300" height="200" className="max-w-full" />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Detection Timeline</CardTitle>
              <CardDescription>Timeline of normal vs. malicious traffic detections</CardDescription>
            </CardHeader>
            <CardContent className="flex justify-center">
              {loading ? (
                <div className="h-[200px] flex items-center justify-center">
                  <Loader2 className="h-8 w-8 animate-spin text-primary" />
                </div>
              ) : (
                <canvas ref={timelineChartRef} width="300" height="200" className="max-w-full" />
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
