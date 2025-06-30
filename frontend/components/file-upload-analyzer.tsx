"use client"

import type React from "react"

import { useState } from "react"
import { Upload, FileType, AlertTriangle, CheckCircle, Loader2, Download } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import ResultsTable from "@/components/results-table"
import ResultsVisualizations from "@/components/results-visualizations"
import { uploadFile } from "@/lib/api"

export default function FileUploadAnalyzer() {
  const [file, setFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [results, setResults] = useState<any | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [plots, setPlots] = useState<{ plot1: string; plot2: string } | null>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0] || null
    setFile(selectedFile)
    setError(null)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!file) {
      setError("Please select a CSV file to analyze")
      return
    }

    if (file.type !== "text/csv" && !file.name.endsWith(".csv")) {
      setError("Only CSV files are supported")
      return
    }

    setIsUploading(true)
    setUploadProgress(0)

    // Simulate upload progress
    const progressInterval = setInterval(() => {
      setUploadProgress((prev) => {
        const newProgress = prev + 5
        if (newProgress >= 95) {
          clearInterval(progressInterval)
          return 95
        }
        return newProgress
      })
    }, 100)

    try {
      console.log("Uploading file:", file.name)

      // For testing, use mock data if API is not available
      let response
      
      // Try to upload file to backend
      response = await uploadFile(file)
      console.log("API response:", response)

      // Process the response
      setResults({
        total_count: response.total_count || 0,
        malicious_count: response.malicious_count || 0,
        malicious_percent: response.malicious_percent || 0,
        breakdown: response.breakdown || [],
        results: response.results || [],
      })

      // Set plots if available
      if (response.plot1 && response.plot2) {
        setPlots({
          plot1: `data:image/png;base64,${response.plot1}`,
          plot2: `data:image/png;base64,${response.plot2}`,
        })
      }

      setError(null)
    } catch (err) {
      console.error("Error uploading file:", err)
      setError("Failed to analyze file. Please try again.")
    } finally {
      clearInterval(progressInterval)
      setUploadProgress(100)
      setTimeout(() => {
        setIsUploading(false)
      }, 500)
    }
  }

  const handleDownloadReport = () => {
    // In a real implementation, this would call an API endpoint to generate a report
    if (!results) return

    // Create a simple CSV from the results
    const csvContent = [
      "ID,Prediction,Confidence,Is Malicious",
      ...results.results.map((r: any) => `${r.id},${r.prediction},${r.confidence},${r.is_malicious ? "Yes" : "No"}`),
    ].join("\n")

    // Create a download link
    const blob = new Blob([csvContent], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "traffic_analysis_report.csv"
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-2xl font-bold tracking-tight">File Analysis</h2>
        <p className="text-muted-foreground">Upload a CSV file containing network traffic data for analysis.</p>
      </div>

      {!results ? (
        <form onSubmit={handleSubmit} className="space-y-4">
          <Card className="border-dashed border-2 hover:border-primary/50 transition-colors cursor-pointer">
            <CardContent className="flex flex-col items-center justify-center py-12">
              <input type="file" id="file-upload" className="hidden" onChange={handleFileChange} accept=".csv" />
              <label htmlFor="file-upload" className="cursor-pointer">
                <div className="flex flex-col items-center gap-2 text-center">
                  <div className="p-3 rounded-full bg-primary/10 text-primary">
                    <Upload className="h-6 w-6" />
                  </div>
                  <h3 className="font-medium">Upload CSV File</h3>
                  <p className="text-sm text-muted-foreground max-w-xs">
                    Drag and drop or click to select a CSV file containing network traffic data
                  </p>
                  {file && (
                    <div className="flex items-center gap-2 mt-2 text-sm font-medium text-primary">
                      <FileType className="h-4 w-4" />
                      <span>{file.name}</span>
                    </div>
                  )}
                </div>
              </label>
            </CardContent>
          </Card>

          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {isUploading && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Uploading and analyzing...</span>
                <span>{uploadProgress}%</span>
              </div>
              <Progress value={uploadProgress} className="h-2" />
            </div>
          )}

          <Button type="submit" className="w-full" disabled={!file || isUploading}>
            {isUploading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              "Analyze Traffic"
            )}
          </Button>
        </form>
      ) : (
        <div className="space-y-6">
          <Alert variant={results.malicious_count > 0 ? "destructive" : "default"}>
            {results.malicious_count > 0 ? <AlertTriangle className="h-4 w-4" /> : <CheckCircle className="h-4 w-4" />}
            <AlertTitle>
              {results.malicious_count > 0
                ? `Detected ${results.malicious_count} malicious traffic patterns`
                : "No malicious traffic detected"}
            </AlertTitle>
            <AlertDescription>
              {results.malicious_count > 0
                ? `${results.malicious_percent.toFixed(2)}% of analyzed traffic was flagged as potentially malicious`
                : "All analyzed traffic appears to be normal"}
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {results.breakdown.map((item: any) => (
              <Card key={item.type} className={`${item.type !== "Normal Traffic" ? "border-destructive/40" : ""}`}>
                <CardContent className="p-4">
                  <div className="flex flex-col">
                    <span className="text-sm font-medium">{item.type}</span>
                    <span className="text-2xl font-bold">{item.count}</span>
                    <span className="text-xs text-muted-foreground">{item.percent.toFixed(2)}% of traffic</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <Tabs defaultValue="table">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="table">Data Table</TabsTrigger>
              <TabsTrigger value="visualizations">Visualizations</TabsTrigger>
            </TabsList>
            <TabsContent value="table" className="mt-4">
              <ResultsTable results={results.results} />
            </TabsContent>
            <TabsContent value="visualizations" className="mt-4">
              <ResultsVisualizations results={results} plots={plots} />
            </TabsContent>
          </Tabs>

          <div className="flex justify-between">
            <Button variant="outline" onClick={() => setResults(null)}>
              Analyze Another File
            </Button>
            <Button onClick={handleDownloadReport}>
              <Download className="mr-2 h-4 w-4" />
              Download Report
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
