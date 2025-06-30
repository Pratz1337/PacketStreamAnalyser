"use client"

import { useState, useEffect } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card } from "@/components/ui/card"
import Header from "@/components/header"
import FileUploadAnalyzer from "@/components/file-upload-analyzer"
import LiveCaptureAnalyzer from "@/components/live-capture-analyzer"
import SettingsPanel from "@/components/settings-panel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { AlertTriangle } from "lucide-react"

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("file-upload")
  const [error, setError] = useState<string | null>(null)

  // Add global error handling
  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      console.error("Global error:", event.error)
      setError("An error occurred. Please check the console for details.")
    }

    window.addEventListener("error", handleError)
    return () => window.removeEventListener("error", handleError)
  }, [])

  return (
    <div className="flex min-h-screen flex-col bg-gradient-to-br from-background to-background/90">
      <Header />
      <main className="flex-1 p-4 md:p-6 lg:p-8 container mx-auto">
        {error && (
          <Alert variant="destructive" className="mb-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="file-upload" className="space-y-6" onValueChange={setActiveTab} value={activeTab}>
          <TabsList className="grid grid-cols-3 w-full max-w-md mx-auto">
            <TabsTrigger value="file-upload" onClick={() => setActiveTab("file-upload")}>
              File Analysis
            </TabsTrigger>
            <TabsTrigger value="live-capture" onClick={() => setActiveTab("live-capture")}>
              Live Capture
            </TabsTrigger>
            <TabsTrigger value="settings" onClick={() => setActiveTab("settings")}>
              Settings
            </TabsTrigger>
          </TabsList>

          <Card className="border border-border/40 bg-card/50 backdrop-blur-sm">
            <TabsContent value="file-upload" className="p-4 md:p-6">
              <FileUploadAnalyzer />
            </TabsContent>

            <TabsContent value="live-capture" className="p-4 md:p-6">
              <LiveCaptureAnalyzer />
            </TabsContent>

            <TabsContent value="settings" className="p-4 md:p-6">
              <SettingsPanel />
            </TabsContent>
          </Card>
        </Tabs>
      </main>
      <footer className="py-4 px-8 text-center text-sm text-muted-foreground border-t border-border/30 backdrop-blur-sm">
        <p>DataShield Network Traffic Analyzer &copy; {new Date().getFullYear()}</p>
      </footer>
    </div>
  )
}
