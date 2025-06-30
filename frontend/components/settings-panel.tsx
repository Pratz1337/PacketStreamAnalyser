"use client"

import { useState, useEffect } from "react"
import { Save, AlertTriangle, Info, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Slider } from "@/components/ui/slider"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { getModelSettings, updateModelSettings } from "@/lib/api"

export default function SettingsPanel() {
  const [thresholds, setThresholds] = useState({
    "Normal Traffic": 0.5,
    DoS: 0.95,
    DDoS: 0.9,
    "Port Scan": 0.9,
    "Brute Force": 0.9,
    default: 0.85,
  })

  const [securitySettings, setSecuritySettings] = useState({
    enableCSP: true,
    enableXSS: true,
    enableCSRF: true,
    enableRateLimiting: true,
    enableLogging: true,
  })

  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // Load settings on component mount
  useEffect(() => {
    async function loadSettings() {
      try {
        setLoading(true)
        const settings = await getModelSettings()

        if (settings && Object.keys(settings).length > 0) {
          setThresholds(settings)
        }
      } catch (err) {
        console.error("Error loading settings:", err)
        setError("Failed to load settings")
      } finally {
        setLoading(false)
      }
    }

    loadSettings()
  }, [])

  const handleThresholdChange = (type: string, value: number[]) => {
    setThresholds((prev) => ({
      ...prev,
      [type]: value[0],
    }))
    setSaved(false)
  }

  const handleSecurityToggle = (setting: string, value: boolean) => {
    setSecuritySettings((prev) => ({
      ...prev,
      [setting]: value,
    }))
    setSaved(false)
  }

  const saveSettings = async () => {
    try {
      setSaving(true)
      setError(null)

      // Save thresholds to backend
      await updateModelSettings(thresholds)

      // Show success message
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      console.error("Error saving settings:", err)
      setError("Failed to save settings")
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-8">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
        <p className="text-muted-foreground">Configure detection thresholds and security settings.</p>
      </div>

      {saved && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Settings saved</AlertTitle>
          <AlertDescription>Your settings have been saved successfully.</AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Detection Thresholds</CardTitle>
            <CardDescription>
              Adjust confidence thresholds for different types of traffic. Higher thresholds reduce false positives but
              may increase false negatives.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {Object.entries(thresholds).map(([type, value]) => (
              <div key={type} className="space-y-2">
                <div className="flex justify-between">
                  <Label>{type}</Label>
                  <span className="text-sm text-muted-foreground">{(value * 100).toFixed(0)}%</span>
                </div>
                <Slider
                  value={[value]}
                  min={0.5}
                  max={0.99}
                  step={0.01}
                  onValueChange={(value) => handleThresholdChange(type, value)}
                />
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Security Settings</CardTitle>
            <CardDescription>Configure security features for the application.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Content Security Policy</Label>
                <p className="text-sm text-muted-foreground">Protect against XSS attacks</p>
              </div>
              <Switch
                checked={securitySettings.enableCSP}
                onCheckedChange={(value) => handleSecurityToggle("enableCSP", value)}
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>XSS Protection</Label>
                <p className="text-sm text-muted-foreground">Additional cross-site scripting protection</p>
              </div>
              <Switch
                checked={securitySettings.enableXSS}
                onCheckedChange={(value) => handleSecurityToggle("enableXSS", value)}
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>CSRF Protection</Label>
                <p className="text-sm text-muted-foreground">Prevent cross-site request forgery</p>
              </div>
              <Switch
                checked={securitySettings.enableCSRF}
                onCheckedChange={(value) => handleSecurityToggle("enableCSRF", value)}
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Rate Limiting</Label>
                <p className="text-sm text-muted-foreground">Prevent brute force and DoS attacks</p>
              </div>
              <Switch
                checked={securitySettings.enableRateLimiting}
                onCheckedChange={(value) => handleSecurityToggle("enableRateLimiting", value)}
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Security Logging</Label>
                <p className="text-sm text-muted-foreground">Log security events for auditing</p>
              </div>
              <Switch
                checked={securitySettings.enableLogging}
                onCheckedChange={(value) => handleSecurityToggle("enableLogging", value)}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      <Alert variant="destructive" className="bg-destructive/5">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Security Warning</AlertTitle>
        <AlertDescription>
          Disabling security features may leave your application vulnerable to attacks. Only disable these features if
          you understand the risks.
        </AlertDescription>
      </Alert>

      <div className="flex justify-end">
        <Button onClick={saveSettings} disabled={saving}>
          {saving ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="mr-2 h-4 w-4" />
              Save Settings
            </>
          )}
        </Button>
      </div>
    </div>
  )
}
