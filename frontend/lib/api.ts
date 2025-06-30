const API_BASE_URL = "http://localhost:5000"

/**
 * Upload a CSV file for analysis
 */
export async function uploadFile(file: File): Promise<any> {
  try {
    const formData = new FormData()
    formData.append("file", file)

    const response = await fetch(`${API_BASE_URL}/upload`, {
      method: "POST",
      body: formData,
    })

    if (!response.ok) {
      throw new Error(`Upload failed: ${response.statusText}`)
    }

    return response.json()
  } catch (error) {
    console.error("API Error in uploadFile:", error)
    throw error
  }
}

/**
 * Get available network interfaces
 */
export async function getNetworkInterfaces(): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/`, {
      method: "GET",
    })

    if (!response.ok) {
      throw new Error(`Failed to get interfaces: ${response.statusText}`)
    }

    // Extract interfaces from the HTML response
    const html = await response.text()
    try {
      // Parse interfaces from the HTML (simplified approach)
      const interfaces = extractInterfacesFromHTML(html)
      return interfaces.length > 0 ? interfaces : [
        { name: 'default', description: 'System Default' },
        { name: 'loopback', description: 'Loopback Interface' }
      ]
    } catch (error) {
      console.error("Error parsing interfaces:", error)
      // Return default interfaces when parsing fails
      return [
        { name: 'default', description: 'System Default' },
        { name: 'loopback', description: 'Loopback Interface' }
      ]
    }
  } catch (error) {
    console.error("API Error in getNetworkInterfaces:", error)
    // Return default interfaces when API call fails
    return [
      { name: 'default', description: 'System Default' },
      { name: 'loopback', description: 'Loopback Interface' }
    ]
  }
}

/**
 * Start live packet capture
 */
export async function startLiveCapture(interface_name: string, batch_size: number): Promise<any> {
  try {
    const formData = new FormData()
    formData.append("interface", interface_name)
    formData.append("batch_size", batch_size.toString())

    const response = await fetch(`${API_BASE_URL}/start_live`, {
      method: "POST",
      body: formData,
    })

    if (!response.ok) {
      throw new Error(`Failed to start capture: ${response.statusText}`)
    }

    return response.json()
  } catch (error) {
    console.error("API Error in startLiveCapture:", error)
    throw error
  }
}

/**
 * Stop live packet capture
 */
export async function stopLiveCapture(): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/stop_live`, {
      method: "POST",
    })

    if (!response.ok) {
      throw new Error(`Failed to stop capture: ${response.statusText}`)
    }

    return response.json()
  } catch (error) {
    console.error("API Error in stopLiveCapture:", error)
    throw error
  }
}

/**
 * Get live capture results
 */
export async function getLiveResults(lastId: number): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/get_live_results?last_id=${lastId}`, {
      method: "GET",
    })

    if (!response.ok) {
      throw new Error(`Failed to get results: ${response.statusText}`)
    }

    return response.json()
  } catch (error) {
    console.error("API Error in getLiveResults:", error)
    throw error
  }
}

/**
 * Download live capture results as CSV
 */
export function downloadLiveResults(): string {
  return `${API_BASE_URL}/download_live_results`
}

/**
 * Get model settings
 */
export async function getModelSettings(): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/settings`, {
      method: "GET",
    })

    if (!response.ok) {
      throw new Error(`Failed to get settings: ${response.statusText}`)
    }

    // Extract thresholds from the HTML response
    // In a production app, you'd create a dedicated API endpoint for this
    const html = await response.text()
    try {
      // Parse thresholds from the HTML (simplified approach)
      const thresholds = extractThresholdsFromHTML(html)
      return thresholds
    } catch (error) {
      console.error("Error parsing thresholds:", error)
      return {}
    }
  } catch (error) {
    console.error("API Error in getModelSettings:", error)
    throw error
  }
}

/**
 * Update model settings
 */
export async function updateModelSettings(thresholds: Record<string, number>): Promise<any> {
  try {
    const formData = new FormData()

    // Add each threshold to the form data
    Object.entries(thresholds).forEach(([key, value]) => {
      formData.append(`threshold_${key.replace(" ", "_")}`, value.toString())
    })

    const response = await fetch(`${API_BASE_URL}/settings`, {
      method: "POST",
      body: formData,
    })

    if (!response.ok) {
      throw new Error(`Failed to update settings: ${response.statusText}`)
    }

    return response.json()
  } catch (error) {
    console.error("API Error in updateModelSettings:", error)
    throw error
  }
}

// Helper function to extract interfaces from HTML
// This is a simplified approach - in a real app, you'd create a dedicated API endpoint
function extractInterfacesFromHTML(html: string): any[] {
  // Fallback to mock interfaces if parsing fails
  try {
    // This is a very simplified parser and would need to be adapted to your actual HTML structure
    const interfaceMatches = html.match(/<option value="([^"]+)">([^<]+)<\/option>/g) || []

    return interfaceMatches.map((match) => {
      const nameMatch = match.match(/value="([^"]+)"/) || []
      const descMatch = match.match(/>([^<]+)</) || []

      return {
        name: nameMatch[1] || "",
        description: descMatch[1] || "",
      }
    })
  } catch (error) {
    console.error("Error extracting interfaces:", error)
    return [
      { name: "eth0", description: "Ethernet Adapter" },
      { name: "wlan0", description: "Wireless Adapter" },
      { name: "lo", description: "Loopback Interface" },
    ]
  }
}

// Helper function to extract thresholds from HTML
// This is a simplified approach - in a real app, you'd create a dedicated API endpoint
function extractThresholdsFromHTML(html: string): Record<string, number> {
  // Fallback to default thresholds if parsing fails
  try {
    // This is a very simplified parser and would need to be adapted to your actual HTML structure
    const thresholdMatches = html.match(/name="threshold_([^"]+)" value="([^"]+)"/g) || []

    const thresholds: Record<string, number> = {}

    thresholdMatches.forEach((match) => {
      const nameMatch = match.match(/threshold_([^"]+)/) || []
      const valueMatch = match.match(/value="([^"]+)"/) || []

      if (nameMatch[1] && valueMatch[1]) {
        const key = nameMatch[1].replace("_", " ")
        thresholds[key] = Number.parseFloat(valueMatch[1])
      }
    })

    return thresholds
  } catch (error) {
    console.error("Error extracting thresholds:", error)
    return {
      "Normal Traffic": 0.5,
      DoS: 0.95,
      DDoS: 0.9,
      "Port Scan": 0.9,
      "Brute Force": 0.9,
      default: 0.85,
    }
  }
}
