import type { Metadata } from "next"
import Dashboard from "@/components/dashboard"

export const metadata: Metadata = {
  title: "DataShield - Network Traffic Analyzer",
  description: "Advanced network traffic analysis for cybersecurity professionals",
}

export default function Home() {
  return <Dashboard />
}
