"use client"

import { useState } from "react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Button } from "@/components/ui/button"
import { ChevronDown, Search, AlertTriangle, CheckCircle, Filter } from "lucide-react"

interface ResultsTableProps {
  results: any[]
  showTimestamp?: boolean
}

export default function ResultsTable({ results, showTimestamp = false }: ResultsTableProps) {
  const [searchTerm, setSearchTerm] = useState("")
  const [filterType, setFilterType] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const rowsPerPage = 10

  // Filter results based on search term and filter type
  const filteredResults = results.filter((result) => {
    const matchesSearch =
      searchTerm === "" || (result.prediction && result.prediction.toLowerCase().includes(searchTerm.toLowerCase()))

    const matchesFilter = filterType === null || result.prediction === filterType

    return matchesSearch && matchesFilter
  })

  // Get unique prediction types for filter
  const predictionTypes = Array.from(new Set(results.map((r) => r.prediction)))

  // Paginate results
  const paginatedResults = filteredResults.slice((page - 1) * rowsPerPage, page * rowsPerPage)

  const totalPages = Math.ceil(filteredResults.length / rowsPerPage)

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-4 justify-between">
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search..."
            className="pl-8"
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value)
              setPage(1) // Reset to first page on search
            }}
          />
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="w-full sm:w-auto">
              <Filter className="mr-2 h-4 w-4" />
              {filterType || "All Types"}
              <ChevronDown className="ml-2 h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem
              onClick={() => {
                setFilterType(null)
                setPage(1)
              }}
            >
              All Types
            </DropdownMenuItem>
            {predictionTypes.map((type) => (
              <DropdownMenuItem
                key={type}
                onClick={() => {
                  setFilterType(type)
                  setPage(1)
                }}
              >
                {type}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[80px]">ID</TableHead>
              {showTimestamp && <TableHead>Timestamp</TableHead>}
              <TableHead>Traffic Type</TableHead>
              <TableHead>Confidence</TableHead>
              <TableHead className="text-right">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedResults.length > 0 ? (
              paginatedResults.map((result) => (
                <TableRow key={result.id}>
                  <TableCell className="font-medium">{result.id}</TableCell>
                  {showTimestamp && <TableCell>{new Date(result.timestamp).toLocaleString()}</TableCell>}
                  <TableCell>{result.prediction}</TableCell>
                  <TableCell>{(result.confidence * 100).toFixed(2)}%</TableCell>
                  <TableCell className="text-right">
                    {result.is_malicious ? (
                      <Badge variant="destructive" className="flex items-center gap-1 ml-auto w-fit">
                        <AlertTriangle className="h-3 w-3" />
                        Malicious
                      </Badge>
                    ) : (
                      <Badge
                        variant="outline"
                        className="flex items-center gap-1 ml-auto w-fit bg-green-500/10 text-green-500 border-green-500/20"
                      >
                        <CheckCircle className="h-3 w-3" />
                        Normal
                      </Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={showTimestamp ? 5 : 4} className="h-24 text-center">
                  No results found.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            Showing {(page - 1) * rowsPerPage + 1}-{Math.min(page * rowsPerPage, filteredResults.length)} of{" "}
            {filteredResults.length} results
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
