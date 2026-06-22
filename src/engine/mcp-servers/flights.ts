/**
 * OpenSky Network Flights MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://opensky-network.org/apidoc/rest.html
// Auth: none required for anonymous access (lower rate limits apply)
// Docs: https://opensky-network.org/apidoc/rest.html
// Category: transportation
// Rate limits: anonymous ~10 req/10s; registered users higher limits

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://opensky-network.org/api';

// OpenSky state vector tuple indices
// [icao24, callsign, origin_country, time_position, last_contact,
//  longitude, latitude, baro_altitude, on_ground, velocity,
//  true_track, vertical_rate, sensors, geo_altitude, squawk,
//  spi, position_source]
type StateVector = [
  string,            // 0  icao24
  string | null,     // 1  callsign
  string,            // 2  origin_country
  number | null,     // 3  time_position
  number,            // 4  last_contact
  number | null,     // 5  longitude
  number | null,     // 6  latitude
  number | null,     // 7  baro_altitude
  boolean,           // 8  on_ground
  number | null,     // 9  velocity
  number | null,     // 10 true_track
  number | null,     // 11 vertical_rate
  number[] | null,   // 12 sensors
  number | null,     // 13 geo_altitude
  string | null,     // 14 squawk
  boolean,           // 15 spi
  number,            // 16 position_source
];

interface StatesResponse {
  time: number;
  states: StateVector[] | null;
}

interface FlightRecord {
  icao24: string;
  firstSeen: number;
  estDepartureAirport: string | null;
  lastSeen: number;
  estArrivalAirport: string | null;
  callsign: string | null;
  estDepartureAirportHorizDistance: number | null;
  estDepartureAirportVertDistance: number | null;
  estArrivalAirportHorizDistance: number | null;
  estArrivalAirportVertDistance: number | null;
  departureAirportCandidatesCount: number;
  arrivalAirportCandidatesCount: number;
}

function shapeStateVector(sv: StateVector) {
  return {
    icao24: sv[0],
    callsign: sv[1]?.trim() ?? null,
    origin_country: sv[2],
    longitude: sv[5],
    latitude: sv[6],
    altitude: sv[7],
    velocity: sv[9],
    heading: sv[10],
    on_ground: sv[8],
  };
}

function shapeFlightRecord(f: FlightRecord) {
  return {
    icao24: f.icao24,
    callsign: f.callsign?.trim() ?? null,
    first_seen: f.firstSeen,
    last_seen: f.lastSeen,
    departure_airport: f.estDepartureAirport,
    arrival_airport: f.estArrivalAirport,
  };
}

export class FlightsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('FlightsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'flights',
      displayName: 'OpenSky Network Flights',
      version: '1.0.0',
      category: 'transportation',
      keywords: [
        'flights', 'aviation', 'aircraft', 'opensky', 'adsb', 'tracking',
        'airport', 'arrivals', 'departures', 'icao24', 'transponder',
        'bounding box', 'real-time', 'air traffic', 'flight data',
      ],
      toolNames: [
        'get_flights_in_area',
        'get_aircraft',
        'get_arrivals',
        'get_departures',
      ],
      description: 'OpenSky Network Flights: real-time aircraft tracking, bounding-box area searches, and airport arrival/departure history — free and unauthenticated.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'get_flights_in_area',
        description:
          'Get all aircraft currently in a geographic bounding box. Returns icao24, callsign, origin country, position, altitude, velocity, and heading for each aircraft.',
        inputSchema: {
          type: 'object',
          properties: {
            lamin: {
              type: 'number',
              description: 'Minimum latitude of the bounding box (degrees)',
            },
            lomin: {
              type: 'number',
              description: 'Minimum longitude of the bounding box (degrees)',
            },
            lamax: {
              type: 'number',
              description: 'Maximum latitude of the bounding box (degrees)',
            },
            lomax: {
              type: 'number',
              description: 'Maximum longitude of the bounding box (degrees)',
            },
          },
          required: ['lamin', 'lomin', 'lamax', 'lomax'],
        },
      },
      {
        name: 'get_aircraft',
        description:
          'Track a specific aircraft by its ICAO24 transponder address (e.g. "a0b1c2"). Returns current position, velocity, altitude, and heading.',
        inputSchema: {
          type: 'object',
          properties: {
            icao24: {
              type: 'string',
              description: 'ICAO24 transponder address (6 hex characters, e.g. "a0b1c2")',
            },
          },
          required: ['icao24'],
        },
      },
      {
        name: 'get_arrivals',
        description:
          'Get flights that arrived at an airport within a time range. Requires an ICAO airport code and Unix timestamps.',
        inputSchema: {
          type: 'object',
          properties: {
            airport: {
              type: 'string',
              description: 'ICAO airport code (e.g. "KLAX", "EGLL")',
            },
            begin: {
              type: 'number',
              description: 'Start of time range as Unix timestamp (seconds)',
            },
            end: {
              type: 'number',
              description: 'End of time range as Unix timestamp (seconds, max 7 days after begin)',
            },
          },
          required: ['airport', 'begin', 'end'],
        },
      },
      {
        name: 'get_departures',
        description:
          'Get flights that departed from an airport within a time range. Requires an ICAO airport code and Unix timestamps.',
        inputSchema: {
          type: 'object',
          properties: {
            airport: {
              type: 'string',
              description: 'ICAO airport code (e.g. "KLAX", "EGLL")',
            },
            begin: {
              type: 'number',
              description: 'Start of time range as Unix timestamp (seconds)',
            },
            end: {
              type: 'number',
              description: 'End of time range as Unix timestamp (seconds, max 7 days after begin)',
            },
          },
          required: ['airport', 'begin', 'end'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_flights_in_area':
          return this.getFlightsInArea(
            args.lamin as number,
            args.lomin as number,
            args.lamax as number,
            args.lomax as number,
          );
        case 'get_aircraft':
          return this.getAircraft(args.icao24 as string);
        case 'get_arrivals':
          return this.getArrivals(
            args.airport as string,
            args.begin as number,
            args.end as number,
          );
        case 'get_departures':
          return this.getDepartures(
            args.airport as string,
            args.begin as number,
            args.end as number,
          );
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async getFlightsInArea(
    lamin: number,
    lomin: number,
    lamax: number,
    lomax: number,
  ): Promise<ToolResult> {
    const params = new URLSearchParams({
      lamin: String(lamin),
      lomin: String(lomin),
      lamax: String(lamax),
      lomax: String(lomax),
    });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/states/all?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as StatesResponse;
    const aircraft = (data.states ?? []).map(shapeStateVector);
    return {
      content: [{ type: 'text', text: this.truncate({ count: aircraft.length, aircraft }) }],
      isError: false,
    };
  }

  private async getAircraft(icao24: string): Promise<ToolResult> {
    const params = new URLSearchParams({ icao24: icao24.toLowerCase() });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/states/all?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as StatesResponse;
    if (!data.states || data.states.length === 0) {
      return {
        content: [{ type: 'text', text: `Aircraft not found or not currently tracked: ${icao24}` }],
        isError: true,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate(shapeStateVector(data.states[0])) }],
      isError: false,
    };
  }

  private async getArrivals(
    airport: string,
    begin: number,
    end: number,
  ): Promise<ToolResult> {
    const params = new URLSearchParams({
      airport: airport.toUpperCase(),
      begin: String(begin),
      end: String(end),
    });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/flights/arrival?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as FlightRecord[];
    const flights = data.map(shapeFlightRecord);
    return {
      content: [{ type: 'text', text: this.truncate({ count: flights.length, flights }) }],
      isError: false,
    };
  }

  private async getDepartures(
    airport: string,
    begin: number,
    end: number,
  ): Promise<ToolResult> {
    const params = new URLSearchParams({
      airport: airport.toUpperCase(),
      begin: String(begin),
      end: String(end),
    });
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/flights/departure?${params}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as FlightRecord[];
    const flights = data.map(shapeFlightRecord);
    return {
      content: [{ type: 'text', text: this.truncate({ count: flights.length, flights }) }],
      isError: false,
    };
  }
}
