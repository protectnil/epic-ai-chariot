/**
 * Movies MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: iTunes Search API (https://itunes.apple.com) + TVmaze API (https://api.tvmaze.com)
// Base URLs: https://itunes.apple.com  /  https://api.tvmaze.com
// Auth: none (both APIs are public, no auth required)
// Category: entertainment
// Rate limits: iTunes: undocumented; TVmaze: ~20 req/10s unauthenticated

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const ITUNES_BASE = 'https://itunes.apple.com';
const TVMAZE_BASE = 'https://api.tvmaze.com';

export class MoviesMCPServer extends MCPAdapterBase {
  private readonly itunesBase: string;
  private readonly tvmazeBase: string;

  constructor(config?: { itunesBase?: string; tvmazeBase?: string }) {
    super();
    if (config === null) { throw new Error('MoviesMCPServer: configuration object is required when provided'); }
    this.itunesBase = config?.itunesBase ?? ITUNES_BASE;
    this.tvmazeBase = config?.tvmazeBase ?? TVMAZE_BASE;
  }

  static catalog() {
    return {
      name: 'movies',
      displayName: 'Movies & TV Shows',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'movies', 'films', 'tv shows', 'television', 'itunes', 'tvmaze',
        'search movies', 'search tv', 'tv schedule', 'episodes', 'broadcast',
        'streaming', 'entertainment', 'cinema', 'series',
      ],
      toolNames: ['search_movies', 'search_tv_shows', 'get_tv_show', 'get_tv_schedule'],
      description: 'Movies & TV: search movies via the iTunes Search API and TV shows via TVmaze, retrieve full show details with episode lists, and look up TV broadcast schedules by country and date. No authentication required.',
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
        name: 'search_movies',
        description:
          'Search for movies by title or keyword. Returns title, director, release date, genre, description, artwork, and iTunes store link.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Movie title or keyword to search for',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1-25, default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_tv_shows',
        description:
          'Search for TV shows by name. Returns show name, genres, premiere/end dates, rating, summary, and image.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'TV show name or keyword to search for',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_tv_show',
        description:
          'Get full details for a TV show by its TVmaze ID, including its complete episode list.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'TVmaze show ID (e.g., 1 for "Under the Dome")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_tv_schedule',
        description:
          "Get the TV broadcast schedule for a given country and date. Defaults to today's US schedule.",
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'ISO 3166-1 alpha-2 country code (default "US")',
            },
            date: {
              type: 'string',
              description: 'Date in YYYY-MM-DD format (default: today)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_movies':   return this.searchMovies(args);
        case 'search_tv_shows': return this.searchTvShows(args);
        case 'get_tv_show':     return this.getTvShow(args);
        case 'get_tv_schedule': return this.getTvSchedule(args);
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

  private stripHtml(html: string | null | undefined): string | null {
    if (!html) return null;
    return html.replace(/<[^>]+>/g, '').trim() || null;
  }

  private formatShow(show: TvmazeShow): MappedShow {
    return {
      id: show.id,
      name: show.name,
      type: show.type ?? null,
      language: show.language ?? null,
      genres: show.genres ?? [],
      status: show.status ?? null,
      premiered: show.premiered ?? null,
      ended: show.ended ?? null,
      rating: show.rating?.average ?? null,
      network: show.network?.name ?? show.webChannel?.name ?? null,
      summary: this.stripHtml(show.summary),
      url: show.url ?? null,
      image: show.image?.medium ?? null,
    };
  }

  private async searchMovies(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    if (!query || typeof query !== 'string') {
      return { content: [{ type: 'text', text: 'query is required and must be a string' }], isError: true };
    }
    const rawLimit = typeof args.limit === 'number' ? args.limit : 10;
    const count = Math.min(25, Math.max(1, rawLimit));

    const params = new URLSearchParams({
      term: query,
      media: 'movie',
      limit: String(count),
    });

    const url = `${this.itunesBase}/search?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as ItunesSearchResponse;
    const result = {
      total_found: data.resultCount,
      movies: data.results.map((item) => ({
        title: item.trackName ?? null,
        director: item.artistName ?? null,
        release_date: item.releaseDate ? item.releaseDate.substring(0, 10) : null,
        genre: item.primaryGenreName ?? null,
        description: item.longDescription ?? item.shortDescription ?? null,
        rating: item.contentAdvisoryRating ?? null,
        runtime_minutes: item.trackTimeMillis ? Math.round(item.trackTimeMillis / 60000) : null,
        itunes_url: item.trackViewUrl ?? null,
        artwork_url: item.artworkUrl100 ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchTvShows(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    if (!query || typeof query !== 'string') {
      return { content: [{ type: 'text', text: 'query is required and must be a string' }], isError: true };
    }

    const url = `${this.tvmazeBase}/search/shows?q=${encodeURIComponent(query)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as TvmazeSearchResult[];
    const result = {
      total_found: data.length,
      shows: data.map((entry) => ({
        score: entry.score,
        ...this.formatShow(entry.show),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTvShow(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as number;
    if (typeof id !== 'number' || !Number.isFinite(id)) {
      return { content: [{ type: 'text', text: 'id is required and must be a number' }], isError: true };
    }

    const url = `${this.tvmazeBase}/shows/${id}?embed=episodes`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `TV show not found for ID: ${id}` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as TvmazeShowWithEmbeds;
    const episodes = data._embedded?.episodes ?? [];
    const result = {
      ...this.formatShow(data),
      episode_count: episodes.length,
      episodes: episodes.map((ep) => ({
        id: ep.id,
        season: ep.season,
        episode: ep.number,
        name: ep.name,
        airdate: ep.airdate ?? null,
        airtime: ep.airtime ?? null,
        runtime_minutes: ep.runtime ?? null,
        summary: this.stripHtml(ep.summary),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getTvSchedule(args: Record<string, unknown>): Promise<ToolResult> {
    const country = ((args.country as string) ?? 'US').toUpperCase();
    const date = args.date as string | undefined;

    const params = new URLSearchParams({ country });
    if (date) params.set('date', date);

    const url = `${this.tvmazeBase}/schedule?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as TvmazeScheduleEntry[];
    const result = {
      country,
      date: date ?? new Date().toISOString().substring(0, 10),
      total_airings: data.length,
      schedule: data.map((entry) => ({
        airtime: entry.airtime ?? null,
        show_name: entry.show?.name ?? null,
        network: entry.show?.network?.name ?? entry.show?.webChannel?.name ?? null,
        episode_name: entry.name,
        season: entry.season,
        episode: entry.number,
        runtime_minutes: entry.runtime ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

// ── Upstream type shapes ────────────────────────────────────────────────────

interface ItunesMovieResult {
  trackName?: string;
  artistName?: string;
  releaseDate?: string;
  primaryGenreName?: string;
  longDescription?: string;
  shortDescription?: string;
  trackViewUrl?: string;
  artworkUrl100?: string;
  trackTimeMillis?: number;
  contentAdvisoryRating?: string;
}

interface ItunesSearchResponse {
  resultCount: number;
  results: ItunesMovieResult[];
}

interface TvmazeImage {
  medium?: string;
  original?: string;
}

interface TvmazeRating {
  average: number | null;
}

interface TvmazeNetwork {
  name: string;
  country?: { name: string; code: string } | null;
}

interface TvmazeShow {
  id: number;
  name: string;
  type?: string;
  language?: string;
  genres?: string[];
  status?: string;
  premiered?: string | null;
  ended?: string | null;
  rating?: TvmazeRating;
  network?: TvmazeNetwork | null;
  webChannel?: { name: string } | null;
  summary?: string | null;
  url?: string;
  image?: TvmazeImage | null;
}

interface TvmazeSearchResult {
  score: number;
  show: TvmazeShow;
}

interface TvmazeEpisode {
  id: number;
  name: string;
  season: number;
  number: number | null;
  airdate?: string;
  airtime?: string;
  runtime?: number | null;
  summary?: string | null;
}

interface TvmazeShowWithEmbeds extends TvmazeShow {
  _embedded?: {
    episodes?: TvmazeEpisode[];
  };
}

interface TvmazeScheduleEntry {
  id: number;
  name: string;
  season: number;
  number: number | null;
  airdate?: string;
  airtime?: string;
  runtime?: number | null;
  show: TvmazeShow;
}

interface MappedShow {
  id: number;
  name: string;
  type: string | null;
  language: string | null;
  genres: string[];
  status: string | null;
  premiered: string | null;
  ended: string | null;
  rating: number | null;
  network: string | null;
  summary: string | null;
  url: string | null;
  image: string | null;
}
