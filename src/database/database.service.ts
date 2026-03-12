import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool, PoolClient, QueryResult } from 'pg';

@Injectable()
export class DatabaseService implements OnModuleInit, OnModuleDestroy {
  private pool: Pool;

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    this.pool = new Pool({
      host: this.config.getOrThrow<string>('DB_HOST'),
      port: this.config.getOrThrow<number>('DB_PORT'),
      database: this.config.getOrThrow<string>('DB_NAME'),
      user: this.config.getOrThrow<string>('DB_USER'),
      password: this.config.getOrThrow<string>('DB_PASSWORD'),
      max: 20,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      ssl: this.config.get<string>('DB_SSL') === 'true' ? { rejectUnauthorized: true } : false,
    });

    this.pool.on('error', (err) => {
      console.error('[DatabaseService] Unexpected pool error:', err);
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Execute a single query using a pool connection.
   */
  async query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<QueryResult<T>> {
    return this.pool.query<T>(sql, params);
  }

  /**
   * Acquire a client for multi-statement transactions.
   * Caller is responsible for calling client.release().
   */
  async getClient(): Promise<PoolClient> {
    return this.pool.connect();
  }

  /**
   * Run a callback inside a transaction.
   * Automatically commits or rolls back on error.
   */
  async withTransaction<T>(
    fn: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await this.getClient();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }
}
