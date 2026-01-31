import swaggerJsdoc from 'swagger-jsdoc';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Cordelia API',
      version: '0.4.0',
      description: 'Project Cordelia: Persistent dense memory system for Claude',
      contact: {
        name: 'Seed Drill',
        url: 'https://github.com/seed-drill/cordelia-proxy',
      },
      license: {
        name: 'AGPL-3.0-only',
        url: 'https://www.gnu.org/licenses/agpl-3.0.en.html',
      },
    },
    servers: [
      {
        url: 'http://localhost:3847',
        description: 'Local development server',
      },
      {
        url: 'https://cordelia-seed-drill.fly.dev',
        description: 'Production server',
      },
    ],
    tags: [
      { name: 'Authentication', description: 'GitHub OAuth authentication' },
      { name: 'System', description: 'System status and information' },
      { name: 'L1 Hot Context', description: 'Hot context operations (loaded every session)' },
      { name: 'L2 Warm Index', description: 'Searchable warm index operations' },
      { name: 'Users', description: 'User management' },
    ],
    components: {
      schemas: {
        Identity: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'User ID' },
            name: { type: 'string', description: 'Display name' },
            roles: { type: 'array', items: { type: 'string' }, description: 'User roles' },
            orgs: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  name: { type: 'string' },
                  role: { type: 'string' },
                },
              },
            },
            github_id: { type: 'string', description: 'GitHub username' },
            tz: { type: 'string', description: 'Timezone' },
          },
        },
        L1HotContext: {
          type: 'object',
          properties: {
            version: { type: 'integer', description: 'Schema version' },
            updated_at: { type: 'string', format: 'date-time' },
            identity: { $ref: '#/components/schemas/Identity' },
            active: {
              type: 'object',
              properties: {
                project: { type: 'string', nullable: true },
                sprint: { type: 'string', nullable: true },
                focus: { type: 'string', nullable: true },
                blockers: { type: 'array', items: { type: 'string' } },
                next: { type: 'array', items: { type: 'string' } },
              },
            },
            prefs: {
              type: 'object',
              properties: {
                planning_mode: { type: 'string', enum: ['important', 'detailed', 'minimal'] },
                verbosity: { type: 'string', enum: ['concise', 'detailed', 'verbose'] },
                emoji: { type: 'boolean' },
              },
            },
          },
        },
        L2Entry: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Entry ID' },
            type: { type: 'string', enum: ['entity', 'session', 'learning'] },
            title: { type: 'string' },
            tags: { type: 'array', items: { type: 'string' } },
            created_at: { type: 'string', format: 'date-time' },
            updated_at: { type: 'string', format: 'date-time' },
          },
        },
        L2Item: {
          allOf: [
            { $ref: '#/components/schemas/L2Entry' },
            {
              type: 'object',
              properties: {
                content: { type: 'string', description: 'Item content' },
              },
            },
          ],
        },
        SystemStatus: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'ok' },
            version: { type: 'string', example: '0.4.0' },
            server: { type: 'string', example: 'http' },
            port: { type: 'integer', example: 3847 },
            auth: {
              type: 'object',
              properties: {
                github_configured: { type: 'boolean' },
              },
            },
            layers: {
              type: 'object',
              properties: {
                L1_hot: { type: 'object', properties: { users: { type: 'array', items: { type: 'string' } } } },
                L2_warm: {
                  type: 'object',
                  properties: {
                    status: { type: 'string' },
                    entries: { type: 'integer' },
                    entities: { type: 'integer' },
                    sessions: { type: 'integer' },
                    learnings: { type: 'integer' },
                  },
                },
              },
            },
            encryption: {
              type: 'object',
              properties: {
                provider: { type: 'string' },
                unlocked: { type: 'boolean' },
              },
            },
          },
        },
        AuthStatus: {
          type: 'object',
          properties: {
            authenticated: { type: 'boolean' },
            github_login: { type: 'string' },
            cordelia_user: { type: 'string', nullable: true },
          },
        },
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string' },
          },
        },
      },
    },
    paths: {
      '/auth/status': {
        get: {
          tags: ['Authentication'],
          summary: 'Check authentication status',
          responses: {
            '200': {
              description: 'Authentication status',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthStatus' } } },
            },
          },
        },
      },
      '/auth/github': {
        get: {
          tags: ['Authentication'],
          summary: 'Initiate GitHub OAuth login',
          responses: {
            '302': { description: 'Redirect to GitHub OAuth' },
            '500': { description: 'GitHub OAuth not configured' },
          },
        },
      },
      '/auth/logout': {
        post: {
          tags: ['Authentication'],
          summary: 'Log out',
          responses: {
            '200': { description: 'Logout successful', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' } } } } } },
          },
        },
      },
      '/api/status': {
        get: {
          tags: ['System'],
          summary: 'Get system status',
          responses: {
            '200': {
              description: 'System status',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/SystemStatus' } } },
            },
          },
        },
      },
      '/api/users': {
        get: {
          tags: ['Users'],
          summary: 'List available users',
          responses: {
            '200': {
              description: 'List of users',
              content: { 'application/json': { schema: { type: 'object', properties: { users: { type: 'array', items: { type: 'string' } } } } } },
            },
          },
        },
      },
      '/api/hot/{userId}': {
        get: {
          tags: ['L1 Hot Context'],
          summary: 'Get L1 hot context for a user',
          parameters: [
            { name: 'userId', in: 'path', required: true, schema: { type: 'string' }, description: 'User ID' },
          ],
          responses: {
            '200': {
              description: 'L1 hot context',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/L1HotContext' } } },
            },
            '404': { description: 'User not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/l2/index': {
        get: {
          tags: ['L2 Warm Index'],
          summary: 'Get L2 index',
          responses: {
            '200': {
              description: 'L2 index',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      version: { type: 'integer' },
                      entries: { type: 'array', items: { $ref: '#/components/schemas/L2Entry' } },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/api/l2/item/{id}': {
        get: {
          tags: ['L2 Warm Index'],
          summary: 'Get L2 item by ID',
          parameters: [
            { name: 'id', in: 'path', required: true, schema: { type: 'string' }, description: 'Item ID' },
          ],
          responses: {
            '200': {
              description: 'L2 item',
              content: { 'application/json': { schema: { $ref: '#/components/schemas/L2Item' } } },
            },
            '404': { description: 'Item not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/l2/search': {
        get: {
          tags: ['L2 Warm Index'],
          summary: 'Search L2 index',
          parameters: [
            { name: 'query', in: 'query', schema: { type: 'string' }, description: 'Search query' },
            { name: 'type', in: 'query', schema: { type: 'string', enum: ['entity', 'session', 'learning'] }, description: 'Filter by type' },
            { name: 'tags', in: 'query', schema: { type: 'string' }, description: 'Comma-separated tags' },
            { name: 'limit', in: 'query', schema: { type: 'integer' }, description: 'Max results' },
          ],
          responses: {
            '200': {
              description: 'Search results',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      results: { type: 'array', items: { $ref: '#/components/schemas/L2Entry' } },
                      count: { type: 'integer' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/api/signup': {
        post: {
          tags: ['Users'],
          summary: 'Create a new user profile',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['name', 'github_id'],
                  properties: {
                    name: { type: 'string', description: 'Display name' },
                    github_id: { type: 'string', description: 'GitHub username' },
                    roles: { type: 'array', items: { type: 'string' } },
                    org_name: { type: 'string' },
                    org_role: { type: 'string' },
                    style: { type: 'array', items: { type: 'string' } },
                    planning_mode: { type: 'string', enum: ['important', 'detailed', 'minimal'] },
                    verbosity: { type: 'string', enum: ['concise', 'detailed', 'verbose'] },
                    emoji: { type: 'boolean' },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'User created',
              content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, user_id: { type: 'string' } } } } },
            },
            '400': { description: 'Missing required fields', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            '409': { description: 'User already exists', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
    },
  },
  apis: [], // We're defining everything inline
};

export const swaggerSpec = swaggerJsdoc(options);
