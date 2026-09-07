// Wraps a portable (request, deps) => Promise<Response> handler into Cloudflare Pages Functions'
// onRequestX({request, env, params}) shape. The portable handler never sees `env` or `context` — only
// the plain `Deps` object `buildDeps` constructs from them — so the same handler runs unmodified under
// any host that can produce a Deps value and a Request.

export type PortableHandler<Deps> = (request: Request, deps: Deps) => Promise<Response>;

export function pagesHandler<Deps, Env = unknown, Params = unknown>(
  handler: PortableHandler<Deps>,
  buildDeps: (context: { request: Request; env: Env; params: Params }) => Deps
): (context: { request: Request; env: Env; params: Params }) => Promise<Response> {
  return (context) => handler(context.request, buildDeps(context));
}
