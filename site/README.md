# FastDog marketing landing v1 — draft

This is a static preview under `/www/`. It does not publish the apex or change DNS. The live edge process on master will not serve this branch until it is merged and the process is deliberately restarted.

## Preview now

From the repository root:

```sh
cd site
python3 -m http.server 8000 --bind 127.0.0.1
```

Open `http://127.0.0.1:8000/`. The status panel will read **Unavailable** here because Python's static server has no `/health`. This is expected.

To smoke test the actual `/www/` mount on a temporary local edge process without touching the running service:

```sh
NODE_ENV=test node --input-type=module -e 'import { server } from "./src/edge/server.js"; server.listen(8797, "127.0.0.1", () => console.log("http://127.0.0.1:8797/www/"))'
```

Open `http://127.0.0.1:8797/www/`. The edge and tunnel checks use its local `/health`; TLS reads **Local preview** because the page uses HTTP. Stop with Ctrl-C.

After a future merge and intentional edge restart, a loopback preview can use:

```sh
ssh -L 8787:127.0.0.1:8787 server3
```

Then open `http://127.0.0.1:8787/www/`. The tunnel URL `https://edge.fastdognetworks.com/www/` depends on that path reaching the running edge. Neither URL implies apex publication.

## Holds

No registrar nameserver flip, apex publication, automatic CoreDNS sync, PoP changes, operator exposure, or live Stripe checkout is part of this branch. Pricing is proposed ranges only. The operator remains on its existing loopback listener.

Font files in `fonts/` are used under the bundled OFL licenses. The SVGs in `logos/` are light variants of the supplied FastDog logo artwork.
