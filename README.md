# ULPF-X Landing Page

A polished Next.js + Three.js implementation inspired by the supplied ULPF-X reference.

## Stack

- Next.js App Router
- TypeScript
- React Three Fiber
- Three.js
- Drei
- Lucide React
- CSS (no Tailwind dependency)

## Run

```bash
npm install
npm run dev
```

Open http://localhost:3000.

## Three.js interaction

The hero uses a real WebGL scene:

- Hoverable 3D ULPF-X core
- Floating architecture cards
- Animated data-stream curves
- Particle field
- Pointer-driven core rotation
- Physically-based materials and environment lighting
- Responsive canvas with mobile layout handling

The `components/ULPFXScene.tsx` file is the main 3D scene.

## Replacing the GitHub URL

Search for `https://github.com/` and replace it with the real ULPF-X repository.

## Real agent download

The visual button currently points into the documentation/download area so it never creates a broken download. When the actual agent ZIP is available, replace the button target with the real `/downloads/ulpf-x-agent-v1.0.0.zip` asset or your release URL.
