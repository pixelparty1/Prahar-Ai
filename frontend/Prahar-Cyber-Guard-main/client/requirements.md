## Packages
three | Base 3D rendering library
@react-three/fiber | React renderer for Three.js
@react-three/drei | Helpful utilities for React Three Fiber components
framer-motion | Subtle UI animations and page transitions

## Notes
Static images: Using purely code-generated CSS grids and Three.js primitive shapes. No external GLTF models needed.
Mouse tracking requires Canvas to either sit above or accurately receive pointer events; we use pointer-events-none on UI wrappers to ensure Canvas perfectly tracks the mouse anywhere on screen.
