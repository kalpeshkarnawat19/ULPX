"use client";

import { Canvas, useFrame } from "@react-three/fiber";
import { Html, Line } from "@react-three/drei";
import { useMemo, useRef, useState } from "react";
import * as THREE from "three";

function Core() {
  const group = useRef<THREE.Group>(null);
  const [hovered, setHovered] = useState(false);

  useFrame((state) => {
    if (!group.current) return;

    group.current.rotation.y += 0.003;

    group.current.rotation.x = THREE.MathUtils.lerp(
      group.current.rotation.x,
      state.pointer.y * 0.08,
      0.04
    );

    group.current.rotation.z = THREE.MathUtils.lerp(
      group.current.rotation.z,
      state.pointer.x * -0.05,
      0.04
    );
  });

  return (
    <group
      ref={group}
      scale={hovered ? 1.08 : 1}
      onPointerEnter={() => setHovered(true)}
      onPointerLeave={() => setHovered(false)}
    >
      <mesh>
        <boxGeometry args={[1.55, 1.55, 1.55]} />
        <meshStandardMaterial
          color="#183640"
          metalness={0.7}
          roughness={0.25}
        />
      </mesh>

      <mesh scale={0.72}>
        <boxGeometry args={[1.55, 1.55, 1.55]} />
        <meshBasicMaterial
          color="#4fbfaf"
          wireframe
          transparent
          opacity={0.8}
        />
      </mesh>

      <mesh scale={1.08}>
        <boxGeometry args={[1.55, 1.55, 1.55]} />
        <meshBasicMaterial
          color="#83d8d0"
          wireframe
          transparent
          opacity={0.25}
        />
      </mesh>

      <mesh>
        <octahedronGeometry args={[0.35, 1]} />
        <meshStandardMaterial
          color="#91e1d5"
          emissive="#3a9f96"
          emissiveIntensity={1.5}
          metalness={0.4}
          roughness={0.15}
        />
      </mesh>

      {/* Browser-rendered label */}
      
    </group>
  );
}
function CoreLabel() {
  return (
    <Html
      position={[0, 0, 0.9]}
      center
      distanceFactor={5}
      style={{
        color: "#e8fffb",
        fontSize: "18px",
        fontWeight: "600",
        letterSpacing: "2px",
        whiteSpace: "nowrap",
        pointerEvents: "none",
        textShadow: "0 1px 8px rgba(0,0,0,0.4)",
      }}
    >
      ULPF-X
    </Html>
  );
}
  

function DataLines() {
  const lines = useMemo(() => {
    const makeCurve = (
      points: [number, number, number][]
    ): THREE.Vector3[] => {
      const curve = new THREE.CatmullRomCurve3(
        points.map((p) => new THREE.Vector3(...p))
      );

      return curve.getPoints(40);
    };

    return [
      makeCurve([
        [-3.1, 1.1, 0],
        [-2, 0.8, 0],
        [-1, 0.35, 0],
        [0, 0, 0],
      ]),

      makeCurve([
        [3.1, 1.1, 0],
        [2, 0.8, 0],
        [1, 0.35, 0],
        [0, 0, 0],
      ]),

      makeCurve([
        [-2.7, -1.5, 0],
        [-1.8, -1, 0],
        [-0.9, -0.45, 0],
        [0, 0, 0],
      ]),

      makeCurve([
        [2.7, -1.5, 0],
        [1.8, -1, 0],
        [0.9, -0.45, 0],
        [0, 0, 0],
      ]),
    ];
  }, []);

  return (
    <>
      {lines.map((points, index) => (
        <Line
          key={index}
          points={points}
          color={index % 2 === 0 ? "#62c8bb" : "#72b6c7"}
          lineWidth={1.2}
          transparent
          opacity={0.65}
        />
      ))}
    </>
  );
}

function Particles() {
  const points = useMemo(() => {
    const count = 350;
    const positions = new Float32Array(count * 3);

    for (let i = 0; i < count; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 8;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 5;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 2;
    }

    return positions;
  }, []);

  const ref = useRef<THREE.Points>(null);

  useFrame((_, delta) => {
    if (!ref.current) return;

    ref.current.rotation.y += delta * 0.015;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          args={[points, 3]}
        />
      </bufferGeometry>

      <pointsMaterial
        size={0.025}
        color="#69bdb5"
        transparent
        opacity={0.5}
      />
    </points>
  );
}

function FloatingBox({
  position,
  title,
  subtitle,
  icon,
  color = "#edf5f3",
}: {
  position: [number, number, number];
  title: string;
  subtitle: string;
  icon: string;
  color?: string;
}) {
  const group = useRef<THREE.Group>(null);
  const [hovered, setHovered] = useState(false);

  useFrame(({ clock }) => {
    if (!group.current) return;

    group.current.position.y =
      position[1] +
      Math.sin(clock.elapsedTime * 1.2 + position[0]) * 0.06;
  });

  return (
    <group
      ref={group}
      position={position}
      scale={hovered ? 1.06 : 1}
      onPointerEnter={() => setHovered(true)}
      onPointerLeave={() => setHovered(false)}
    >
      {/* Main panel */}
      <mesh>
        <boxGeometry args={[1.25, 0.72, 0.06]} />
        <meshStandardMaterial
          color={hovered ? "#ffffff" : color}
          transparent
          opacity={0.96}
          roughness={0.28}
          metalness={0.08}
        />
      </mesh>

      {/* Panel border */}
      <mesh position={[0, 0, 0.055]}>
        <boxGeometry args={[1.16, 0.63, 0.015]} />
        <meshBasicMaterial
          color="#a7d8d4"
          wireframe
          transparent
          opacity={0.45}
        />
      </mesh>

      {/* Browser-rendered content */}
      <Html
        position={[0, 0, 0.08]}
        center
        transform
        distanceFactor={5}
        style={{
          width: "150px",
          padding: "12px 14px",
          pointerEvents: "none",
          userSelect: "none",
          color: "#1c3039",
          fontFamily:
            "Inter, ui-sans-serif, system-ui, -apple-system, sans-serif",
          background: "rgba(245, 250, 249, 0.88)",
          borderRadius: "12px",
          border: "1px solid rgba(90, 150, 150, 0.22)",
          boxShadow:
            "0 12px 35px rgba(30, 70, 80, 0.12)",
          backdropFilter: "blur(8px)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            marginBottom: "9px",
          }}
        >
          <span
            style={{
              fontSize: "20px",
              color: "#34515b",
            }}
          >
            {icon}
          </span>

          <span
            style={{
              fontSize: "16px",
              fontWeight: 600,
              letterSpacing: "0.2px",
            }}
          >
            {title}
          </span>
        </div>

        <div
          style={{
            fontSize: "15px",
            color: "#71858b",
            lineHeight: 1.5,
          }}
        >
          {subtitle}
        </div>

        <div
          style={{
            marginTop: "13px",
            width: "70px",
            height: "2px",
            background: "#73cbbd",
          }}
        />
      </Html>
    </group>
  );
}

function Scene() {
  return (
    <>
      <ambientLight intensity={1.8} />

      <directionalLight
        position={[4, 6, 5]}
        intensity={3}
      />

      <pointLight
        position={[-3, 2, 3]}
        color="#69d0c2"
        intensity={5}
        distance={7}
      />

      <pointLight
        position={[3, -2, 2]}
        color="#7bbccc"
        intensity={4}
        distance={7}
      />

      <Particles />

      <DataLines />

      <FloatingBox
        position={[-2.35, 0.95, 0]}
        title="Raw Logs"
        subtitle="syslog · json · cef"
        icon="▧"
      />

      <FloatingBox
        position={[-1.05, 1.55, 0]}
        title="Parser"
        subtitle="DSL / Rules"
        icon="</>"
      />

      <FloatingBox
        position={[2.35, 0.95, 0]}
        title="Normalized"
        subtitle="ULPF-IR structured data"
        icon="▤"
      />

      <FloatingBox
        position={[-1.45, -1.25, 0]}
        title="Lineage"
        subtitle="traceable & auditable"
        icon="⌘"
      />

      <FloatingBox
        position={[2.25, -1.15, 0]}
        title="Validation"
        subtitle="certified parsers"
        icon="◇"
      />

      <Core />
      <CoreLabel />
    </>
  );
}

export default function ULPFXScene() {
  return (
    <Canvas
      camera={{
        position: [0, 0, 7.5],
        fov: 38,
      }}
      dpr={[1, 2]}
      gl={{
        antialias: true,
        alpha: true,
      }}
      style={{
        width: "100%",
        height: "100%",
      }}
    >
      <Scene />
    </Canvas>
  );
}