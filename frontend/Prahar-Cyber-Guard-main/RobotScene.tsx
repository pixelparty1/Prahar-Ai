import { useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Float, Environment, ContactShadows } from '@react-three/drei';
import * as THREE from 'three';

type RobotThemeConfig = {
  label: string;
  bodyColor: string;
  eyeColor: string;
  rimLight1Color: string;
  rimLight2Color: string;
  rimLight1Intensity: number;
  rimLight2Intensity: number;
  shadowColor: string;
  swatches: [string, string, string];
};

export const ROBOT_THEMES: Record<string, RobotThemeConfig> = {
  'Midnight Command': {
    label: 'Midnight Command',
    bodyColor: '#0a0f1c',
    eyeColor: '#00f0ff',
    rimLight1Color: '#3b82f6',
    rimLight2Color: '#00cc44',
    rimLight1Intensity: 50,
    rimLight2Intensity: 40,
    shadowColor: '#00f0ff',
    swatches: ['#3b82f6', '#0a0f1c', '#00f0ff'],
  },
  'Crimson Shadow': {
    label: 'Crimson Shadow',
    bodyColor: '#1a0505',
    eyeColor: '#ff2020',
    rimLight1Color: '#cc0000',
    rimLight2Color: '#ff6666',
    rimLight1Intensity: 52,
    rimLight2Intensity: 36,
    shadowColor: '#ff2020',
    swatches: ['#cc0000', '#1a0505', '#ff2020'],
  },
  'Monochrome Elite': {
    label: 'Monochrome Elite',
    bodyColor: '#1a1a1a',
    eyeColor: '#ffffff',
    rimLight1Color: '#cccccc',
    rimLight2Color: '#888888',
    rimLight1Intensity: 50,
    rimLight2Intensity: 34,
    shadowColor: '#ffffff',
    swatches: ['#cccccc', '#1a1a1a', '#ffffff'],
  },
  'Royal Obsidian': {
    label: 'Royal Obsidian',
    bodyColor: '#111111',
    eyeColor: '#aaaaaa',
    rimLight1Color: '#666666',
    rimLight2Color: '#444444',
    rimLight1Intensity: 48,
    rimLight2Intensity: 34,
    shadowColor: '#888888',
    swatches: ['#666666', '#111111', '#aaaaaa'],
  },
  'Sahara Dusk': {
    label: 'Sahara Dusk',
    bodyColor: '#1a1205',
    eyeColor: '#d4a96a',
    rimLight1Color: '#c8964a',
    rimLight2Color: '#e8c98a',
    rimLight1Intensity: 50,
    rimLight2Intensity: 38,
    shadowColor: '#d4a96a',
    swatches: ['#c8964a', '#1a1205', '#d4a96a'],
  },
  'Classic Dark': {
    label: 'Classic Dark',
    bodyColor: '#0a0f1c',
    eyeColor: '#00ff41',
    rimLight1Color: '#3b82f6',
    rimLight2Color: '#00cc44',
    rimLight1Intensity: 50,
    rimLight2Intensity: 40,
    shadowColor: '#00ff41',
    swatches: ['#3b82f6', '#0a0f1c', '#00ff41'],
  },
};

const APP_THEME_TO_ROBOT_THEME: Record<string, keyof typeof ROBOT_THEMES> = {
  midnight: 'Midnight Command',
  crimson: 'Crimson Shadow',
  monochrome: 'Monochrome Elite',
  obsidian: 'Royal Obsidian',
  sahara: 'Sahara Dusk',
  classic: 'Classic Dark',
  'Midnight Command': 'Midnight Command',
  'Crimson Shadow': 'Crimson Shadow',
  'Monochrome Elite': 'Monochrome Elite',
  'Royal Obsidian': 'Royal Obsidian',
  'Sahara Dusk': 'Sahara Dusk',
  'Classic Dark': 'Classic Dark',
};

function RobotMascot({ eyeColor, bodyColor }: { eyeColor: string; bodyColor: string }) {
  const headRef = useRef<THREE.Group>(null);
  const bodyMaterialRef = useRef<THREE.MeshStandardMaterial>(null);
  const innerMaterialRef = useRef<THREE.MeshStandardMaterial>(null);
  const leftEyeMaterialRef = useRef<THREE.MeshBasicMaterial>(null);
  const rightEyeMaterialRef = useRef<THREE.MeshBasicMaterial>(null);
  const { viewport } = useThree();

  const targetBodyColor = useMemo(() => new THREE.Color(bodyColor), [bodyColor]);
  const targetEyeColor = useMemo(() => new THREE.Color(eyeColor), [eyeColor]);
  const targetInnerColor = useMemo(() => {
    const color = new THREE.Color(bodyColor);
    color.multiplyScalar(0.45);
    return color;
  }, [bodyColor]);
  
  // Adjust scale based on screen size (responsive)
  const isMobile = viewport.width < 5;
  const scale = isMobile ? 0.7 : 1;
  const positionY = isMobile ? 1.5 : 0.8; 

  useFrame((state) => {
    if (!headRef.current) return;
    
    // Convert normalized device coordinates (-1 to +1) to 3D target coordinates
    // We amplify the X and Y bounds to make the head rotation more pronounced
    const targetX = state.pointer.x * (viewport.width / 2);
    const targetY = state.pointer.y * (viewport.height / 2);
    
    // Look-at point slightly ahead of the robot
    const targetZ = 6; 
    const target = new THREE.Vector3(targetX, targetY, targetZ);
    
    // Create a dummy object to calculate the ideal rotation
    const dummy = new THREE.Object3D();
    dummy.position.copy(headRef.current.position);
    dummy.lookAt(target);
    
    // Smoothly interpolate current rotation towards target rotation
    headRef.current.quaternion.slerp(dummy.quaternion, 0.08);

    const colorLerpSpeed = 0.12;
    if (bodyMaterialRef.current) {
      bodyMaterialRef.current.color.lerp(targetBodyColor, colorLerpSpeed);
    }
    if (innerMaterialRef.current) {
      innerMaterialRef.current.color.lerp(targetInnerColor, colorLerpSpeed);
    }
    if (leftEyeMaterialRef.current) {
      leftEyeMaterialRef.current.color.lerp(targetEyeColor, colorLerpSpeed);
    }
    if (rightEyeMaterialRef.current) {
      rightEyeMaterialRef.current.color.lerp(targetEyeColor, colorLerpSpeed);
    }
  });

  return (
    <Float speed={2} rotationIntensity={0.2} floatIntensity={1.2}>
      <group scale={scale} position={[0, positionY, 0]}>
        
        {/* Main Body (Sphere) */}
        <mesh position={[0, -1.3, 0]}>
          <sphereGeometry args={[1.1, 64, 64]} />
          <meshStandardMaterial
            ref={bodyMaterialRef}
            color={bodyColor}
            metalness={0.7}
            roughness={0.3}
            envMapIntensity={1.5}
          />
        </mesh>

        {/* Neck (Cylinder) */}
        <mesh position={[0, -0.1, 0]}>
          <cylinderGeometry args={[0.35, 0.45, 0.5, 32]} />
          <meshStandardMaterial
            ref={innerMaterialRef}
            color={`#${targetInnerColor.getHexString()}`}
            metalness={0.9}
            roughness={0.4}
          />
        </mesh>

        {/* Head Group - This receives the tracking rotation */}
        <group ref={headRef} position={[0, 0.6, 0]}>
          
          {/* Head Sphere */}
          <mesh>
            <sphereGeometry args={[0.9, 64, 64]} />
            <meshStandardMaterial
              color={bodyColor}
              metalness={0.7}
              roughness={0.3}
              envMapIntensity={1.5}
            />
          </mesh>

          {/* Left Eye */}
          <group position={[-0.35, 0.1, 0.8]} rotation={[Math.PI / 2, 0, 0]}>
            {/* Outer Rim */}
            <mesh position={[0, 0.05, 0]}>
              <cylinderGeometry args={[0.25, 0.25, 0.1, 32]} />
              <meshStandardMaterial
                color={`#${targetInnerColor.getHexString()}`}
                metalness={0.9}
                roughness={0.4}
              />
            </mesh>
            {/* Inner Lens Dark Glass */}
            <mesh position={[0, 0.1, 0]}>
              <cylinderGeometry args={[0.2, 0.2, 0.11, 32]} />
              <meshStandardMaterial color="#000000" metalness={1} roughness={0.1} />
            </mesh>
            {/* Glowing Pupil */}
            <mesh position={[0, 0.15, 0]}>
              <cylinderGeometry args={[0.08, 0.08, 0.12, 32]} />
              <meshBasicMaterial ref={leftEyeMaterialRef} color={eyeColor} />
            </mesh>
          </group>

          {/* Right Eye */}
          <group position={[0.35, 0.1, 0.8]} rotation={[Math.PI / 2, 0, 0]}>
            <mesh position={[0, 0.05, 0]}>
              <cylinderGeometry args={[0.25, 0.25, 0.1, 32]} />
              <meshStandardMaterial
                color={`#${targetInnerColor.getHexString()}`}
                metalness={0.9}
                roughness={0.4}
              />
            </mesh>
            <mesh position={[0, 0.1, 0]}>
              <cylinderGeometry args={[0.2, 0.2, 0.11, 32]} />
              <meshStandardMaterial color="#000000" metalness={1} roughness={0.1} />
            </mesh>
            <mesh position={[0, 0.15, 0]}>
              <cylinderGeometry args={[0.08, 0.08, 0.12, 32]} />
              <meshBasicMaterial ref={rightEyeMaterialRef} color={eyeColor} />
            </mesh>
          </group>
          
        </group>
      </group>
    </Float>
  );
}

export function RobotScene({ appTheme }: { appTheme: string }) {
  const mappedThemeName = APP_THEME_TO_ROBOT_THEME[appTheme] ?? 'Midnight Command';
  const t = ROBOT_THEMES[mappedThemeName];

  return (
    <div className="absolute inset-0 z-0">
      <Canvas
        camera={{ position: [0, 0, 8], fov: 45 }}
        gl={{ antialias: true, alpha: true }}
      >
        <color attach="background" args={['#000000']} />
        
        {/* Soft Ambient Light for base visibility */}
        <ambientLight intensity={0.4} color="#ffffff" />
        
        {/* Soft Key Light from top-left */}
        <directionalLight 
          position={[-5, 5, 5]} 
          intensity={1} 
          color="#ffffff" 
        />
        
        {/* Dramatic Rim Lights (Cyan and Purple) */}
        <spotLight 
          position={[5, 5, -5]} 
          intensity={t.rimLight1Intensity} 
          distance={20}
          color={t.rimLight1Color} 
          angle={0.5}
          penumbra={1}
        />
        <spotLight 
          position={[-5, -5, -5]} 
          intensity={t.rimLight2Intensity} 
          distance={20}
          color={t.rimLight2Color} 
          angle={0.5}
          penumbra={1}
        />

        {/* The 3D Robot Mascot */}
        <RobotMascot
          eyeColor={t.eyeColor}
          bodyColor={t.bodyColor}
        />
        
        {/* Studio environment for premium metallic reflections */}
        <Environment preset="city" />
        
        {/* Ground shadow for depth */}
        <ContactShadows 
          position={[0, -2, 0]} 
          opacity={0.6} 
          scale={10} 
          blur={2.5} 
          far={4} 
          color={t.shadowColor}
        />
      </Canvas>
    </div>
  );
}
