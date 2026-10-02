import { useMemo } from 'react'

interface SvgIconProps {
  svg: string
  className?: string
  alt?: string
}

export function SvgIcon({ svg, className, alt = '' }: SvgIconProps) {
  const dataUri = useMemo(
    () => `data:image/svg+xml;base64,${btoa(svg)}`,
    [svg]
  )

  return <img src={dataUri} className={className} alt={alt} />
}
