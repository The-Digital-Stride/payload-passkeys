'use client'
// The only module that imports next/*. @payloadcms/ui 3.90 exports no router hooks (Verified
// facts Q4); when Payload 4 does, this file is the whole port.
export { useRouter, useSearchParams } from 'next/navigation.js'
