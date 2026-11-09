import type { UIFieldServerProps } from 'payload'

import React from 'react'

import type { Reauthentication } from '../shared/reauthentication.js'

import { PasskeysManager } from '../PasskeysManager/index.js'
import { shouldRenderManager } from './shouldRender.js'

export const PasskeysManagerField = (props: UIFieldServerProps) =>
  shouldRenderManager(props) ? (
    <PasskeysManager
      collectionSlug={props.collectionSlug}
      // From the field's clientProps (src/collections/userFields.ts).
      reauthentication={(props as { reauthentication?: Reauthentication }).reauthentication}
    />
  ) : null
