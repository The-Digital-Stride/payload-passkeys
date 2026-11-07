import type { UIFieldServerProps } from 'payload'

import React from 'react'

import { PasskeysManager } from '../PasskeysManager/index.js'
import { shouldRenderManager } from './shouldRender.js'

export const PasskeysManagerField = (props: UIFieldServerProps) =>
  shouldRenderManager(props) ? <PasskeysManager collectionSlug={props.collectionSlug} /> : null
