import type { UIFieldServerProps } from 'payload'

/**
 * Own document only (Verified facts Q2). Compares req.user, not the `user` prop, which has field
 * read access applied. Nothing on create or on anyone else's document.
 */
export const shouldRenderManager = ({
  collectionSlug,
  id,
  operation,
  req,
}: Pick<UIFieldServerProps, 'collectionSlug' | 'id' | 'operation' | 'req'>): boolean => {
  const user = req?.user
  if (operation !== 'update' || id === undefined || id === null) return false
  return Boolean(user && user.collection === collectionSlug && String(user.id) === String(id))
}
