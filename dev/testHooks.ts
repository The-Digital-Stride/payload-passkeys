type Hook = ((args: Record<string, unknown>) => unknown) | null

export const testHooks = {
  afterLogin: null as Hook,
  beforeLogin: null as Hook,
  onSignIn: null as Hook,
  reset() {
    this.afterLogin = null
    this.beforeLogin = null
    this.onSignIn = null
  },
}
