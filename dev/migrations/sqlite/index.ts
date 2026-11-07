import * as migration_20261106_230824_initial from './20261106_230824_initial';

export const migrations = [
  {
    up: migration_20261106_230824_initial.up,
    down: migration_20261106_230824_initial.down,
    name: '20261106_230824_initial'
  },
];
