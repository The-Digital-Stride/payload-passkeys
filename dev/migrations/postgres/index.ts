import * as migration_20261106_230822_initial from './20261106_230822_initial';

export const migrations = [
  {
    up: migration_20261106_230822_initial.up,
    down: migration_20261106_230822_initial.down,
    name: '20261106_230822_initial'
  },
];
