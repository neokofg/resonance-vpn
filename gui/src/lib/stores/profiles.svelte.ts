import { Store } from '@tauri-apps/plugin-store';

export interface ServerProfile {
  id: string;
  name: string;
  server: string;
  psk: string;
  dns: string[];
  lastConnected?: number;
}

class ProfilesStore {
  profiles = $state<ServerProfile[]>([]);
  activeProfileId = $state<string | null>(null);
  private store: Store | null = null;

  get activeProfile(): ServerProfile | undefined {
    return this.profiles.find(p => p.id === this.activeProfileId);
  }

  async init() {
    this.store = await Store.load('profiles.json');
    const saved = await this.store.get<ServerProfile[]>('profiles');
    if (saved) this.profiles = saved;
    const activeId = await this.store.get<string>('activeProfileId');
    if (activeId) this.activeProfileId = activeId;
  }

  private async save() {
    if (!this.store) return;
    await this.store.set('profiles', this.profiles);
    await this.store.set('activeProfileId', this.activeProfileId);
    await this.store.save();
  }

  async addProfile(profile: Omit<ServerProfile, 'id'>) {
    const id = crypto.randomUUID();
    this.profiles = [...this.profiles, { ...profile, id }];
    if (!this.activeProfileId) this.activeProfileId = id;
    await this.save();
    return id;
  }

  async updateProfile(id: string, updates: Partial<ServerProfile>) {
    this.profiles = this.profiles.map(p => p.id === id ? { ...p, ...updates } : p);
    await this.save();
  }

  async deleteProfile(id: string) {
    this.profiles = this.profiles.filter(p => p.id !== id);
    if (this.activeProfileId === id) this.activeProfileId = this.profiles[0]?.id ?? null;
    await this.save();
  }

  async setActive(id: string) {
    this.activeProfileId = id;
    await this.save();
  }

  async touchLastConnected(id: string) {
    await this.updateProfile(id, { lastConnected: Date.now() });
  }
}

export const profilesStore = new ProfilesStore();
