import type { Writable } from 'svelte/store';
import { writable } from 'svelte/store';

let savedAccessToken: string | null = localStorage.getItem('access_token');
export let accessToken: Writable<string> = writable(savedAccessToken || '');
accessToken.subscribe(value => localStorage.setItem('access_token', value));
