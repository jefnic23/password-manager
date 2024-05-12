import type { Writable } from "svelte/store";
import { writable } from "svelte/store";
import browser from "webextension-polyfill";

export async function getToken(token: string): Promise<string | null> {
    const result = await browser.storage.local.get(token);
    if (result[token]) {
        console.log(`${token} retrieved from storage.`);
        return result[token];
    } else {
        console.log(`${token} not found.`);
        return null;
    }
}

async function saveToken(token: Record<string, string>): Promise<void> {
    try {
        await browser.storage.local.set(token);
    } catch {
        console.log(`Error saving token.`);
    } finally {
        console.log(`token saved.`);
    }
}


// let savedAccessToken: string | null = await getToken("accessToken");
export let accessToken: Writable<string> = writable("");
accessToken.subscribe(async token => await saveToken({ accessToken: token }));

// let savedRefreshToken: string | null = await getToken("refreshToken");
export let refreshToken: Writable<string> = writable("");
refreshToken.subscribe(async token => await saveToken({ refreshToken: token }));
