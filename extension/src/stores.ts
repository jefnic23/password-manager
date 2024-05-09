import type { Writable } from "svelte/store";
import { writable } from "svelte/store";
import browser from "webextension-polyfill";

export async function getAccessToken(): Promise<string | null> {
    const result = await browser.storage.local.get("accessToken");
    if (result.accessToken) {
        console.log("Access token retrieved from storage.");
        return result.accessToken;
    } else {
        console.log("Access token not found.");
        return null;
    }
}

export async function saveAccessToken(token: string): Promise<void> {
    try {
        await browser.storage.local.set({ accessToken: token });
    } catch {
        console.log("Error saving access token.");
    } finally {
        console.log("Access token saved.");
    }
}


let savedAccessToken: string | null = await getAccessToken();
export let accessToken: Writable<string> = writable(savedAccessToken || "");
accessToken.subscribe(async token => await saveAccessToken(token));
