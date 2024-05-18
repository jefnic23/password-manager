<script lang="ts">
	import { onMount } from "svelte";
	import Login from "@components/Login.svelte";
	import { jwtDecode } from "jwt-decode";
	import { accessToken, refreshToken } from "@stores/tokens";
	import { user, getUser } from "@stores/users";

	onMount(async () => {
		if ($accessToken && $refreshToken) {
			const decodedAccessToken = jwtDecode($accessToken);
			if (
				(decodedAccessToken.exp as number) >
				Math.floor(Date.now() / 1000)
			) {
				user.set(await getUser($accessToken));
			}
		}
	});

	// on mount, check for access and refresh tokens
	// if access token, attempt to get user
	// else, show login
	// if user attempt successful, show user
	// else, attempt refresh
	// if refresh successful, get user
	// else, show login screen
</script>

<div>
	<img src="/icon.png" alt="" />
	{#if $user}
		<p>
			Welcome, {$user}
		</p>
	{:else}
		<Login />
	{/if}
</div>

<style>
	img {
		width: 128px;
		height: 128px;
		filter: drop-shadow(0 0 2em #ffcc00);
		margin-bottom: 3rem;
	}
</style>
