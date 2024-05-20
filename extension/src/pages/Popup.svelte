<script lang="ts">
	import { onMount } from "svelte";
	import Login from "@components/Login.svelte";
	import { accessToken, refreshToken } from "@stores/tokens";
	import { user, getUser } from "@stores/users";
	import { type Token, isExpired } from "@interfaces/token";

	onMount(async () => {
		if ($accessToken && $refreshToken) {
			if (isExpired($accessToken)) {
				user.set(await getUser($accessToken));
			} else {
				const response = await fetch(`http://127.0.0.1:8000/refresh`, {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
					body: JSON.stringify({ refreshToken: $refreshToken }),
				});

				if (response.status === 200) {
					const responseData: Token = await response.json();
					accessToken.set(responseData.accessToken);
					refreshToken.set(responseData.refreshToken);
					user.set(await getUser($accessToken));
				} else {
					console.log("Error logging in.");
				}
			}
		}
	});
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
