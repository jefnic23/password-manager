<script lang="ts">
    import { accessToken, refreshToken } from "@stores/tokens";
    import { user, getUser } from "@stores/users";
    import type { Token } from "@interfaces/token";

    async function handleSubmit(event: Event): Promise<void> {
        const formEl = event.target as HTMLFormElement;
        const data = new FormData(formEl);

        const response = await fetch(formEl.action, {
            method: formEl.method,
            body: data,
        });

        if (response.status == 200) {
            const responseData: Token = await response.json();
            accessToken.update(t => t = responseData.accessToken);
            refreshToken.update(t => t = responseData.refreshToken);
            user.set(await getUser($accessToken));
        } else if (response.status == 401) {
            console.log("Username or password incorrect.");
        } else {
            console.log("Error logging in.");
        }
    }
</script>

<div>
    <form
        method="post"
        action="http://127.0.0.1:8000/login"
        on:submit|preventDefault={handleSubmit}
    >
        <input type="text" name="username" placeholder="email" />
        <input type="password" name="password" placeholder="password" />
        <button type="submit">Submit</button>
    </form>
</div>
