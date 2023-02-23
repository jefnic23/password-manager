const Reducer = (state, action) => {
    const { type, payload } = action;

    switch (type) {
        case "SET_TOKEN":
            return {
                ...state,
                token: payload,
            };
        case "SET_AUTHENTICATED":
            return {
                ...state,
                authenticated: payload,
            };
        default:
            return state;
    }
};

export default Reducer;
