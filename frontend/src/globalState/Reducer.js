const Reducer = (state, action) => {
    switch (action.type) {
        case "SET_TOKEN":
            return {
                ...state,
                token: action.payload,
            };
        case "SET_AUTHENTICATED":
            return {
                ...state,
                authenticated: action.payload,
            };
        default:
            return state;
    }
};

export default Reducer;
