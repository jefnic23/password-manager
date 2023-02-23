import React, { createContext, useReducer } from 'react';
import Reducer from './Reducer';

const initialState = {
    token: null,
    authenticated: false
};

const StateProvider = ({ children }) => {
    const [state, dispatch] = useReducer(Reducer, initialState);

    return (
        <Context.Provider value={[ state, dispatch ]}>
            {children}
        </Context.Provider>
    );
};

export const Context = createContext();
export default StateProvider;
