import React from "react";
import styles from './Button.module.scss';

export default function Button(props) {
    return (
        <button 
            type = {props.type}
            className = {styles[props.buttonStyle]}
        >   
            {props.children}
        </button>
    )
}