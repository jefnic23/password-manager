import React from "react";
import styles from './TextInput.module.scss';

/**
 * Builds an HTML text input element.
 */
export default function TextInput(props) {
    return (
        <input 
            className={styles.input}
            id = {props.id}
            autoFocus = {props.autoFocus}
            placeholder = {props.placeholder}
            type = {props.type}
            value = {props.value}
            onChange = {e => props.onChange(e.target.value)}
            required = {props.required}
        />
    )
}