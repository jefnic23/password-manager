import React from "react";
import styles from './Form.module.scss';

/**
 * Builds an HTML form element, with inputs passed as props.
 * @param {*} props 
 * @returns 
 */
export default function Form(props) {
    return (
        <form className={styles.form} onSubmit={props.handleSubmit}>
            {props.children}
        </form>
    )
}