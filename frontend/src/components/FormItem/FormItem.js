import React from "react";
import styles from './FormItem.module.scss';

/**
 * Builds an HTML text input element.
 */
export default function FormItem(props) {
    return (
        <div className={styles.formItem}>
            {props.children}
        </div>
    )
}
