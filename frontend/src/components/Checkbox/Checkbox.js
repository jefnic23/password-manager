import React from "react";
import styles from './Checkbox.module.scss';

/**
 * Builds an HTML checkbox input element.
 */
export default function Checkbox(props) {
    return (
        <div className={styles.checkbox}>
            <label>
                <input 
                    type = 'checkbox'
                    checked = {props.checked}
                    onChange = {props.onChange}
                />
                {props.label}
            </label>
        </div>
    )
}