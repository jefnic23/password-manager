import React from "react";
import styles from './Container.module.scss';

export default function Container(props) {
    return (
        <div className={styles.center}>
            {props.children}
        </div>
    )
}