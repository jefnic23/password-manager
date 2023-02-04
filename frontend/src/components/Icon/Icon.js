import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import styles from './Icon.module.scss';

export default function Icon(props) {
    return (
        <span className={styles.icon}>
            <FontAwesomeIcon icon={props.icon} size={props.size} />
        </span>
    )
}