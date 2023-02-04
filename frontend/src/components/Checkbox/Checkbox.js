import React from "react";

/**
 * Builds an HTML checkbox input element.
 */
export default function Checkbox(props) {
    return (
        <div>
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