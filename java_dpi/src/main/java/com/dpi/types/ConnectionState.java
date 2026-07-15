package com.dpi.types;

/** Connection lifecycle state. Maps to ConnectionState enum in types.h. */
public enum ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
}
