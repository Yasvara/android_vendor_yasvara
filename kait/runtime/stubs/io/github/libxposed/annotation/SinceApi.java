package io.github.libxposed.annotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** Compile-only stand-in for io.github.libxposed:annotation (CLASS retained, no behaviour). */
@Retention(RetentionPolicy.CLASS)
public @interface SinceApi {
    int value();
}
