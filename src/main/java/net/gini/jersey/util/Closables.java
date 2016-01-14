package net.gini.jersey.util;

import java.io.Closeable;
import java.io.IOException;

/**
 * Utility methods for {@link Closeable} objects.
 */
public final class Closables {
    private Closables() {
    }

    public static void closeQuietly(final Closeable closeable) {
        if (closeable == null) {
            return;
        }

        try {
            closeable.close();
        } catch (IOException e) {
            // Swallow exception
        }
    }
}
