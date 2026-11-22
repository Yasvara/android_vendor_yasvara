package hidden;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

import dalvik.system.BaseDexClassLoader;

/**
 * A class loader over in-memory dex files.
 *
 * <p>Yasvara: upstream extends BaseDexClassLoader through its hidden ByteBuffer constructors,
 * which a platform build cannot name. This does what those constructors do: build an empty
 * loader through the public one, then hand the buffers to its DexPathList. Only ever called from
 * code the platform already trusts, so the reflection is not subject to the hidden API checks.
 */
public class ByteBufferDexClassLoader extends BaseDexClassLoader {

    public ByteBufferDexClassLoader(ByteBuffer[] dexFiles, ClassLoader parent) {
        this(dexFiles, null, parent);
    }

    public ByteBufferDexClassLoader(ByteBuffer[] dexFiles, String librarySearchPath, ClassLoader parent) {
        super("", null, librarySearchPath, parent);
        try {
            Field pathListField = BaseDexClassLoader.class.getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object pathList = pathListField.get(this);
            Field elements = pathList.getClass().getDeclaredField("dexElements");
            elements.setAccessible(true);
            elements.set(pathList, null); // initByteBufferDexPath insists on being the first
            Method init = pathList.getClass()
                    .getDeclaredMethod("initByteBufferDexPath", ByteBuffer[].class);
            init.setAccessible(true);
            init.invoke(pathList, (Object) dexFiles);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot attach in-memory dex files", e);
        }
    }
}
