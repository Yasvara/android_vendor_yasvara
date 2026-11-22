/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.vibrator;

public final class RabaProfileTest {
    private static int sFailed;

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        if (!ok) sFailed++;
    }

    private static boolean is(RabaProfile.Tone t, int wave, float scale) {
        return t != null && t.wave == wave && Math.abs(t.scale - scale) < 1e-4f;
    }

    public static void main(String[] args) {
        RabaProfile d = RabaProfile.parse(null);
        check("default is HyperOS", d.profile() == RabaProfile.PROFILE_HYPEROS);
        check("default master 1", d.master() == 1f);
        check("default reskins", d.reskin());
        check("tap = wave 6 full", is(d.tone(RabaProfile.VIRTUAL_KEY), 6, 1f));
        check("key release light", is(d.tone(RabaProfile.VIRTUAL_KEY_RELEASE), 6, 0.375f));
        check("keyboard = wave 8", is(d.tone(RabaProfile.KEYBOARD_TAP), 8, 1f));
        check("switch = wave 10", is(d.tone(RabaProfile.TOGGLE_ON), 10, 1f));
        check("scroll edge = wave 8 @ 0.375", is(d.tone(RabaProfile.SCROLL_LIMIT), 8, 0.375f));
        check("long press = wave 1 @ 0.625", is(d.tone(RabaProfile.LONG_PRESS), 1, 0.625f));
        check("drag start = wave 3", is(d.tone(RabaProfile.DRAG_START), 3, 1f));
        check("pull threshold = wave 3 @ 0.375",
                is(d.tone(RabaProfile.GESTURE_THRESHOLD_ACTIVATE), 3, 0.375f));
        check("reject = double", is(d.tone(RabaProfile.REJECT), 2, 1f));
        check("hardware constants stay platform", d.tone(10002) == null && d.tone(10004) == null);
        check("unlisted constant stays platform", d.tone(14) == null && d.tone(-1) == null);
        for (int c = 0; c < RabaProfile.CATEGORY_KEYS.length; c++) {
            RabaProfile.Category lead = RabaProfile.hyperOsCategory(c);
            check("lead of " + RabaProfile.CATEGORY_KEYS[c],
                    lead.on && lead.wave >= 1 && lead.wave <= RabaProfile.WAVES);
        }

        RabaProfile pixel = RabaProfile.parse("{\"profile\":\"pixel\",\"master\":0.6}");
        check("pixel: platform table", pixel.tone(RabaProfile.VIRTUAL_KEY) == null
                && pixel.tone(RabaProfile.TOGGLE_ON) == null);
        check("pixel: no reskin", !pixel.reskin());
        check("pixel: master kept", Math.abs(pixel.master() - 0.6f) < 1e-6);

        // What Laras writes.
        RabaProfile custom = RabaProfile.parse("{\"profile\":\"custom\",\"master\":1.2,"
                + "\"reskin\":false,\"categories\":{"
                + "\"taps\":{\"on\":true,\"wave\":9,\"strength\":0.5},"
                + "\"switches\":{\"on\":false,\"wave\":10,\"strength\":1},"
                + "\"ticks\":{\"on\":true,\"wave\":3,\"strength\":1.0}}}");
        check("custom: edited lead", is(custom.tone(RabaProfile.VIRTUAL_KEY), 9, 0.5f));
        check("custom: weight kept", is(custom.tone(RabaProfile.VIRTUAL_KEY_RELEASE), 9, 0.1875f));
        check("custom: other texture follows", is(custom.tone(RabaProfile.CALENDAR_DATE), 9, 0.5f));
        check("custom: off", custom.tone(RabaProfile.TOGGLE_ON).isOff()
                && custom.tone(RabaProfile.TOGGLE_OFF).isOff());
        check("custom: weight clamps", is(custom.tone(RabaProfile.CLOCK_TICK), 3, 1f));
        check("custom: unedited stays HyperOS", is(custom.tone(RabaProfile.KEYBOARD_TAP), 8, 1f));
        check("custom: reskin off", !custom.reskin());
        check("custom: master", Math.abs(custom.master() - 1.2f) < 1e-6);

        RabaProfile hyperWithEdits = RabaProfile.parse("{\"profile\":\"hyperos\",\"categories\":"
                + "{\"taps\":{\"on\":false,\"wave\":9,\"strength\":0.5}}}");
        check("hyperos ignores stored edits", is(hyperWithEdits.tone(RabaProfile.VIRTUAL_KEY), 6, 1f));

        check("malformed: default", RabaProfile.parse("{nope").profile() == RabaProfile.PROFILE_HYPEROS);
        check("not an object: default", RabaProfile.parse("[1,2]").tone(RabaProfile.VIRTUAL_KEY) != null);
        RabaProfile wild = RabaProfile.parse("{\"profile\":\"turbo\",\"master\":9,\"future\":[1],"
                + "\"categories\":{\"taps\":{\"wave\":12},\"edges\":{\"wave\":4,\"strength\":0},"
                + "\"keyboard\":\"x\"}}");
        check("unknown profile: HyperOS", wild.profile() == RabaProfile.PROFILE_HYPEROS);
        check("master clamps", wild.master() == RabaProfile.MASTER_MAX);
        RabaProfile wildCustom = RabaProfile.parse("{\"profile\":\"custom\",\"master\":-1,"
                + "\"categories\":{\"taps\":{\"wave\":12},\"edges\":{\"wave\":4,\"strength\":0}}}");
        check("bad wave ignored", is(wildCustom.tone(RabaProfile.VIRTUAL_KEY), 6, 1f));
        check("strength floor", is(wildCustom.tone(RabaProfile.SCROLL_LIMIT), 4, RabaProfile.STRENGTH_MIN));
        check("negative master clamps", wildCustom.master() == 0f);

        check("boost: none at 100 %", d.textureBoost() == 0f);
        check("boost: full at 150 %", RabaProfile.parse("{\"master\":1.5}").textureBoost() == 1f);
        check("boost: half at 125 %",
                Math.abs(RabaProfile.parse("{\"master\":1.25}").textureBoost() - 0.5f) < 1e-4f);
        check("boost: none below 100 %", RabaProfile.parse("{\"master\":0.6}").textureBoost() == 0f);
        check("boost: none under Pixel",
                RabaProfile.parse("{\"profile\":\"pixel\",\"master\":1.5}").textureBoost() == 0f);

        int[][] reskin = RabaProfile.reskinTable();
        boolean ok = reskin.length > 0;
        for (int[] pair : reskin) ok &= pair[0] >= 1 && pair[0] <= 8 && pair[1] >= 1 && pair[1] <= 11;
        check("reskin table in range", ok);

        if (sFailed > 0) {
            System.out.println(sFailed + " failed");
            System.exit(1);
        }
        System.out.println("all passed");
    }
}
