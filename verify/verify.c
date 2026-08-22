// sandbox_verify.c
//
// Standalone, no cargo needed:
//   cc sandbox_verify.c -o sandbox_verify
//   ./sandbox_verify
//
// Checks three things runbox-helper's redesign depends on:
//   1. confstr(_CS_DARWIN_USER_TEMP_DIR) resolves to a real path — using
//      the system header's constant, not a hardcoded number.
//   2. sandbox_init_with_parameters links and accepts a literal SBPL
//      profile string with a (param "TMPDIR") reference.
//   3. The compiled profile actually enforces: write inside TMPDIR
//      succeeds, write to $HOME fails.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

// sandbox.h is private and often not installed by Xcode CLT — declared
// manually here, matching what runbox-helper will need to do in Rust.
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                         const char *const parameters[],
                                         char **errorbuf);
extern void sandbox_free_error(char *errorbuf);

int main(void) {
    char tmpdir[1024];
    size_t len = confstr(_CS_DARWIN_USER_TEMP_DIR, tmpdir, sizeof(tmpdir));
    if (len == 0) {
        perror("confstr(_CS_DARWIN_USER_TEMP_DIR) failed");
        return 1;
    }
    if (tmpdir[strlen(tmpdir) - 1] == '/') {
        tmpdir[strlen(tmpdir) - 1] = '\0';
    }
    printf("resolved TMPDIR (symlinked form): %s\n", tmpdir);

    // /var/folders/... is itself a symlink to /private/var/folders/... —
    // Seatbelt's subpath matching operates on the real, canonicalized
    // path, not the symlinked alias. Resolve it before using it as the
    // sandbox parameter, same reasoning system.sb applies to /etc, /tmp,
    // /var themselves.
    char real_tmpdir[PATH_MAX];
    if (realpath(tmpdir, real_tmpdir) == NULL) {
        perror("realpath failed");
        return 1;
    }
    printf("resolved TMPDIR (real path):      %s\n", real_tmpdir);

    const char *profile =
        "(version 1)\n"
        "(deny default)\n"
        "(allow file-read-metadata (literal \"/var\") (literal \"/tmp\"))\n"
        "(allow file-read* file-write* (subpath (param \"TMPDIR\")))\n"
        "(allow file-read* (literal \"/\"))\n"
        "(allow file-read-metadata (literal \"/\"))\n";

    const char *params[] = { "TMPDIR", real_tmpdir, NULL };
    char *errorbuf = NULL;

    int ret = sandbox_init_with_parameters(profile, 0, params, &errorbuf);
    if (ret != 0) {
        fprintf(stderr, "sandbox_init_with_parameters FAILED: %s\n",
                errorbuf ? errorbuf : "(no error message)");
        if (errorbuf) sandbox_free_error(errorbuf);
        return 1;
    }
    printf("sandbox_init_with_parameters: OK, profile applied\n");

    char inside_path[1200];
    snprintf(inside_path, sizeof(inside_path), "%s/runbox_sandbox_test.txt", tmpdir);
    FILE *f = fopen(inside_path, "w");
    if (f) {
        fprintf(f, "ok");
        fclose(f);
        remove(inside_path);
        printf("write inside TMPDIR: ALLOWED (expected)\n");
    } else {
        printf("write inside TMPDIR: DENIED (%s) -- UNEXPECTED, profile too strict\n", strerror(errno));
    }

    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char outside_path[1200];
    snprintf(outside_path, sizeof(outside_path), "%s/runbox_sandbox_test_should_fail.txt", home);
    FILE *f2 = fopen(outside_path, "w");
    if (f2) {
        fprintf(f2, "should not happen");
        fclose(f2);
        remove(outside_path);
        printf("write outside TMPDIR (to $HOME): ALLOWED -- WRONG, sandbox not enforcing\n");
    } else {
        printf("write outside TMPDIR (to $HOME): DENIED (%s) -- expected, sandbox working\n", strerror(errno));
    }

    return 0;
}
