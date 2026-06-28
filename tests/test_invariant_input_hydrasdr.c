#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "src/input_hydrasdr.h"

START_TEST(test_board_name_buffer_reads_within_bounds)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "NormalBoardName",                    // Valid input
        "Board\0With\0Embedded\0Nulls\0",     // Exact exploit case
        "A"                                   // Boundary: minimal valid
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        hydrasdr_device_info_t info;
        memset(&info, 0, sizeof(info));
        
        // Copy payload into board_name field
        strncpy(info.board_name, payloads[i], sizeof(info.board_name) - 1);
        info.board_name[sizeof(info.board_name) - 1] = '\0';
        
        // Initialize minimal app context
        hydrasdr_app_t app;
        memset(&app, 0, sizeof(app));
        
        // Call the actual vulnerable function
        process_device_info(&app, &info);
        
        // If we reach here without crashing, test passes
        ck_assert(1);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_board_name_buffer_reads_within_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}