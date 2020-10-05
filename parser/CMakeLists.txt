cmake_minimum_required(VERSION 3.10)
project(parser C)

set(CMAKE_C_STANDARD 11)

add_executable(test_transaction_parser test_transaction_parser.c transaction_parser.c)
target_link_libraries(test_transaction_parser PUBLIC cmocka)

add_executable(test_transaction_printer test_transaction_printer.c transaction_printer.c transaction_parser.c printers.c transaction_summary.c)
target_link_libraries(test_transaction_printer PUBLIC cmocka)
