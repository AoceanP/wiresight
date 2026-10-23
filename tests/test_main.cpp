#include "test.hpp"

#include <exception>
#include <iostream>

/**
 * WHAT:   Runs every registered test and prints PASSED or FAILED for each.
 * WHY:    A non-zero exit code lets CTest and CI mark the build as failed.
 * RETURN: 0 if all tests passed, 1 otherwise
 *
 * @return the process exit code
 */
int main()
{
	int failed = 0;
	for (const test::Case& testCase : test::registry())
	{
		try
		{
			testCase.body();
			std::cout << testCase.name << " PASSED\n";
		}
		catch (const test::Failure& failure)
		{
			++failed;
			std::cout << testCase.name << " FAILED\n    " << failure.message << '\n';
		}
		catch (const std::exception& error)
		{
			++failed;
			std::cout << testCase.name << " FAILED\n    unexpected exception: " << error.what() << '\n';
		}
	}

	const std::size_t total = test::registry().size();
	std::cout << '\n' << total - static_cast<std::size_t>(failed) << " of " << total << " tests passed\n";
	return failed == 0 ? 0 : 1;
}
