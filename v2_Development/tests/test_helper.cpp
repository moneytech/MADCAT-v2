#include "gtest/gtest.h"

extern "C" {
  #include "madcat.helper.h"
  #include "madcat.common.h"
}

TEST(test1, ok) {
  

  ASSERT_EQ(1, 1);
}

TEST(FehlerDummy, not_ok) {
  ASSERT_EQ(1, 0);
}