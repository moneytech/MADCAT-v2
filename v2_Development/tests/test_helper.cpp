#include "gtest/gtest.h"

extern "C" {
  #include "madcat.helper.h"
  #include "madcat.common.h"
  #include <stdlib.h>
  #include <strings.h>
  #include <time.h>
}

/* test fixture
class MadCatHelper : public ::testing::Test {
 protected:
  virtual void SetUp() {

  }
  //virtual void TearDown() {}

};*/

TEST(time_str, unix_time) {
  int size = 4096;
  char * unix_buf = (char*)malloc(size);
  char * readable_buf = (char*)malloc(size);

  struct timeval tv;
  char tmbuf_1[size];
  char tmzone_1[6]; //e.g. "+0100\0" is max. 6 chars

  gettimeofday(&tv, NULL); //fetch struct timeval with actuall time and convert it to string...
  strftime(tmbuf_1, size, "%Y-%m-%dT%H:%M:%S", localtime(&tv.tv_sec)); //Target format: "2018-08-17T05:51:53.835934", therefore...
  strftime(tmzone_1, 6, "%z", localtime(&tv.tv_sec)); //...get timezone...>

  time_str(unix_buf,size,readable_buf,size);

  if (readable_buf != NULL) {
      //snprintf(readable_buf, readable_size, "%s.%06ld%s", tmbuf, tv.tv_usec, tmzone); readable_buf[readable_size-1] = 0; //Human readable string
  }
  if (unix_buf != NULL) {
      //snprintf(unix_buf, unix_size, "%lu.%lu", tv.tv_sec, tv.tv_usec); unix_buf[unix_size-1] = 0; //Unix time incl. usec
  }

  ASSERT_EQ(1, 1);
}


TEST(time_str, readable_time) {
  int size = 4096;
  char * unix_buf = (char*)malloc(size);
  char * readable_buf = (char*)malloc(size);


  time_str(unix_buf,size,readable_buf,size);

  printf("%s\n",readable_buf);

  ASSERT_EQ(1, 1);
}
