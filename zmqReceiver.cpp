#include "include.h"
#include <assert.h>

#define USE_ENCRYPTION

int main(int argc, char *argv[]) {
  int is_server = 1;
  void *context = zmq_ctx_new();
  void *subscriber = zmq_socket(context, ZMQ_SUB);
  int rc;
  char sub_public_key[41];
  char sub_secret_key[41];
  char message[13];

#ifdef USE_ENCRYPTION
  rc = zmq_curve_keypair(sub_public_key, sub_secret_key);
  assert(rc == 0);
  
  rc = zmq_setsockopt(subscriber, ZMQ_CURVE_SECRETKEY, sub_secret_key, strlen(sub_secret_key));
  assert(rc == 0);
  
  rc = zmq_setsockopt(subscriber, ZMQ_CURVE_PUBLICKEY, sub_public_key, strlen(sub_public_key));
  assert(rc == 0);
  
  rc = zmq_setsockopt(subscriber, ZMQ_CURVE_SERVER,    &is_server,     sizeof(is_server));
  assert(rc == 0);
  
  printf("Use ZMQ server key: %s\n", sub_public_key);
#endif
  
  rc = zmq_bind(subscriber, "tcp://127.0.0.1:5556");
  printf("zmq_bind() returned %d\n", rc);
  assert(rc == 0);

  const char *topic = "";
  errno = 0;
  rc = zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, topic, strlen(topic));
  printf("zmq_setsockopt(%s) returned %d [%d/%s]\n", topic, rc, errno, strerror(errno));
  assert(rc == 0);


  while(1) {
    struct zmq_msg_hdr hdr;
    char buffer[1024];
    
    rc = zmq_recv(subscriber, &hdr, sizeof(hdr), 0);
    assert(rc != -1);

    hdr.size = ntohs(hdr.size);
    rc = zmq_recv(subscriber, buffer, hdr.size, 0);
    assert(rc != -1);
    
    buffer[hdr.size] = '\0';
    printf("[topic: %s] %s\n", hdr.url, buffer);
  }
  
  zmq_close(subscriber);
  zmq_ctx_destroy(context);

  return 0;
}
