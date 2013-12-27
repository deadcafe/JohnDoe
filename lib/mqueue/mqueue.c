
struct jd_msg {
	void *val;
	size_t len;
	size_t refcnt;
	void (*destroyer)(struct jd_msg *);
} jd_msg_t;

struct {
	head;
	size_t num;
	pthread_mutex_t mutex;
} jd_msg_q_t;

struct {
	pthread_mutex_t mutex;
	size_t num;
	msg_q_t *que;
} jd_q_mng_t;


int
jd_mque_create(int num)
{

}

jd_msg_t *
jd_msg_alloc(size_t len)
{

}



