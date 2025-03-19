#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

#include <stdio.h>
#include <stdlib.h>

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t)(&((TYPE *)0)->MEMBER))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({ \
            const typeof(*ptr) *__ptr = (ptr);                      \
            (type *) ((char*)__ptr - offsetof(type, member));})
#endif


#define LIST_POISON1 ((void *) 0x00100100)
#define LIST_POISON2 ((void *) 0x00200200)

static inline void prefetch(const void *x) {;}
static inline void prefetchw(const void *x) {;}

struct list_head {
  struct list_head *prev, *next;
};
    
#define LIST_HEAD_INIT(name) {&(name), &(name)}

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name);
    
#define INIT_LIST_HEAD(ptr) do {\
    (ptr)->prev = (ptr); (ptr)->next = (ptr); \
} while (0)

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
  new->prev = prev;
  prev->next = new;
  next->prev = new;
  new->next = next;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
  __list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
  __list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
  prev->next = next;
  next->prev = prev;
}

static inline void list_del(struct list_head *pos)
{
    __list_del(pos->prev, pos->next);
}

static inline void list_del_init(struct list_head *pos)
{
    __list_del(pos->prev, pos->next);
    pos->prev = LIST_POISON1;
    pos->next = LIST_POISON2;
}

static inline void list_move(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add(list, head);
}

static inline void list_move_tail(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add_tail(list, head);
}

static inline int list_empty(struct list_head *head)
{
    return head->next == head;
}

static inline int list_empty_careful(struct list_head *head)
{
    return (head->next == head) && (head->next == head->prev);
}

static inline void __list_splice(struct list_head *list, struct list_head *head)
{
    head->next->prev = list->prev;
    list->prev->next = head->next;
    head->next = list->next;
    list->next->prev = head;
}

static inline void list_splice(struct list_head *list, struct list_head *head)
{
    if (!list_empty(list))
        __list_splice(list, head);
}

static inline void list_splice_init(struct list_head *list, struct list_head *head)
{
    if (!list_empty(list)) {
        __list_splice(list, head);
        INIT_LIST_HEAD(list);
    }
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define __list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each(pos, head) \
    for (pos = (head)->next; prefetch(pos->next); pos != (head); pos = pos->next)

#define list_for_each_prev(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define list_for_each_safe(pos, temp, head) \
    for (pos = (head)->next, temp = pos->next; pos != (head); pos = temp, temp = pos->next)

#define list_for_each_entry(pos, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member);\
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_index(pos, index, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member), index = 0;\
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member), index++)

#define list_for_each_entry_reverse(pos, head, member) \
    for (pos = list_entry((head)->prev, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_prepare_entry(pos, head, member) \
    ((pos) ? : list_entry(head, typeof(*pos), member))


#define list_for_each_entry_continue(pos, head, member) \
    for (pos = list_entry((pos)->member.next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, temp, head, member) \
    for (pos = list_entry((head)->next, typeof(*pos), member), temp = list_entry(pos->member.next, typeof(*pos), member); \
         &pos->member != (head); \
         pos = temp, temp = list_entry(temp->member.next, typeof(*temp), member))

#endif

struct hlist_node {
    struct hlist_node *next, **pprev;
};

struct hlist_head {
    struct hlist_node *first;
};

#define HLIST_HEAD_INIT {.first = NULL}

#define HLIST_HEAD(name) struct hlist_head name = HLIST_HEAD_INIT

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

#define INIT_HLIST_NODE(node) ((node)->next = NULL, (node)->pprev = NULL)

static inline int hlist_unhashed(const struct hlist_node *h)
{
    return !h->pprev;
}

static inline int hlist_empty(const struct hlist_head *head)
{
    return !head->first;
}

/* hlist must not be empty */
static inline void __hlist_del(struct hlist_node *node)
{
    *node->pprev = node->next;
    if (node->next)
        node->next->pprev = node->pprev;
}

static inline void hlist_del(struct hlist_node *node)
{
    __hlist_del(node);
    node->next = LIST_POISON1;
    node->pprev = LIST_POISON2;
}

static inline void hlist_del_init(struct hlist_node *node)
{
    __hlist_del(node);
    INIT_HLIST_NODE(node);
}

/* head must not be null */
static inline void hlist_add_head(struct hlist_node *node, struct hlist_head *head)
{
    struct hlist_node *first = head->first;

    head->first = node;
    node->pprev = &head->first;
    node->next = first;
    if (first)
        first->pprev = &node->next;
}

static inline void hlist_add_before(struct hlist_node *node, struct hlist_node *next)
{
    struct hlist_node **pprev = next->pprev;

    *pprev = node;
    node->pprev = pprev;
    node->next = next;
    next->pprev = &node->next;
}

static inline void hlist_add_after(struct hlist_node *node, struct hlist_node *next)
{
    struct hlist_node *after = next->next;

    next->next = node;
    node->pprev = &next->next;
    node->next = after;
    if (after)
        after->pprev = &node->next;
}

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_for_each(pos, head) \
    for (pos = (head)->first; \
         pos && ({prefetch(pos->next); 1;}); \
        pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
    for (pos = (head)->first; \
         pos && ({n = pos->next; 1;}); \
        pos = n)

#define hlist_for_each_entry(tpos, pos, head, member) \
    for (pos = (head)->first; \
         pos && ({prefetch(pos->next; 1;)}) && ({tops = hlist_entry(pos, typeof(*tpos), member)}; 1;); \
        pos = pos->next)

#define hlist_for_each_entry_continue(tpos, pos, member) \
    for (pos = (pos)->next; \
         pos && ({tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
        pos = pos->next)

#define hlist_for_each_entry_from(tpos, pos, member) \
    for (; pos && ({tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
        pos = pos->next)

#define hlist_for_each_entry_safe(tpos, pos, n, head, member) \
    for (pos = (head)->first; \
         pos && ({n = pos->next; 1;}) && ({tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
        pos = n)
