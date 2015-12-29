/* net/sched/sch_ingress.c - Ingress and clsonly qdisc
 *
 *              Used for invoking classifiers only. ingress qdisc is a subset
 *              of clsonly qdisc. clsonly qdisc can hold classifiers for ingress
 *              and egress. egress classifiers are executed lockless as well
 *              and before we push the skb to a real egress qdisc. This also
 *              allows for tc actions when only having class-less qdiscs.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jamal Hadi Salim 1999
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>

static struct Qdisc *ingress_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long ingress_get(struct Qdisc *sch, u32 classid)
{
	return TC_H_MIN(classid) + 1;
}

static unsigned long ingress_bind_filter(struct Qdisc *sch,
					 unsigned long parent, u32 classid)
{
	return ingress_get(sch, classid);
}

static void ingress_put(struct Qdisc *sch, unsigned long cl)
{
}

static void ingress_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
}

static struct tcf_proto __rcu **ingress_find_tcf(struct Qdisc *sch,
						 unsigned long cl)
{
	struct net_device *dev = qdisc_dev(sch);

	return &dev->ingress_cl_list;
}

static int ingress_init(struct Qdisc *sch, struct nlattr *opt)
{
	net_inc_ingress_queue();
	sch->flags |= TCQ_F_CPUSTATS;

	return 0;
}

static void ingress_destroy(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);

	tcf_destroy_chain(&dev->ingress_cl_list);
	net_dec_ingress_queue();
}

static int ingress_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct Qdisc_class_ops ingress_class_ops = {
	.leaf		=	ingress_leaf,
	.get		=	ingress_get,
	.put		=	ingress_put,
	.walk		=	ingress_walk,
	.tcf_chain	=	ingress_find_tcf,
	.bind_tcf	=	ingress_bind_filter,
	.unbind_tcf	=	ingress_put,
};

static struct Qdisc_ops ingress_qdisc_ops __read_mostly = {
	.cl_ops		=	&ingress_class_ops,
	.id		=	"ingress",
	.init		=	ingress_init,
	.destroy	=	ingress_destroy,
	.dump		=	ingress_dump,
	.owner		=	THIS_MODULE,
};

static unsigned long clsonly_get(struct Qdisc *sch, u32 classid)
{
	switch (TC_H_MIN(classid)) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
	case TC_H_MIN(TC_H_MIN_EGRESS):
		return TC_H_MIN(classid);
	default:
		return 0;
	}
}

static unsigned long clsonly_bind_filter(struct Qdisc *sch,
					 unsigned long parent, u32 classid)
{
	return clsonly_get(sch, classid);
}

static struct tcf_proto __rcu **clsonly_find_tcf(struct Qdisc *sch,
						 unsigned long cl)
{
	struct net_device *dev = qdisc_dev(sch);

	switch (cl) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
		return &dev->ingress_cl_list;
	case TC_H_MIN(TC_H_MIN_EGRESS):
		return &dev->egress_cl_list;
	default:
		return NULL;
	}
}

static int clsonly_init(struct Qdisc *sch, struct nlattr *opt)
{
	net_inc_ingress_queue();
	net_inc_egress_queue();

	sch->flags |= TCQ_F_CPUSTATS;

	return 0;
}

static void clsonly_destroy(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);

	tcf_destroy_chain(&dev->ingress_cl_list);
	tcf_destroy_chain(&dev->egress_cl_list);

	net_dec_ingress_queue();
	net_dec_egress_queue();
}

static const struct Qdisc_class_ops clsonly_class_ops = {
	.leaf		=	ingress_leaf,
	.get		=	clsonly_get,
	.put		=	ingress_put,
	.walk		=	ingress_walk,
	.tcf_chain	=	clsonly_find_tcf,
	.bind_tcf	=	clsonly_bind_filter,
	.unbind_tcf	=	ingress_put,
};

static struct Qdisc_ops clsonly_qdisc_ops __read_mostly = {
	.cl_ops		=	&clsonly_class_ops,
	.id		=	"clsonly",
	.init		=	clsonly_init,
	.destroy	=	clsonly_destroy,
	.dump		=	ingress_dump,
	.owner		=	THIS_MODULE,
};

static int __init ingress_module_init(void)
{
	int ret;

	ret = register_qdisc(&ingress_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&clsonly_qdisc_ops);
		if (ret)
			unregister_qdisc(&ingress_qdisc_ops);
	}

	return ret;
}

static void __exit ingress_module_exit(void)
{
	unregister_qdisc(&ingress_qdisc_ops);
	unregister_qdisc(&clsonly_qdisc_ops);
}

module_init(ingress_module_init);
module_exit(ingress_module_exit);

MODULE_ALIAS("sch_clsonly");
MODULE_LICENSE("GPL");
