#include <asm/uaccess.h>

#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#define ARCH_TIMER_CTRL_ENABLE		(1 << 0)
#define ARCH_TIMER_CTRL_IT_MASK		(1 << 1)

struct latency_tester {
	struct latency_tester __percpu **lt_percpu;
	int irq;
	struct dentry *debugfs;
	bool open;
	bool data_in_queue;
	spinlock_t lock;
	wait_queue_head_t wait;
	u32 cntfrq;
	int timer_cpu;
	u64 last_cval;
	u64 time_trigger;
	u64 time_isr;
};

static inline u32 read_cntfrq(void)
{
	u32 val;

	asm volatile("mrc p15, 0, %0, c14, c0, 0" : "=r" (val));

	return val;
}

static inline u64 read_cntvct(void)
{
	u32 cval_lo;
	u32 cval_hi;

	isb();
	asm volatile("mrrc p15, 1, %0, %1, c14" : "=r" (cval_lo), "=r" (cval_hi));

	return (((u64)cval_hi) << 32) | cval_lo;
}

static inline void write_cntv_ctl(u32 val)
{
	asm volatile("mcr p15, 0, %0, c14, c3, 1" : : "r" (val));
	isb();
}

static inline void write_cntv_cval(u64 val)
{
	asm volatile("mcrr p15, 3, %0, %1, c14" : : "r" (val & 0xffffffff), "r" (val >> 32));
	isb();
}

static inline void set_timer_expiry(struct latency_tester *lt)
{
	lt->last_cval += lt->cntfrq;
	write_cntv_cval(lt->last_cval);
}

static void enable_timer_imp(void *arg)
{
	struct latency_tester *lt = arg;

	lt->last_cval = read_cntvct();
	set_timer_expiry(lt);

	write_cntv_ctl(ARCH_TIMER_CTRL_ENABLE);
	enable_percpu_irq(lt->irq, 0);
}

static inline void enable_timer(struct latency_tester *lt)
{
	smp_call_function_single(lt->timer_cpu, enable_timer_imp, lt, 1);
}

static void disable_timer_imp(void *arg)
{
	struct latency_tester *lt = arg;

	disable_percpu_irq(lt->irq);
	write_cntv_cval(0xffffffffffffffffULL);
	write_cntv_ctl(ARCH_TIMER_CTRL_IT_MASK);
}

static inline void disable_timer(struct latency_tester *lt)
{
	smp_call_function_single(lt->timer_cpu, disable_timer_imp, lt, 1);
}

static int lt_open(struct inode *inode, struct file *file)
{
	struct latency_tester *lt = file->f_inode->i_private;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&lt->lock, flags);
	if (lt->open) {
		ret = -EBUSY;
	} else {
		lt->open = true;
		ret = 0;
	}
	spin_unlock_irqrestore(&lt->lock, flags);
	if (ret)
		return ret;

	enable_timer(lt);

	return nonseekable_open(inode, file);
}

static int lt_release(struct inode *inode, struct file *file)
{
	struct latency_tester *lt = file->f_inode->i_private;

	disable_timer(lt);
	lt->open = false;

	return 0;
}

ssize_t lt_write(struct file *file, const char __user *data,
		   size_t len, loff_t *ppos)
{
	return -EINVAL;
}

ssize_t lt_read(struct file *file, char __user *buf,
		  size_t len, loff_t *ppos)
{
	struct latency_tester *lt = file->f_inode->i_private;
	unsigned long flags;
	int ret;

	if (len != 16)
		return -EINVAL;

	for (;;) {
		if (lt->data_in_queue) {
			spin_lock_irqsave(&lt->lock, flags);
			ret = copy_to_user(buf, &lt->time_trigger, len);
			if (!ret)
				lt->data_in_queue = false;
			spin_unlock_irqrestore(&lt->lock, flags);
			if (ret)
				return ret;

			*ppos += len;
			return len;
		}

		ret = wait_event_interruptible(lt->wait, lt->data_in_queue);
		if (ret)
			return ret;
	}
}

static const struct file_operations lt_fileops = {
	.owner	= THIS_MODULE,
	.open	= lt_open,
	.release = lt_release,
	.write	= lt_write,
	.read	= lt_read,
	.llseek = no_llseek,
};

static irqreturn_t latency_tester_isr(int irq, void *arg)
{
	struct latency_tester **ltp = arg;
	struct latency_tester *lt = *ltp;
	unsigned long flags;

	spin_lock_irqsave(&lt->lock, flags);
	if (!lt->data_in_queue) {
		lt->time_trigger = lt->last_cval;
		lt->time_isr = read_cntvct();
		lt->data_in_queue = true;
		wake_up_interruptible(&lt->wait);
	}
	spin_unlock_irqrestore(&lt->lock, flags);

	set_timer_expiry(lt);

	return IRQ_HANDLED;
}

static int latency_tester_probe(struct platform_device *pdev)
{
	struct latency_tester *lt;
	int cpu, ret;

	lt = devm_kzalloc(&pdev->dev, sizeof(struct latency_tester), GFP_KERNEL);
	if (!lt) {
		ret = -ENOMEM;
		goto err;
	}
	dev_set_drvdata(&pdev->dev, lt);

	spin_lock_init(&lt->lock);
	init_waitqueue_head(&lt->wait);
	lt->cntfrq = read_cntfrq();

	lt->irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (lt->irq < 0) {
		ret = lt->irq;
		dev_err(&pdev->dev, "failed to get IRQ: %d\n", ret);
		goto err;
	}

	lt->lt_percpu = alloc_percpu(struct latency_tester *);
	if (!lt->lt_percpu) {
		ret = -ENOMEM;
		goto err;
	}
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(lt->lt_percpu, cpu) = lt;

	ret = request_percpu_irq(lt->irq, latency_tester_isr, "latency-tester", lt->lt_percpu);
	if (ret) {
		dev_err(&pdev->dev, "failed to register IRQ %d: %d\n", lt->irq, ret);
		goto err_free_percpu;
	}

	lt->debugfs = debugfs_create_file("latency_tester", S_IFREG | S_IRUGO | S_IWUGO, NULL, lt, &lt_fileops);
	if (!lt->debugfs) {
		ret = -ENODEV;
		goto err_free_irq;
	}

	return 0;

err_free_irq:
	free_percpu_irq(lt->irq, lt);
err_free_percpu:
	free_percpu(lt->lt_percpu);
err:
	return ret;
}

static int latency_tester_remove(struct platform_device *pdev)
{
	struct latency_tester *lt = dev_get_drvdata(&pdev->dev);

	debugfs_remove(lt->debugfs);
	free_percpu_irq(lt->irq, lt);
	free_percpu(lt->lt_percpu);

	return 0;
}

static const struct of_device_id latency_tester_of_match[] = {
	{ .compatible = "linux,latency-tester" },
	{ },
};

static struct platform_driver latency_tester_driver = {
	.driver		= {
		.name = "latency-tester",
		.of_match_table = latency_tester_of_match,
	},
	.probe = latency_tester_probe,
	.remove = latency_tester_remove,
};
module_platform_driver(latency_tester_driver);
