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
#include <linux/platform_device.h>

struct latency_tester {
	void __iomem *trigger_reg;
	u32 trigger_val;
	int irq;
	struct dentry *debugfs;

	struct completion irq_done;
	u64 time_trigger;
	u64 time_isr;
};

static inline u64 arch_counter_get_cntvct(void)
{
	u64 cval;

	isb();
	asm volatile("mrrc p15, 1, %Q0, %R0, c14" : "=r" (cval));
	return cval;
}

static int lt_open(struct inode *inode, struct file *file)
{
	return nonseekable_open(inode, file);
}

ssize_t lt_write(struct file *file, const char __user *data,
		   size_t len, loff_t *ppos)
{
	struct latency_tester *lt = file->f_inode->i_private;

	lt->time_trigger = arch_counter_get_cntvct();
	writel(lt->trigger_val, lt->trigger_reg);

	return len;
}

ssize_t lt_read(struct file *file, char __user *buf,
		  size_t len, loff_t *ppos)
{
	struct latency_tester *lt = file->f_inode->i_private;
	int ret;

	if (len != 16)
		return -EINVAL;

	reinit_completion(&lt->irq_done);
	ret = wait_for_completion_interruptible(&lt->irq_done);
	if (ret < 0)
		return -EIO;

	ret = copy_to_user(buf, &lt->time_trigger, len);
	if (ret < 0)
		return ret;

	*ppos += len;

	return len;
}

static const struct file_operations lt_fileops = {
	.owner	= THIS_MODULE,
	.open	= lt_open,
	.write	= lt_write,
	.read	= lt_read,
	.llseek = no_llseek,
};

static irqreturn_t latency_tester_isr(int irq, void *arg)
{
	struct latency_tester *lt = arg;

	lt->time_isr = arch_counter_get_cntvct();
	complete(&lt->irq_done);

	return IRQ_HANDLED;
}

static int latency_tester_probe(struct platform_device *pdev)
{
	struct latency_tester *lt;
	int ret;
	struct resource *mem;

	lt = devm_kzalloc(&pdev->dev, sizeof(struct latency_tester), GFP_KERNEL);
	if (!lt) {
		ret = -ENOMEM;
		goto err;
	}
	dev_set_drvdata(&pdev->dev, lt);

	init_completion(&lt->irq_done);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		dev_err(&pdev->dev, "No memory resource\n");
		ret = -ENODEV;
		goto err;
	}

	lt->trigger_reg = devm_ioremap(&pdev->dev, mem->start, resource_size(mem));
	if (!lt->trigger_reg) {
		dev_err(&pdev->dev, "ioremap failed\n");
		ret = -ENOMEM;
		goto err;
	}

	ret = of_property_read_u32(pdev->dev.of_node, "trigger-val", &lt->trigger_val);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to read trigger-val: %d\n", ret);
		goto err;
	}

	lt->irq = platform_get_irq(pdev, 0);
	if (lt->irq < 0) {
		dev_err(&pdev->dev, "failed to get IRQ: %d\n", ret);
		goto err;
	}

	ret = request_irq(lt->irq, latency_tester_isr, IRQF_SHARED, "latency-tester", lt);
	if (ret) {
		dev_err(&pdev->dev, "failed to register IRQ: %d\n", ret);
		goto err;
	}

	lt->debugfs = debugfs_create_file("latency_tester", S_IFREG | S_IRUGO | S_IWUGO, NULL, lt, &lt_fileops);
	if (!lt->debugfs) {
		ret = -ENODEV;
		goto err_free_irq;
	}

	return 0;

err_free_irq:
	free_irq(lt->irq, lt);
err:
	return ret;
}

static int latency_tester_remove(struct platform_device *pdev)
{
	struct latency_tester *lt = dev_get_drvdata(&pdev->dev);

	debugfs_remove(lt->debugfs);
	free_irq(lt->irq, lt);

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
