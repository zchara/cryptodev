/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
        struct crypto_device *crdev;
        unsigned long flags;

        debug("Entering");

        spin_lock_irqsave(&crdrvdata.lock, flags);
        list_for_each_entry(crdev, &crdrvdata.devs, list) {
                if (crdev->minor == minor)
                        goto out;
        }
        crdev = NULL;

out:
        spin_unlock_irqrestore(&crdrvdata.lock, flags);

        debug("Leaving");
        return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
        int ret = 0;
        int err;
        unsigned int len;
        struct crypto_open_file *crof;
        struct crypto_device *crdev;
        unsigned int* syscall_type;
        int *host_fd;
        struct scatterlist sg1, sg2;
        struct scatterlist* sg_array[2];

        debug("bhka sthn open");

        syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
        *syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;

         host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
        *host_fd = -1;


        debug("ekana malloc");

        ret = -ENODEV;
        if ((ret = nonseekable_open(inode, filp)) < 0)
                goto fail;

        debug("ekana open ");
/* Associate this open file with the relevant crypto device. */
        crdev = get_crypto_dev_by_minor(iminor(inode));
        if (!crdev) {
                debug("Could not find crypto device with %u minor",
                      iminor(inode));
                ret = -ENODEV;
                goto fail;
        }

        debug("found minor number ");

        crof = kzalloc(sizeof(*crof), GFP_KERNEL);
        if (!crof) {
                ret = -ENOMEM;
                goto fail;
                }
        crof->crdev = crdev;
        crof->host_fd = -1;
        filp->private_data = crof;

        debug("ekana kzalloc kai eftiaxa to private daa");

        /**
         * We need two sg lists, one for syscall_type and one to get the
         * file descriptor from the host.
         **/
        sg_init_one(&sg1, syscall_type, sizeof(*syscall_type));
        sg_array[0] = &sg1;
        sg_init_one(&sg2, host_fd, sizeof(*host_fd));
        sg_array[1] = &sg2;

        debug("eftiaxa tis sg listes");

        /**
         * Wait for the host to process our data.
         **/
         if (down_interruptible(&crdev->sem))
                return -ERESTARTSYS;
        debug("epiasa ton shmaforo");

        err = virtqueue_add_sgs(crdev->vq, sg_array, 1, 1, &sg1, GFP_ATOMIC);
        virtqueue_kick(crdev->vq);

        debug("enhmerwsa ton backend");
        while (virtqueue_get_buf(crdev->vq, &len) == NULL)
                /* do nothing */ ;
        up(&crdev->sem);
        debug("afhsa ton shmaforo");

        debug("done me ta virtqueues");

        /* If host failed to open() return -ENODEV. */

        if (*host_fd < 0) {
                ret = -ENODEV;
                goto fail;
        }
        else {
            crof->host_fd = *host_fd;

        }

        debug("phra to host fd");
fail:
        debug("Leaving open");
        return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
        int ret = 0;
        struct crypto_open_file *crof = filp->private_data;
        struct crypto_device *crdev = crof->crdev;
        unsigned int *syscall_type;
        struct scatterlist sg1, sg2;
        struct scatterlist *sg_array[2];
        int err;
        unsigned int len;

        debug("Entering");

        syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
        *syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;


        /**
         * Send data to the host.
         **/

        sg_init_one(&sg1, syscall_type, sizeof(*syscall_type));
        sg_init_one(&sg2, &(crof->host_fd), sizeof(crof->host_fd));
        sg_array[0] = &sg1;
        sg_array[1] = &sg2;

        /**
         * Wait for the host to process our data.
         **/
        if (down_interruptible(&crdev->sem))
                return -ERESTARTSYS;

        err = virtqueue_add_sgs(crdev->vq, sg_array, 2, 0, &sg1, GFP_ATOMIC);
        virtqueue_kick(crdev->vq);
        while (virtqueue_get_buf(crdev->vq, &len) == NULL)
                /* do nothing */ ;
       up(&crdev->sem);


	        kfree(crof);
        debug("Leaving");
        return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{


        //long ret = 0;
        int err;

        struct crypto_open_file *crof = filp->private_data;
        struct crypto_device *crdev = crof->crdev;
        struct virtqueue *vq = crdev->vq;
        struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, host_fd_sg, ioctl_cmd_sg, session_key_sg, session_op_sg, host_return_val_sg, ses_id_sg, crypt_op_sg, src_sg, iv_sg, dst_sg,
                           *sgs[8];
        unsigned int num_out, num_in, len;
#define MSG_LEN 100
        unsigned char *output_msg, *input_msg;            /* messages between guest and host */



        unsigned int *syscall_type;
        struct session_op* my_session = NULL;
        struct crypt_op* my_crypt = NULL;
        unsigned char** my_key;
        unsigned char* key = NULL;
        unsigned char* src = NULL;
        unsigned char* dst = NULL;
        unsigned char* iv = NULL;
        unsigned char* dest = NULL;

        u32* ses_id = NULL;
        long* ret_addr;
	long addre;
        void* temp  = NULL;
        void* write_from = NULL;
        int cs = 0;
        int* f;
        unsigned int* cmd_ad= NULL;
        debug("Entering");
 /**
         * Allocate all data that will be sent to the host.
         **/

        syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
        *syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;

         cmd_ad = kmalloc(sizeof(*cmd_ad), GFP_KERNEL);
        *cmd_ad = cmd;

         ret_addr = kmalloc(sizeof(*ret_addr), GFP_KERNEL);

        num_out = 0;
        num_in = 0;
        f= &(crof->host_fd);

        /**
         *  These are common to all ioctl commands.
         **/
        sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
        sgs[num_out++] = &syscall_type_sg;
        sg_init_one(&host_fd_sg, f, sizeof(*f));
        sgs[num_out++] = &host_fd_sg;
        sg_init_one(&ioctl_cmd_sg, cmd_ad, sizeof(*cmd_ad));
        sgs[num_out++] = &ioctl_cmd_sg;

   switch (*cmd_ad) {
        case CIOCGSESSION:
                debug("CIOCGSESSION");
                my_session = kmalloc(sizeof(*my_session), GFP_KERNEL);
                if( copy_from_user(my_session, (void __user*) arg, sizeof(*my_session)) != 0 )  {
                        printk("error with copying user session");
                        return -EFAULT;
                }




                key = kmalloc((my_session->keylen)*sizeof(char), GFP_KERNEL);
                if(copy_from_user(key,  my_session->key, (my_session->keylen)*sizeof(char)) > 0 )  {
                    printk("error with copying key");
                    return -EFAULT;
                 }

                my_session->key = key;

                sg_init_one(&session_key_sg, key, my_session->keylen);
                sgs[num_out++] = &session_key_sg;

                sg_init_one(&session_op_sg, my_session, sizeof(*my_session));
                sgs[num_out + num_in++] = &session_op_sg;

                sg_init_one(&host_return_val_sg, ret_addr, sizeof(*ret_addr));
                sgs[num_out + num_in++] = &host_return_val_sg;


                debug ("ready for virtqueue");

                cs = 1;
                write_from = my_session;


                break;
case CIOCFSESSION:
                debug("CIOCFSESSION");
                ses_id = kmalloc(sizeof(*ses_id), GFP_KERNEL);
                if (copy_from_user(ses_id, (void __user*) arg, sizeof(*ses_id)) > 0) {
                        printk("Error in COPY FROM USER: Copying session_op\n");
                        return -EFAULT;
                }


                sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
                sgs[num_out++] = &ses_id_sg;
                sg_init_one(&host_return_val_sg, ret_addr, sizeof(*ret_addr));
                sgs[num_out + num_in++] = &host_return_val_sg;

                write_from= NULL;

                cs=3;
                break;
 case CIOCCRYPT:
                debug("CIOCCRYPT");
                my_crypt = kmalloc(sizeof(*my_crypt), GFP_KERNEL);

                debug("mem ok");
                if (copy_from_user(my_crypt, (void __user*) arg, sizeof(*my_crypt)) > 0) {
                         printk("Error in COPY FROM USER: Copying crypt_op\n");
                        return -EFAULT;
                }

                debug("copy user argument ok");

                sg_init_one(&crypt_op_sg, my_crypt, sizeof(*my_crypt));
                sgs[num_out++] = &crypt_op_sg;

                src = kmalloc((my_crypt->len) * sizeof(char), GFP_KERNEL);
                if ( copy_from_user(src, my_crypt->src, (my_crypt->len) * sizeof(char)) > 0) {
                        printk("error in copying source from user\n");
                        return -EFAULT;
                        }

                sg_init_one(&src_sg, src, (my_crypt->len) * sizeof(char));
                sgs[num_out++] = &src_sg;

                debug("copying source ok");

                iv = kmalloc(16 * sizeof(char), GFP_KERNEL);

                debug("mem for iv ok");

                if ( copy_from_user(iv, my_crypt->iv, 16* sizeof(char)) != 0) {
                        printk("error in copying iv from user\n");
                        return -EFAULT;
                }

                sg_init_one(&iv_sg, iv, 16 * sizeof(char));
                sgs[num_out++] = &iv_sg;

                debug("copy iv ok");
 		 dest = my_crypt->dst;
                dst = kmalloc(my_crypt->len * sizeof(char), GFP_KERNEL);
                my_crypt->dst = dst;

                debug("dst ok");

                sg_init_one(&dst_sg, dst, my_crypt->len * sizeof(char));
                sgs[num_out + num_in++] = &dst_sg;

                sg_init_one(&host_return_val_sg, ret_addr, sizeof(*ret_addr));
                sgs[num_out + num_in++] = &host_return_val_sg;

                debug("leaving");

                write_from= my_crypt;
                cs = 2;
                break;

        default:
                debug("Unsupported ioctl command");

                break;
        }


        /**
         * Wait for the host to process our data.
         **/

/**
         * Wait for the host to process our data.
         **/

        if (down_interruptible(&crdev->sem))
               return -ERESTARTSYS;

        err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
        virtqueue_kick(vq);
        while (virtqueue_get_buf(vq, &len) == NULL)
                /* do nothing */;
        up(&crdev->sem);


        if (cs == 1) {
                if (copy_to_user((void __user *)arg, my_session, sizeof(*my_session)))
                        return -EFAULT;

                kfree(key);
                kfree(my_session);
        }
        else if (cs == 2) {
                if (copy_to_user((void __user *)dest, dst, my_crypt->len * sizeof(char)))
                        return -EFAULT;


                kfree(src);
                kfree(dst);
                kfree(iv);
                kfree(my_crypt);
        }
        else if (cs == 3)
                kfree(ses_id);

	 	
	kfree(syscall_type);
	addre = *ret_addr;
        kfree(ret_addr);
        kfree(cmd_ad);

        debug("Leaving");

        return addre;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf,
                                  size_t cnt, loff_t *f_pos)
{
        debug("Entering");
        debug("Leaving");
        return -EINVAL;
}

static struct file_operations crypto_chrdev_fops =
{
        .owner          = THIS_MODULE,
        .open           = crypto_chrdev_open,
        .release        = crypto_chrdev_release,
        .read           = crypto_chrdev_read,
        .unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
        int ret;
        dev_t dev_no;
        unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

        debug("Initializing character device...");
        cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
        crypto_chrdev_cdev.owner = THIS_MODULE;
        crypto_chrdev_cdev.ops = &crypto_chrdev_fops;

        dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
        ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
        if (ret < 0) {
                debug("failed to register region, ret = %d", ret);
                goto out;
        }
        ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
        if (ret < 0) {
                debug("failed to add character device");
                goto out_with_chrdev_region;
        }

        debug("Completed successfully");
        return 0;

out_with_chrdev_region:
        unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
        return ret;
}

void crypto_chrdev_destroy(void)
{
        dev_t dev_no;
        unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

        debug("entering");
        dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
        cdev_del(&crypto_chrdev_cdev);
        unregister_chrdev_region(dev_no, crypto_minor_cnt);
        debug("leaving");
}

