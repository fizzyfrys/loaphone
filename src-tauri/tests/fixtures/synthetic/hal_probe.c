/* Synthetic HAL used by the headless REA tests. Rebuild with build.sh. */
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define PROBE_IOC_MAGIC 'P'
struct probe_cfg { uint32_t rate; uint32_t mode; };
#define PROBE_IOC_SET_CFG _IOW(PROBE_IOC_MAGIC, 3, struct probe_cfg)
#define PROBE_IOC_RESET _IO(PROBE_IOC_MAGIC, 9)

#define MDSS_BASE 0x0ae00000u
#define UFS_PHY_BASE 0x01d87000u

const char *probe_firmware = "/vendor/firmware/probe/probe_fw.mdt";
const char *probe_node = "/dev/probe0";

int probe_start(struct probe_cfg *cfg) {
    int fd = open(probe_node, O_RDWR);
    if (fd < 0) return fd;
    if (ioctl(fd, PROBE_IOC_SET_CFG, cfg) < 0) return -1;
    return ioctl(fd, PROBE_IOC_RESET, 0);
}

uint32_t probe_peek(int memfd) {
    volatile uint32_t *mdss = mmap(0, 0x1000, PROT_READ, MAP_SHARED, memfd, MDSS_BASE);
    volatile uint32_t *ufs = mmap(0, 0x1000, PROT_READ, MAP_SHARED, memfd, UFS_PHY_BASE);
    return mdss[0] ^ ufs[1];
}
