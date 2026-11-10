use std::{
    ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr},
    ptr,
};

pub const VENDOR_ID: u16 = 0x04c5;
pub const PRODUCT_ID: u16 = 0x132b;
pub const INTERFACE: u8 = 0;
pub const BULK_OUT: u8 = 0x02;
pub const BULK_IN: u8 = 0x81;
pub const TIMEOUT_MS: c_uint = 5000;

#[repr(C)]
struct LibusbDeviceDescriptor {
    length: u8,
    descriptor_type: u8,
    usb_version: u16,
    class: u8,
    subclass: u8,
    protocol: u8,
    max_packet_size: u8,
    vendor: u16,
    product: u16,
    device_version: u16,
    manufacturer: u8,
    product_string: u8,
    serial: u8,
    configurations: u8,
}

#[link(name = "usb-1.0")]
unsafe extern "C" {
    fn libusb_init(ctx: *mut *mut c_void) -> c_int;
    fn libusb_exit(ctx: *mut c_void);
    fn libusb_get_device_list(ctx: *mut c_void, list: *mut *mut *mut c_void) -> isize;
    fn libusb_free_device_list(list: *mut *mut c_void, unref: c_int);
    fn libusb_get_device_descriptor(
        device: *mut c_void,
        desc: *mut LibusbDeviceDescriptor,
    ) -> c_int;
    fn libusb_open(device: *mut c_void, handle: *mut *mut c_void) -> c_int;
    fn libusb_close(handle: *mut c_void);
    fn libusb_kernel_driver_active(handle: *mut c_void, interface: c_int) -> c_int;
    fn libusb_detach_kernel_driver(handle: *mut c_void, interface: c_int) -> c_int;
    fn libusb_claim_interface(handle: *mut c_void, interface: c_int) -> c_int;
    fn libusb_release_interface(handle: *mut c_void, interface: c_int) -> c_int;
    fn libusb_bulk_transfer(
        handle: *mut c_void,
        endpoint: c_uchar,
        data: *mut c_uchar,
        length: c_int,
        transferred: *mut c_int,
        timeout: c_uint,
    ) -> c_int;
    fn libusb_error_name(code: c_int) -> *const c_char;
}

fn err(code: c_int) -> String {
    unsafe {
        CStr::from_ptr(libusb_error_name(code))
            .to_string_lossy()
            .into_owned()
    }
}

pub struct Scanner {
    context: *mut c_void,
    handle: *mut c_void,
    timeout_ms: c_uint,
}

impl Scanner {
    pub fn open() -> Result<Self, String> {
        Self::open_with_timeout(TIMEOUT_MS)
    }

    pub fn open_with_timeout(timeout_ms: c_uint) -> Result<Self, String> {
        unsafe {
            let mut context = ptr::null_mut();
            let rc = libusb_init(&mut context);
            if rc != 0 {
                return Err(format!("libusb initialization failed: {}", err(rc)));
            }
            let mut list = ptr::null_mut();
            let count = libusb_get_device_list(context, &mut list);
            if count < 0 {
                libusb_exit(context);
                return Err(format!("USB enumeration failed: {}", err(count as c_int)));
            }
            let mut found = None;
            for i in 0..count as usize {
                let device = *list.add(i);
                let mut desc = std::mem::zeroed::<LibusbDeviceDescriptor>();
                if libusb_get_device_descriptor(device, &mut desc) == 0
                    && desc.vendor == VENDOR_ID
                    && desc.product == PRODUCT_ID
                {
                    let mut handle = ptr::null_mut();
                    let rc = libusb_open(device, &mut handle);
                    if rc == 0 {
                        found = Some(handle);
                    } else {
                        libusb_free_device_list(list, 1);
                        libusb_exit(context);
                        return Err(format!(
                            "cannot open scanner (check udev permissions): {}",
                            err(rc)
                        ));
                    }
                    break;
                }
            }
            libusb_free_device_list(list, 1);
            let handle = match found {
                Some(h) => h,
                None => {
                    libusb_exit(context);
                    return Err(format!(
                        "ScanSnap iX500 ({VENDOR_ID:04x}:{PRODUCT_ID:04x}) not found"
                    ));
                }
            };
            if libusb_kernel_driver_active(handle, INTERFACE as c_int) == 1 {
                let rc = libusb_detach_kernel_driver(handle, INTERFACE as c_int);
                if rc != 0 {
                    libusb_close(handle);
                    libusb_exit(context);
                    return Err(format!("cannot detach kernel driver: {}", err(rc)));
                }
            }
            let rc = libusb_claim_interface(handle, INTERFACE as c_int);
            if rc != 0 {
                libusb_close(handle);
                libusb_exit(context);
                return Err(format!(
                    "cannot claim USB interface {INTERFACE}: {}",
                    err(rc)
                ));
            }
            println!("USB {VENDOR_ID:04x}:{PRODUCT_ID:04x}, interface {INTERFACE}, class 0xff, endpoints 0x{BULK_OUT:02x}/0x{BULK_IN:02x}, packet 512 bytes");
            Ok(Self {
                context,
                handle,
                timeout_ms,
            })
        }
    }

    pub fn bulk_out(&self, data: &[u8]) -> Result<usize, String> {
        transfer(
            self.handle,
            BULK_OUT,
            data.as_ptr() as *mut u8,
            data.len(),
            self.timeout_ms,
        )
    }
    pub fn bulk_in(&self, data: &mut [u8]) -> Result<usize, String> {
        transfer(
            self.handle,
            BULK_IN,
            data.as_mut_ptr(),
            data.len(),
            self.timeout_ms,
        )
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        unsafe {
            let _ = libusb_release_interface(self.handle, INTERFACE as c_int);
            libusb_close(self.handle);
            libusb_exit(self.context);
        }
    }
}

fn transfer(
    handle: *mut c_void,
    endpoint: u8,
    data: *mut u8,
    len: usize,
    timeout_ms: c_uint,
) -> Result<usize, String> {
    let mut transferred = 0;
    let rc = unsafe {
        libusb_bulk_transfer(
            handle,
            endpoint,
            data,
            len as c_int,
            &mut transferred,
            timeout_ms,
        )
    };
    if rc != 0 {
        Err(format!(
            "USB bulk endpoint 0x{endpoint:02x} failed: {}",
            err(rc)
        ))
    } else {
        Ok(transferred as usize)
    }
}
