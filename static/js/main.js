// Main JavaScript file for ClearQ platform

// Utility functions
const Utils = {
    // Debounce function for performance
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Format currency
    formatCurrency: function(amount, currency = 'INR') {
        return new Intl.NumberFormat('en-IN', {
            style: 'currency',
            currency: currency,
            minimumFractionDigits: 0,
            maximumFractionDigits: 0
        }).format(amount);
    },

    // Format date
    formatDate: function(date, format = 'medium') {
        const dateObj = new Date(date);
        const options = {
            weekday: 'short',
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        };
        
        if (format === 'short') {
            options.weekday = undefined;
            options.year = undefined;
        }
        
        return dateObj.toLocaleDateString('en-US', options);
    },

    // Copy to clipboard
    copyToClipboard: function(text) {
        return navigator.clipboard.writeText(text)
            .then(() => true)
            .catch(() => {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                const result = document.execCommand('copy');
                document.body.removeChild(textArea);
                return result;
            });
    },

    // Show notification
    showNotification: function(message, type = 'info') {
        // Remove existing notifications
        document.querySelectorAll('.custom-notification').forEach(n => n.remove());
        
        const notification = document.createElement('div');
        notification.className = `custom-notification fixed top-4 right-4 px-4 py-2 rounded-lg shadow-lg z-50 transform translate-x-full transition-transform duration-300 ${
            type === 'success' ? 'bg-green-500 text-white' :
            type === 'error' ? 'bg-red-500 text-white' :
            type === 'warning' ? 'bg-yellow-500 text-white' :
            'bg-blue-500 text-white'
        }`;
        
        notification.innerHTML = `
            <div class="flex items-center gap-2">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.classList.remove('translate-x-full');
            notification.classList.add('translate-x-0');
        }, 10);
        
        // Animate out and remove
        setTimeout(() => {
            notification.classList.remove('translate-x-0');
            notification.classList.add('translate-x-full');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        }, 3000);
        
        // Make notification focusable for accessibility
        notification.setAttribute('role', 'alert');
        notification.setAttribute('aria-live', 'assertive');
        notification.focus();
    },

    // Validate email
    validateEmail: function(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // Validate password strength
    validatePassword: function(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        
        return {
            isValid: password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers,
            minLength: password.length >= minLength,
            hasUpperCase,
            hasLowerCase,
            hasNumbers,
            hasSpecialChar
        };
    },

    // Generate random ID
    generateId: function(length = 8) {
        return Math.random().toString(36).substr(2, length);
    },

    // Parse URL parameters
    getUrlParams: function() {
        const params = {};
        const queryString = window.location.search.substring(1);
        const pairs = queryString.split('&');
        
        pairs.forEach(pair => {
            const [key, value] = pair.split('=');
            if (key) {
                params[decodeURIComponent(key)] = decodeURIComponent(value || '');
            }
        });
        
        return params;
    },

    // Set URL parameter
    setUrlParam: function(key, value) {
        const url = new URL(window.location);
        url.searchParams.set(key, value);
        window.history.pushState({}, '', url);
    },

    // Remove URL parameter
    removeUrlParam: function(key) {
        const url = new URL(window.location);
        url.searchParams.delete(key);
        window.history.pushState({}, '', url);
    }
};

// Form validation class
class FormValidator {
    constructor(formId, options = {}) {
        this.form = document.getElementById(formId);
        if (!this.form) return;
        
        this.options = {
            liveValidation: true,
            showErrors: true,
            errorClass: 'error-message',
            ...options
        };
        
        this.init();
    }
    
    init() {
        if (this.options.liveValidation) {
            this.form.addEventListener('input', this.validateField.bind(this));
        }
        
        this.form.addEventListener('submit', this.validateForm.bind(this));
    }
    
    validateField(event) {
        const field = event.target;
        if (!field.hasAttribute('data-validate')) return;
        
        const value = field.value.trim();
        const rules = field.getAttribute('data-validate').split(' ');
        let isValid = true;
        let errorMessage = '';
        
        rules.forEach(rule => {
            switch(rule) {
                case 'required':
                    if (!value) {
                        isValid = false;
                        errorMessage = field.getAttribute('data-required-message') || 'This field is required';
                    }
                    break;
                    
                case 'email':
                    if (value && !Utils.validateEmail(value)) {
                        isValid = false;
                        errorMessage = field.getAttribute('data-email-message') || 'Please enter a valid email address';
                    }
                    break;
                    
                case 'password':
                    if (value) {
                        const passwordValidation = Utils.validatePassword(value);
                        if (!passwordValidation.isValid) {
                            isValid = false;
                            errorMessage = field.getAttribute('data-password-message') || 'Password must be at least 8 characters with uppercase, lowercase, and numbers';
                        }
                    }
                    break;
                    
                case 'minlength':
                    const minLength = field.getAttribute('data-minlength') || 3;
                    if (value && value.length < minLength) {
                        isValid = false;
                        errorMessage = field.getAttribute('data-minlength-message') || `Minimum ${minLength} characters required`;
                    }
                    break;
                    
                case 'match':
                    const matchField = document.getElementById(field.getAttribute('data-match'));
                    if (matchField && value !== matchField.value) {
                        isValid = false;
                        errorMessage = field.getAttribute('data-match-message') || 'Fields do not match';
                    }
                    break;
            }
        });
        
        this.setFieldState(field, isValid, errorMessage);
        return isValid;
    }
    
    validateForm(event) {
        event.preventDefault();
        
        const fields = this.form.querySelectorAll('[data-validate]');
        let isValid = true;
        let firstInvalidField = null;
        
        fields.forEach(field => {
            if (!this.validateField({ target: field })) {
                isValid = false;
                if (!firstInvalidField) {
                    firstInvalidField = field;
                }
            }
        });
        
        if (!isValid && firstInvalidField) {
            firstInvalidField.focus();
            Utils.showNotification('Please fix the errors in the form', 'error');
            return false;
        }
        
        return true;
    }
    
    setFieldState(field, isValid, errorMessage) {
        // Remove existing error message
        const existingError = field.parentNode.querySelector(`.${this.options.errorClass}`);
        if (existingError) {
            existingError.remove();
        }
        
        // Update field styling
        if (isValid) {
            field.classList.remove('border-red-500');
            field.classList.add('border-green-500');
        } else {
            field.classList.remove('border-green-500');
            field.classList.add('border-red-500');
            
            // Add error message
            if (this.options.showErrors && errorMessage) {
                const errorElement = document.createElement('div');
                errorElement.className = `${this.options.errorClass} text-red-600 text-sm mt-1`;
                errorElement.textContent = errorMessage;
                field.parentNode.appendChild(errorElement);
            }
        }
        
        return isValid;
    }
}

// Image upload handler
class ImageUploader {
    constructor(inputId, previewId, options = {}) {
        this.input = document.getElementById(inputId);
        this.preview = document.getElementById(previewId);
        this.options = {
            maxSize: 5 * 1024 * 1024, // 5MB
            allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
            ...options
        };
        
        if (!this.input || !this.preview) return;
        
        this.init();
    }
    
    init() {
        this.input.addEventListener('change', this.handleFileSelect.bind(this));
        
        // Add drag and drop if supported
        if (this.preview) {
            this.preview.addEventListener('dragover', this.handleDragOver.bind(this));
            this.preview.addEventListener('drop', this.handleDrop.bind(this));
        }
    }
    
    handleFileSelect(event) {
        const file = event.target.files[0];
        this.validateAndPreview(file);
    }
    
    handleDragOver(event) {
        event.preventDefault();
        event.stopPropagation();
        this.preview.classList.add('border-blue-500', 'bg-blue-50');
    }
    
    handleDrop(event) {
        event.preventDefault();
        event.stopPropagation();
        this.preview.classList.remove('border-blue-500', 'bg-blue-50');
        
        const file = event.dataTransfer.files[0];
        this.validateAndPreview(file);
    }
    
    validateAndPreview(file) {
        if (!file) return;
        
        // Validate file type
        if (!this.options.allowedTypes.includes(file.type)) {
            Utils.showNotification(`Invalid file type. Allowed types: ${this.options.allowedTypes.join(', ')}`, 'error');
            return;
        }
        
        // Validate file size
        if (file.size > this.options.maxSize) {
            Utils.showNotification(`File too large. Maximum size: ${this.options.maxSize / 1024 / 1024}MB`, 'error');
            return;
        }
        
        // Preview image
        const reader = new FileReader();
        reader.onload = (e) => {
            this.preview.innerHTML = `<img src="${e.target.result}" class="w-full h-full object-cover rounded-lg" alt="Preview">`;
            this.preview.classList.remove('border-dashed');
        };
        reader.readAsDataURL(file);
    }
}

// Booking system
class BookingSystem {
    constructor(mentorId, serviceId) {
        this.mentorId = mentorId;
        this.serviceId = serviceId;
        this.selectedDate = null;
        this.selectedTime = null;
        this.availableDates = [];
        this.availableSlots = [];
    }
    
    async loadAvailableDates() {
        try {
            const response = await fetch(`/api/available-dates/${this.mentorId}`);
            const data = await response.json();
            
            if (data.success) {
                this.availableDates = data.dates;
                return this.availableDates;
            }
            return [];
        } catch (error) {
            console.error('Error loading dates:', error);
            return [];
        }
    }
    
    async loadAvailableSlots(date) {
        try {
            const response = await fetch(`/api/available-slots/${this.mentorId}?date=${date}`);
            const data = await response.json();
            
            if (data.success) {
                this.availableSlots = data.slots;
                return this.availableSlots;
            }
            return [];
        } catch (error) {
            console.error('Error loading slots:', error);
            return [];
        }
    }
    
    async createBooking() {
        if (!this.selectedDate || !this.selectedTime) {
            throw new Error('Please select date and time');
        }
        
        const formData = new FormData();
        formData.append('service_id', this.serviceId);
        formData.append('scheduled_for', this.selectedDate);
        formData.append('time_slot', this.selectedTime);
        
        const response = await fetch('/api/create-booking', {
            method: 'POST',
            body: formData
        });
        
        return response.json();
    }
}

// Payment handler
class PaymentHandler {
    constructor(options = {}) {
        this.options = {
            keyId: options.keyId || '',
            currency: 'INR',
            theme: {
                color: '#4f46e5'
            },
            ...options
        };
    }
    
    initializePayment(orderData, callback) {
        if (typeof Razorpay === 'undefined') {
            console.error('Razorpay SDK not loaded');
            return;
        }
        
        const options = {
            key: this.options.keyId,
            amount: orderData.amount * 100,
            currency: this.options.currency,
            name: 'ClearQ Mentorship',
            description: orderData.description || 'Service Booking',
            order_id: orderData.order_id,
            handler: async (response) => {
                if (callback && typeof callback === 'function') {
                    await callback(response);
                }
            },
            prefill: orderData.prefill || {},
            theme: this.options.theme,
            modal: {
                ondismiss: function() {
                    Utils.showNotification('Payment cancelled', 'info');
                }
            }
        };
        
        const razorpay = new Razorpay(options);
        razorpay.open();
    }
    
    async verifyPayment(paymentResponse) {
        try {
            const formData = new FormData();
            formData.append('razorpay_order_id', paymentResponse.razorpay_order_id);
            formData.append('razorpay_payment_id', paymentResponse.razorpay_payment_id);
            formData.append('razorpay_signature', paymentResponse.razorpay_signature);
            
            const response = await fetch('/api/verify-payment', {
                method: 'POST',
                body: formData
            });
            
            return response.json();
        } catch (error) {
            console.error('Error verifying payment:', error);
            return { success: false, message: 'Payment verification failed' };
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize mobile menu
    const mobileMenuButton = document.getElementById('mobileMenuButton');
    const mobileMenu = document.getElementById('mobileMenu');
    
    if (mobileMenuButton && mobileMenu) {
        mobileMenuButton.addEventListener('click', function() {
            const isExpanded = this.getAttribute('aria-expanded') === 'true';
            this.setAttribute('aria-expanded', !isExpanded);
            mobileMenu.classList.toggle('active');
            
            // Update icon
            const icon = this.querySelector('i');
            if (icon) {
                if (isExpanded) {
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                } else {
                    icon.classList.remove('fa-bars');
                    icon.classList.add('fa-times');
                }
            }
        });
    }
    
    // Close mobile menu when clicking outside
    document.addEventListener('click', function(event) {
        if (mobileMenu && mobileMenuButton && 
            !mobileMenu.contains(event.target) && 
            !mobileMenuButton.contains(event.target) && 
            mobileMenu.classList.contains('active')) {
            mobileMenu.classList.remove('active');
            mobileMenuButton.setAttribute('aria-expanded', 'false');
            const icon = mobileMenuButton.querySelector('i');
            if (icon) {
                icon.classList.remove('fa-times');
                icon.classList.add('fa-bars');
            }
        }
    });
    
    // Close mobile menu on escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && mobileMenu && mobileMenu.classList.contains('active')) {
            mobileMenu.classList.remove('active');
            if (mobileMenuButton) {
                mobileMenuButton.setAttribute('aria-expanded', 'false');
                const icon = mobileMenuButton.querySelector('i');
                if (icon) {
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                }
            }
        }
    });
    
    // Initialize form validators
    const forms = document.querySelectorAll('form[data-validate]');
    forms.forEach(form => {
        const formId = form.id || Utils.generateId();
        if (!form.id) form.id = formId;
        new FormValidator(formId);
    });
    
    // Initialize image uploaders
    const imageInputs = document.querySelectorAll('input[type="file"][data-image-upload]');
    imageInputs.forEach(input => {
        const previewId = input.getAttribute('data-preview');
        if (previewId) {
            new ImageUploader(input.id, previewId);
        }
    });
    
    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            
            if (href === '#' || href.startsWith('#!')) return;
            
            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                
                // Close mobile menu if open
                if (mobileMenu && mobileMenu.classList.contains('active')) {
                    mobileMenu.classList.remove('active');
                    if (mobileMenuButton) {
                        mobileMenuButton.setAttribute('aria-expanded', 'false');
                        const icon = mobileMenuButton.querySelector('i');
                        if (icon) {
                            icon.classList.remove('fa-times');
                            icon.classList.add('fa-bars');
                        }
                    }
                }
                
                // Get header height for offset
                const header = document.querySelector('header');
                const headerHeight = header ? header.offsetHeight : 0;
                
                // Calculate target position
                const targetPosition = target.getBoundingClientRect().top + window.pageYOffset;
                const offsetPosition = targetPosition - headerHeight - 20;
                
                // Smooth scroll
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
    
    // Lazy loading for images
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    const src = img.getAttribute('data-src');
                    if (src) {
                        img.src = src;
                        img.removeAttribute('data-src');
                    }
                    observer.unobserve(img);
                }
            });
        });
        
        document.querySelectorAll('img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });
    }
    
    // Initialize tooltips
    if (typeof tippy !== 'undefined') {
        tippy('[data-tippy-content]', {
            arrow: true,
            animation: 'scale',
            duration: 200,
        });
    }
    
    // Add loading states to buttons
    document.querySelectorAll('button[data-loading]').forEach(button => {
        button.addEventListener('click', function() {
            const originalHTML = this.innerHTML;
            this.innerHTML = '<span class="loading"></span> Processing...';
            this.disabled = true;
            
            // Reset after 10 seconds (fallback)
            setTimeout(() => {
                this.innerHTML = originalHTML;
                this.disabled = false;
            }, 10000);
        });
    });
    
    // Handle form submissions
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            // Prevent double submission
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton && submitButton.disabled) {
                e.preventDefault();
                return;
            }
            
            if (submitButton) {
                submitButton.disabled = true;
                const originalHTML = submitButton.innerHTML;
                submitButton.innerHTML = '<span class="loading"></span> Processing...';
                
                // Re-enable after 30 seconds (fallback)
                setTimeout(() => {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalHTML;
                }, 30000);
            }
        });
    });
    
    // Add keyboard navigation for dropdowns
    document.querySelectorAll('[role="menu"]').forEach(menu => {
        menu.addEventListener('keydown', function(e) {
            const items = this.querySelectorAll('[role="menuitem"]');
            const currentIndex = Array.from(items).indexOf(document.activeElement);
            
            switch(e.key) {
                case 'ArrowDown':
                    e.preventDefault();
                    if (currentIndex < items.length - 1) {
                        items[currentIndex + 1].focus();
                    } else {
                        items[0].focus();
                    }
                    break;
                    
                case 'ArrowUp':
                    e.preventDefault();
                    if (currentIndex > 0) {
                        items[currentIndex - 1].focus();
                    } else {
                        items[items.length - 1].focus();
                    }
                    break;
                    
                case 'Home':
                    e.preventDefault();
                    items[0].focus();
                    break;
                    
                case 'End':
                    e.preventDefault();
                    items[items.length - 1].focus();
                    break;
                    
                case 'Escape':
                    this.closest('[role="menu"]')?.classList.add('hidden');
                    break;
            }
        });
    });
    
    // Initialize analytics if available
    if (typeof gtag !== 'undefined') {
        // Track page views
        gtag('config', 'UA-XXXXXXXXX-X', {
            page_title: document.title,
            page_path: window.location.pathname,
        });
    }
    
    // Service worker registration for PWA
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', function() {
            navigator.serviceWorker.register('/service-worker.js')
                .then(function(registration) {
                    console.log('ServiceWorker registration successful with scope: ', registration.scope);
                })
                .catch(function(err) {
                    console.log('ServiceWorker registration failed: ', err);
                });
        });
    }
    
    // Add beforeunload warning for unsaved changes
    window.addEventListener('beforeunload', function(e) {
        const formsWithChanges = document.querySelectorAll('form[data-unsaved]');
        let hasUnsavedChanges = false;
        
        formsWithChanges.forEach(form => {
            if (form.checkValidity && !form.checkValidity()) {
                hasUnsavedChanges = true;
            }
        });
        
        if (hasUnsavedChanges) {
            e.preventDefault();
            e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
        }
    });
});

// Export utilities for global access
window.ClearQ = {
    Utils,
    FormValidator,
    ImageUploader,
    BookingSystem,
    PaymentHandler
};
