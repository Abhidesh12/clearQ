// Initialize Razorpay
function initializeRazorpay(orderData, callback) {
    const options = {
        key: orderData.key,
        amount: orderData.order.amount,
        currency: orderData.order.currency,
        name: 'ClearQ',
        description: 'Payment for service',
        order_id: orderData.order.id,
        handler: function(response) {
            callback(response);
        },
        prefill: {
            name: orderData.user_name || '',
            email: orderData.user_email || '',
            contact: orderData.user_phone || ''
        },
        theme: {
            color: '#667eea'
        }
    };
    
    const rzp = new Razorpay(options);
    rzp.open();
}

// Book service with payment
function bookServiceWithPayment(serviceId, date, slot) {
    fetch(`/book-service/${serviceId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `date=${encodeURIComponent(date)}&slot=${encodeURIComponent(slot)}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success && data.booking_id) {
            // Create Razorpay order
            return fetch('/create-order', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    amount: data.amount,
                    currency: 'INR',
                    booking_id: data.booking_id
                })
            });
        } else {
            throw new Error(data.message || 'Booking failed');
        }
    })
    .then(response => response.json())
    .then(orderData => {
        if (orderData.success) {
            // Initialize Razorpay payment
            initializeRazorpay(orderData, function(response) {
                // Verify payment
                fetch('/verify-payment', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        razorpay_payment_id: response.razorpay_payment_id,
                        razorpay_order_id: response.razorpay_order_id,
                        razorpay_signature: response.razorpay_signature,
                        booking_id: data.booking_id
                    })
                })
                .then(response => response.json())
                .then(verificationData => {
                    if (verificationData.success) {
                        window.location.href = verificationData.redirect || '/dashboard';
                    } else {
                        alert('Payment verification failed: ' + verificationData.error);
                    }
                });
            });
        } else {
            alert('Failed to create order: ' + orderData.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred: ' + error.message);
    });
}
