// Function to refresh all devices
async function refreshDevices() {
    try {
        const response = await fetch('/api/devices/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to refresh devices');
        }

        const data = await response.json();
        updateDeviceStats(data.stats);
        updateDeviceTable(data.devices);
        showToast('success', 'Devices refreshed successfully');
    } catch (error) {
        console.error('Error refreshing devices:', error);
        showToast('error', 'Failed to refresh devices');
    }
}

// Function to refresh a single device
async function refreshDevice(deviceId) {
    try {
        const response = await fetch(`/api/devices/${deviceId}/refresh`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to refresh device');
        }

        const data = await response.json();
        updateDeviceStats(data.stats);
        updateDeviceTable(data.devices);
        showToast('success', 'Device refreshed successfully');
    } catch (error) {
        console.error('Error refreshing device:', error);
        showToast('error', 'Failed to refresh device');
    }
}

// Function to update device statistics with animation
function updateDeviceStats(stats) {
    animateNumber('onlineDevices', stats.online);
    animateNumber('offlineDevices', stats.offline);
    animateNumber('pendingDevices', stats.pending);
    animateNumber('totalDevices', stats.total);
}

// Function to animate number changes
function animateNumber(elementId, newValue) {
    const element = document.getElementById(elementId);
    const currentValue = parseInt(element.textContent);
    const duration = 1000; // Animation duration in milliseconds
    const steps = 60; // Number of steps in the animation
    const stepValue = (newValue - currentValue) / steps;
    let currentStep = 0;

    const interval = setInterval(() => {
        currentStep++;
        const value = Math.round(currentValue + (stepValue * currentStep));
        element.textContent = value;

        if (currentStep >= steps) {
            element.textContent = newValue;
            clearInterval(interval);
        }
    }, duration / steps);
}

// Function to update the device table
function updateDeviceTable(devices) {
    const tbody = document.getElementById('deviceTableBody');
    tbody.innerHTML = '';

    if (!devices || devices.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="px-6 py-4 text-center text-gray-400">No devices found</td>
            </tr>
        `;
        return;
    }

    devices.forEach(device => {
        const row = document.createElement('tr');
        row.className = 'text-gray-300 hover:bg-gray-700/50 transition-all duration-300';
        
        row.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap">${device.name}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-3 py-1.5 text-sm font-medium rounded-full ${
                    device.status === 'Online' 
                        ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                        : 'bg-red-500/10 text-red-400 border border-red-500/20'
                }">
                    ${device.status}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">${device.model}</td>
            <td class="px-6 py-4 whitespace-nowrap">${device.manufacturer}</td>
            <td class="px-6 py-4 whitespace-nowrap">${device.osVersion}</td>
            <td class="px-6 py-4 whitespace-nowrap">${device.serialNumber}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center space-x-3">
                    <button onclick="refreshDevice('${device.id}')" 
                            class="inline-flex items-center text-blue-400 hover:text-blue-300 transition-all duration-300"
                            title="Refresh Device">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                        </svg>
                    </button>
                    <button onclick="showDeviceDetails('${device.id}')"
                            class="inline-flex items-center text-blue-400 hover:text-blue-300 transition-all duration-300"
                            title="View Details">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                        </svg>
                    </button>
                </div>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

// Function to show device details modal
async function showDeviceDetails(deviceId) {
    try {
        const response = await fetch(`/api/devices/${deviceId}`);
        if (!response.ok) {
            throw new Error('Failed to fetch device details');
        }

        const device = await response.json();
        const modal = document.getElementById('deviceDetailsModal');
        const content = document.getElementById('deviceDetailsContent');

        content.innerHTML = `
            <div class="space-y-4">
                <div class="bg-gray-700/50 p-4 rounded-lg">
                    <h4 class="text-sm font-medium text-gray-400 mb-2">Basic Information</h4>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <p class="text-sm text-gray-400">Name</p>
                            <p class="text-white">${device.name}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-400">Status</p>
                            <span class="px-3 py-1.5 text-sm font-medium rounded-full inline-block ${
                                device.status === 'Online' 
                                    ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                                    : 'bg-red-500/10 text-red-400 border border-red-500/20'
                            }">
                                ${device.status}
                            </span>
                        </div>
                    </div>
                </div>
                
                <div class="bg-gray-700/50 p-4 rounded-lg">
                    <h4 class="text-sm font-medium text-gray-400 mb-2">Hardware Details</h4>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <p class="text-sm text-gray-400">Model</p>
                            <p class="text-white">${device.model}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-400">Manufacturer</p>
                            <p class="text-white">${device.manufacturer}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-400">Serial Number</p>
                            <p class="text-white">${device.serialNumber}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-400">OS Version</p>
                            <p class="text-white">${device.osVersion}</p>
                        </div>
                    </div>
                </div>

                <div class="bg-gray-700/50 p-4 rounded-lg">
                    <h4 class="text-sm font-medium text-gray-400 mb-2">System Information</h4>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <p class="text-sm text-gray-400">Last Check-in</p>
                            <p class="text-white">${formatDate(device.lastCheckIn)}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-400">Last Update</p>
                            <p class="text-white">${formatDate(device.lastUpdate)}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-400">Battery Level</p>
                            <p class="text-white">${device.batteryLevel}%</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-400">Storage Used</p>
                            <p class="text-white">${device.storageUsed}%</p>
                        </div>
                    </div>
                </div>
            </div>
        `;

        modal.classList.remove('hidden');
    } catch (error) {
        console.error('Error fetching device details:', error);
        showToast('error', 'Failed to fetch device details');
    }
}

// Function to hide device details modal
function hideDeviceDetails() {
    const modal = document.getElementById('deviceDetailsModal');
    modal.classList.add('hidden');
}

// Function to format date
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Function to filter devices
function filterDevices() {
    const searchInput = document.getElementById('deviceSearch');
    const filter = searchInput.value.toLowerCase();
    const tbody = document.getElementById('deviceTableBody');
    const rows = tbody.getElementsByTagName('tr');

    for (let row of rows) {
        const cells = row.getElementsByTagName('td');
        let shouldShow = false;

        for (let cell of cells) {
            const text = cell.textContent || cell.innerText;
            if (text.toLowerCase().indexOf(filter) > -1) {
                shouldShow = true;
                break;
            }
        }

        row.style.display = shouldShow ? '' : 'none';
    }
}

// Function to show toast notifications
function showToast(type, message) {
    const toast = document.createElement('div');
    toast.className = `fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg transition-all duration-300 transform translate-y-0 z-50 ${
        type === 'success' ? 'bg-green-500' : 'bg-red-500'
    }`;
    
    toast.innerHTML = `
        <div class="flex items-center text-white">
            <span class="text-sm font-medium">${message}</span>
        </div>
    `;

    document.body.appendChild(toast);

    // Animate in
    setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-2');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}

// Initialize event listeners when the document is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Add event listener for the search input
    const searchInput = document.getElementById('deviceSearch');
    if (searchInput) {
        searchInput.addEventListener('input', filterDevices);
    }

    // Add event listener for clicking outside the modal to close it
    const modal = document.getElementById('deviceDetailsModal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                hideDeviceDetails();
            }
        });
    }

    // Add event listener for the Escape key to close the modal
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideDeviceDetails();
        }
    });
}); 