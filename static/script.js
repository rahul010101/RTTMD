let packets = [];

function fetchPackets() {
    fetch('/packets')
        .then(response => response.json())
        .then(data => {
            packets = data; // Store packets in a global variable
            const tableBody = document.getElementById('packet-table-body');
            tableBody.innerHTML = '';  // Clear the table

            // Insert new packets at the top
            data.forEach((packet, index) => {
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.textContent = `${packet.timestamp} - ${packet.summary}`;  // Set the packet summary with timestamp

                // Create a new cell for the threat level
                const threatCell = document.createElement('td');
                threatCell.textContent = packet.threat_level;  // Show threat level
                threatCell.className = `threat-level threat-level-${packet.threat_level.toLowerCase()}`;  // Add classes for styling

                const srcIpCell = document.createElement('td');
                srcIpCell.textContent = packet.fields.ip_src || 'N/A';  // Source IP

                const dstIpCell = document.createElement('td');
                dstIpCell.textContent = packet.fields.ip_dst || 'N/A';  // Destination IP

                const srcPortCell = document.createElement('td');
                srcPortCell.textContent = packet.fields.tcp_sport || packet.fields.udp_sport || 'N/A';  // Source Port

                const dstPortCell = document.createElement('td');
                dstPortCell.textContent = packet.fields.tcp_dport || packet.fields.udp_dport || 'N/A';  // Destination Port

                const saveButton = document.createElement('button');
                saveButton.textContent = 'Save';
                saveButton.onclick = () => savePacket(index);  // Pass index to save function

                row.appendChild(cell);
                row.appendChild(threatCell);  // Add threat level cell to the row
                row.appendChild(srcIpCell);  // Add source IP cell
                row.appendChild(dstIpCell);  // Add destination IP cell
                row.appendChild(srcPortCell);  // Add source port cell
                row.appendChild(dstPortCell);  // Add destination port cell
                row.appendChild(saveButton);  // Add save button to the row

                // Insert the new row at the top of the table
                tableBody.insertBefore(row, tableBody.firstChild);
            });
        })
        .catch(error => console.error('Error fetching packets:', error));
}

// Fetch packets every 2 seconds
setInterval(fetchPackets, 2000);

function startCapture() {
    fetch('/start')
        .then(response => response.json())
        .then(data => alert(data.status))
        .catch(error => console.error('Error starting capture:', error));
}

function stopCapture() {
    fetch('/stop')
        .then(response => response.json())
        .then(data => alert(data.status))
        .catch(error => console.error('Error stopping capture:', error));
}

function clearCapture() {
    fetch('/clear')
        .then(response => response.json())
        .then(data => alert(data.status))
        .catch(error => console.error('Error clearing capture:', error));
}

function savePacket(packetIndex) {
    fetch(`/save/${packetIndex}`)
        .then(response => response.json())
        .then(data => alert(data.status))
        .catch(error => console.error('Error saving packet:', error));
}
