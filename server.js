// Import required modules
const express = require('express');
const { Sequelize, DataTypes, Op } = require('sequelize');
const ExcelJS = require('exceljs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

const adminConfig = require('./config/admin');
const adminRoutes = require('./routes/admin');

const sequelize = require('./config/database');
const User = require('./models/user');
const Equipment = require('./models/Equipment');
const Rental = require('./models/Rental');

// Initialize Express app
const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
//app.use(express.static('public'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', adminRoutes);


const authenticateAdmin = require('./middleware/auth');
const authenticateOwner = require('./middleware/auth-owner');

// Add this route to check authentication status
app.get('/api/check-auth', authenticateOwner, (req, res) => {
    // If the middleware passes, the user is authenticated
    res.status(200).json({ authenticated: true });
});

app.get('/api/check-auth-admin', authenticateAdmin, (req, res) => {
    // If the middleware passes, the user is authenticated
    res.status(200).json({ authenticated: true });
});
/*
// Route to get all equipment (when loading the starting page)
app.get('/api/equipment', async (req, res) => {
    //console.log("get all equipment");
    try {
        const equipment = await Equipment.findAll({ where: { is_deleted: false } });
        res.json(equipment);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to retrieve equipment.' });
    }
});
*/

// Route to get all equipment (when loading the starting page) //changed
app.get('/api/equipment', authenticateOwner, async (req, res) => {
    try {
        // Find the user based on the username from the token
        const user = await User.findOne({ where: { username: req.username } });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        // Fetch only the equipment for this specific owner
        const equipment = await Equipment.findAll({ 
            where: { 
                ownerId: user.id,
                is_deleted: false 
            } 
        });

        res.json(equipment);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to retrieve equipment.' });
    }
});


// Route to get equipment by ID (when pressing on equipment to get to its details)
app.get('/api/equipment/:id', async (req, res) => {
    console.log("get equipment by ID");
    const equipmentId = req.params.id;
    try {
        const equipment = await Equipment.findOne({ where: { id: equipmentId, is_deleted: false } });
        if (!equipment) {
            return res.status(404).json({ message: 'Equipment not found.' });
        }
        res.json(equipment);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to retrieve equipment.' });
    }
});



// Route to get rental details for an equipment (when equipment is being already rented)
app.get('/api/equipment/:id/rental', async (req, res) => {
    console.log("get rental details for an equipment");
    const equipmentId = req.params.id;
    try {
        const rental = await Rental.findOne({ where: { equipment_id: equipmentId, end_time: null } });
        if (rental) {
            res.json(rental);
        } else {
            res.status(404).json({ message: 'No active rental found for this equipment.' });
        }
    } catch (error) {
        console.error('Error fetching rental data:', error);
        res.status(500).json({ message: 'Failed to retrieve rental data.' });
    }
});


/*
// Route to add new equipment
app.post('/api/equipment', authenticateOwner, async (req, res) => {
    console.log("add new equipment");
    const { name } = req.body;
    try {
        const newEquipment = await Equipment.create({ name, status: 'available', ownerId: req.userId });
        res.status(201).json(newEquipment);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to add equipment.' });
    }
});
*/

// Route to add new equipment (when pressing to add new equipment) //changed
app.post('/api/equipment', authenticateOwner, async (req, res) => {
    const { name } = req.body;
    try {
        const user = await User.findOne({ where: { username: req.username } });
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        const newEquipment = await Equipment.create({ 
            name, 
            status: 'available', 
            ownerId: user.id 
        });

        res.status(201).json(newEquipment);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to add equipment.' });
    }
});



/*
// Route to start new rental order (when pressing to start rental) 
app.post('/api/rentals', async (req, res) => {
    console.log("add new rental order");
    const { customer_name, equipment_id, hourly_rate } = req.body;
    try {
        const equipment = await Equipment.findOne({ where: { id: equipment_id } });

        if (equipment.status === 'rented') {
            return res.status(400).json({ message: 'This equipment is already rented.' });
        }

        const start_time = new Date();
        const rental = await Rental.create({
            customer_name,
            equipment_id,
            hourly_rate,
            start_time: start_time  // Start time is set to the current time
        });

        // Update equipment status to "rented"
        await Equipment.update(
            { status: 'rented' },
            { where: { id: equipment_id } }
        );

        res.status(201).json(rental);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to create rental order.' });
    }
});
*/


// Route to start new rental order (when pressing to start rental)  //changed
app.post('/api/rentals', authenticateOwner, async (req, res) => {
    const { customer_name, equipment_id, hourly_rate, is_fixed_price, total_cost } = req.body;
    
    try {
        const user = await User.findOne({ where: { username: req.username } });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        const equipment = await Equipment.findOne({ 
            where: { 
                id: equipment_id, 
                ownerId: user.id 
            } 
        });

        if (!equipment) {
            return res.status(403).json({ message: 'You do not have permission to rent this equipment' });
        }

        if (equipment.status === 'rented') {
            return res.status(400).json({ message: 'This equipment is already rented.' });
        }

        const start_time = new Date();
        const rental = await Rental.create({
            customer_name,
            equipment_id,
            hourly_rate,
            ownerId: user.id,
            start_time: start_time,
            is_fixed_price,
            total_cost: is_fixed_price ? total_cost : null // Set total_cost only for fixed price rentals
        });

        await Equipment.update(
            { status: 'rented' },
            { where: { id: equipment_id } }
        );

        res.status(201).json(rental);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to create rental order.' });
    }
});


// Route to end a rental (when pressing to end order) now
app.put('/api/rentals/end', authenticateOwner, async (req, res) => {
    const { equipment_id, total_cost } = req.body;
    try {
        const user = await User.findOne({ where: { username: req.username } });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        const rental = await Rental.findOne({
            where: {
                equipment_id: equipment_id,
                ownerId: user.id, 
                end_time: null
            }
        });

        if (!rental) {
            return res.status(403).json({ message: 'This equipment is not being rented or you do not have permission to end this rental' });
        }

        const endTime = new Date();
        let finalCost;

        if (rental.is_fixed_price) {
            // For fixed price rentals, use the total_cost that was set at the start
            finalCost = rental.total_cost;
        } else {
            // For hourly rentals, calculate based on duration
            const rentalDurationHours = (endTime - rental.start_time) / (1000 * 60 * 60);
            finalCost = rentalDurationHours * rental.hourly_rate;
        }

        await rental.update({
            end_time: endTime,
            total_cost: finalCost
        });

        await Equipment.update(
            { status: 'available' },
            { where: { id: rental.equipment_id } }
        );

        res.json(rental);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to end rental.' });
    }
});



/*
// Route to end a rental (when pressing to end order)
app.put('/api/rentals/end', async (req, res) => {
    console.log("stop rental order");
    const { equipment_id } = req.body;
    try {
        const rental = await Rental.findOne({
            where: {
                equipment_id: equipment_id,
                end_time: null
            }
        });

        if (!rental) {
            return res.status(404).json({ message: 'Active rental not found for this equipment.' });
        }

        const endTime = new Date();
        const rentalDurationHours = (endTime - rental.start_time) / (1000 * 60 * 60);
        const totalCost = rentalDurationHours * rental.hourly_rate;

        await rental.update({
            end_time: endTime,
            total_cost: totalCost
        });

        // Update equipment status back to "available"
        await Equipment.update(
            { status: 'available' },
            { where: { id: rental.equipment_id } }
        );

        res.json(rental);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to end rental.' });
    }
});
*/

// Route to delete equipment (when pressing to delete equipment) //now
app.delete('/api/equipment/:id', authenticateOwner, async (req, res) => {
    const equipmentId = req.params.id;
    try {
        // Find the user (owner) based on the username from the token
        const user = await User.findOne({ where: { username: req.username } });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }
        // Find the equipment and verify it belongs to the owner
        const equipment = await Equipment.findOne({ 
            where: { 
                id: equipmentId, 
                ownerId: user.id,
                is_deleted: false
            } 
        });

        if (!equipment) {
            return res.status(403).json({ message: 'You do not have permission to delete this equipment' });
        }
        // Find rentals that are currently active
        const rentals = await Rental.findAll({
            where: {
                equipment_id: equipmentId,
                end_time: {
                    [Op.gte]: new Date() // Find rentals that are ongoing
                }
            }
        });

        if (rentals.length > 0) {
            return res.status(400).json({ message: 'Cannot delete equipment with active rentals.' });
        }

        // Proceed to soft delete
        const result = await Equipment.update(
            { is_deleted: true },
            { 
                where: { 
                    id: equipmentId,
                ownerId: user.id
                } 
            }
        );

        if (result[0] === 0) {
            return res.status(404).json({ message: 'Equipment not found.' });
        }

        res.json({ message: 'Equipment deleted successfully.' });
    } catch (error) {
        console.error('Error deleting equipment:', error);
        res.status(500).json({ message: 'Failed to delete equipment.' });
    }
});

/*
// Route to delete equipment (when pressing to delete equipment)
app.delete('/api/equipment/:id', async (req, res) => {
    console.log("delete equipment");
    const equipmentId = req.params.id;
    try {
        // Find rentals that are currently active
        const rentals = await Rental.findAll({
            where: {
                equipment_id: equipmentId,
                end_time: {
                    [Op.gte]: new Date() // Find rentals that are ongoing
                }
            }
        });

        if (rentals.length > 0) {
            return res.status(400).json({ message: 'Cannot delete equipment with active rentals.' });
        }

        // Proceed to soft delete
        const result = await Equipment.update(
            { is_deleted: true },
            { where: { id: equipmentId } }
        );

        if (result[0] === 0) {
            return res.status(404).json({ message: 'Equipment not found.' });
        }

        res.json({ message: 'Equipment deleted successfully.' });
    } catch (error) {
        console.error('Error deleting equipment:', error);
        res.status(500).json({ message: 'Failed to delete equipment.' });
    }
});
*/



/*
// Route to generate and download Excel file
app.get('/api/rentals/excel', async (req, res) => {
    try {
        const rentals = await Rental.findAll({
            include: [Equipment]
        });

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Rentals');

        // Define the header row
        worksheet.columns = [
            { header: 'ID', key: 'id', width: 10 },
            { header: 'Customer Name', key: 'customer_name', width: 30 },
            { header: 'Equipment Name', key: 'equipment_name', width: 30 },
            { header: 'Hourly Rate', key: 'hourly_rate', width: 15 },
            { header: 'Start Time', key: 'start_time', width: 20 },
            { header: 'End Time', key: 'end_time', width: 20 },
            { header: 'Total Cost', key: 'total_cost', width: 15 }
        ];

        // Add data rows
        rentals.forEach(rental => {
            worksheet.addRow({
                id: rental.id,
                customer_name: rental.customer_name,
                equipment_name: rental.Equipment.name,
                hourly_rate: rental.hourly_rate,
                start_time: rental.start_time,
                end_time: rental.end_time,
                total_cost: rental.total_cost
            });
        });

        // Write to buffer
        const buffer = await workbook.xlsx.writeBuffer();

        res.setHeader('Content-Disposition', 'attachment; filename="rentals.xlsx"');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.send(buffer);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to generate Excel file.' });
    }
});
*/






// Route to generate and download Excel file //now
app.get('/api/rentals/excel', authenticateOwner, async (req, res) => {
    try {
        // Find the user (owner) based on the username from the token
        const user = await User.findOne({ where: { username: req.username } });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        // Find rentals for this specific owner, including associated equipment
        const rentals = await Rental.findAll({
            where: { ownerId: user.id }, // Filter rentals by owner
            include: [
                {
                    model: Equipment,
                    where: { ownerId: user.id } // Ensure equipment belongs to the owner
                }
            ]
        });

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Rentals');

        // Define the header row
        worksheet.columns = [
            { header: 'ID', key: 'id', width: 10 },
            { header: 'Customer Name', key: 'customer_name', width: 30 },
            { header: 'Equipment Name', key: 'equipment_name', width: 30 },
            { header: 'Hourly Rate', key: 'hourly_rate', width: 15 },
            { header: 'Start Time', key: 'start_time', width: 20 },
            { header: 'End Time', key: 'end_time', width: 20 },
            { header: 'Total Cost', key: 'total_cost', width: 15 }
        ];

        // Add data rows
        rentals.forEach(rental => {
            worksheet.addRow({
                id: rental.id,
                customer_name: rental.customer_name,
                equipment_name: rental.Equipment.name,
                hourly_rate: rental.hourly_rate,
                start_time: rental.start_time ? rental.start_time.toLocaleString() : 'N/A',
                end_time: rental.end_time ? rental.end_time.toLocaleString() : 'N/A',
                total_cost: rental.total_cost || 'N/A'
            });
        });

        // Write to buffer
        const buffer = await workbook.xlsx.writeBuffer();

        res.setHeader('Content-Disposition', 'attachment; filename="rentals.xlsx"');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.send(buffer);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to generate Excel file.' });
    }
});


app.get('/login', (req, res) => {
     res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


app.get('/', authenticateOwner, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Protect any other pages that require authentication
app.get('/equipment-details', authenticateOwner, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'equipment-details.html'));
});




const PORT = process.env.PORT || 3000;
// Sync Sequelize models and start the server
sequelize.sync()
    .then(() => {
        console.log('Database & tables created!');
        app.listen(PORT, '0.0.0.0', () => {
            console.log('Server running on port 3000');
        });
    })
    .catch((error) => {
        console.error('Unable to sync database:', error);
});

/*

//const express = require('express');
const { Server } = require('ws');

// WebSocket server
const wss = new Server({ noServer: true });

wss.on('connection', (ws) => {
    setInterval(async () => {
        const equipment = await Equipment.findAll({ where: { is_deleted: false } });
        ws.send(JSON.stringify(equipment));
    }, 5000);
});


server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

app.use(express.json());
app.get('/api/equipment', async (req, res) => {
    try {
        const equipment = await Equipment.findAll({ where: { is_deleted: false } });
        res.json(equipment);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to retrieve equipment.' });
    }
});



*/

/*
// Middleware for admin authentication
const authenticateAdmin = (req, res, next) => {
    console.log("authenticateAdmin");
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Failed to authenticate token' });

        req.username = decoded.username;
        next();
    });
};



// Admin login route
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === adminConfig.username && password === adminConfig.password) {
        const token = jwt.sign({ username }, 'your_jwt_secret', { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true }).sendStatus(200);
    } else {
        // Check if the user is an owner
      try {
        const user = await User.findOne({ where: { username } });
        if (user && await bcrypt.compare(password, user.password)) {
          res.cookie('username', username);
          res.cookie('role', 'owner'); // Set role cookie
          return res.json({ message: 'Login successful', role: 'owner' });
        } else {
          return res.status(401).json({ message: 'Invalid credentials' });
        }
      } catch (error) {
        return res.status(500).json({ message: 'Error during login', error });
      }
    }
});



// Admin create owner route
// Admin create owner route
app.post('/admin/create-owner', authenticateAdmin, async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = await User.create({
            username,
            password: hashedPassword,
            role: 'owner' // or any role you intend to set
        });
        res.status(201).json(newUser);
    } catch (error) {
        console.error('Error creating new owner:', error);
        res.status(500).json({ message: 'Failed to create owner.' });
    }
});

app.get('/admin/current-admin', authenticateAdmin, (req, res) => {
    res.json({ username: req.username });
  });


app.get('/admin/current-user', (req, res) => {
    const username = req.cookies.username;
    const role = req.cookies.role;
  
    if (username && role) {
      res.json({ username, role });
    } else {
      res.status(401).json({ message: 'Not authenticated' });
    }
});
  
*/