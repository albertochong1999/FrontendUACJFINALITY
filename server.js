const express = require('express');
const bcrypt = require('bcrypt');
const { Connection, Request, TYPES } = require('tedious');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const ExcelJS = require('exceljs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Configuración de CORS
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:5173', 
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
    'https://brave-desert-01acf810f.5.azurestaticapps.net'
];;
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Habilitar preflight para todas las rutas
app.options('*', cors());

// Configuración de la base de datos
const config = {
    server: 'proyectouacj2.database.windows.net',
    authentication: {
        type: 'default',
        options: {
            userName: 'Testback',
            password: 'Fifa14love'
        }
    },
    options: {
        port: 1433,
        database: 'BDUACJonline',
        encrypt: true,
        trustServerCertificate: true,
        rowCollectionOnRequestCompletion: true 
    }
};

// Función para obtener una nueva conexión
function getConnection() {
    return new Promise((resolve, reject) => {
        const connection = new Connection(config);
        connection.on('connect', err => {
            if (err) {
                reject(err);
            } else {
                resolve(connection);
            }
        });
        connection.connect();
    });
}

// Middleware para asegurar que el usuario está autenticado
function ensureAuthenticated(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ message: 'No se proporcionó token de autenticación' });
    }
    const bearerToken = token.split(' ')[1];
    jwt.verify(bearerToken, process.env.JWT_SECRET || 'your_jwt_secret', (err, decoded) => {
        if (err) {
            console.error('Error de validación de token:', err);
            return res.status(401).json({ message: 'Token inválido' });
        }
        req.user = decoded;
        next();
    });
}

function ensureAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ message: 'No autenticado' });
    }
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    next();
}

const transporter = nodemailer.createTransport({
    host: 'smtp.office365.com',
    port: 587,
    secure: false, // true para 465, false para otros puertos
    auth: {
        user: 'al169906@alumnos.uacj.mx', // Tu correo institucional
        pass: 'Fif@16love' // Tu contraseña
    },
    tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false
    }
});

// Verificar la conexión al iniciar el servidor
transporter.verify(function(error, success) {
    if (error) {
        console.log('Error en la configuración del correo:', error);
    } else {
        console.log('Servidor listo para enviar correos');
    }
});

app.post('/api/recover-password', async (req, res) => {
    const { email } = req.body;
    console.log('Solicitud de recuperación para:', email);

    try {
        // Verificar si el email existe en la base de datos
        const connection = await getConnection();
        const checkUserQuery = `SELECT UserID, Name FROM Users WHERE Email = @Email`;
        
        const userResult = await new Promise((resolve, reject) => {
            const request = new Request(checkUserQuery, (err, rowCount, rows) => {
                if (err) {
                    reject(err);
                    return;
                }
                if (rowCount === 0) {
                    resolve(null);
                    return;
                }
                resolve({
                    id: rows[0][0].value,
                    name: rows[0][1].value
                });
            });

            request.addParameter('Email', TYPES.NVarChar, email);
            connection.execSql(request);
        });

        if (!userResult) {
            return res.status(404).json({ 
                message: 'No existe una cuenta con este correo electrónico.' 
            });
        }

        // Generar nueva contraseña temporal
        const newPassword = crypto.randomBytes(4).toString('hex');

        // Actualizar la contraseña en la base de datos
        const updateQuery = `UPDATE Users SET PasswordHash = @PasswordHash WHERE UserID = @UserID`;
        
        await new Promise((resolve, reject) => {
            const request = new Request(updateQuery, (err) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve();
            });

            request.addParameter('PasswordHash', TYPES.NVarChar, newPassword);
            request.addParameter('UserID', TYPES.Int, userResult.id);
            connection.execSql(request);
        });

        // Configurar el correo
        const mailOptions = {
            from: 'al169906@alumnos.uacj.mx', // Tu correo
            to: email,
            subject: 'Recuperación de Contraseña - Sistema UACJ',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #0047AB; color: white; padding: 20px; text-align: center;">
                        <h2 style="margin: 0;">Recuperación de Contraseña</h2>
                    </div>
                    <div style="padding: 20px;">
                        <p>Hola ${userResult.name},</p>
                        <p>Has solicitado recuperar tu contraseña. Tu nueva contraseña temporal es:</p>
                        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
                            <h3 style="color: #0047AB; margin: 0;">${newPassword}</h3>
                        </div>
                        <p style="color: #ff0000; font-weight: bold;">
                            Por seguridad, te recomendamos cambiar esta contraseña temporal 
                            la próxima vez que inicies sesión.
                        </p>
                        <p>Si no solicitaste este cambio, por favor contacta al administrador.</p>
                    </div>
                    <div style="background-color: #0047AB; color: white; padding: 10px; text-align: center; font-size: 12px;">
                        <p>Sistema de Gestión Académica - UACJ</p>
                    </div>
                </div>
            `
        };

        // Enviar el correo
        console.log('Intentando enviar correo...');
        await transporter.sendMail(mailOptions);
        console.log('Correo enviado exitosamente');

        res.json({ 
            message: 'Se ha enviado una nueva contraseña a tu correo electrónico.',
            success: true
        });

    } catch (error) {
        console.error('Error en recuperación de contraseña:', error);
        res.status(500).json({ 
            message: 'Error al procesar la solicitud. Por favor, intenta más tarde.',
            error: error.message
        });
    }
});

// Rutas
app.post('/api/register', async (req, res) => {
    const { email, name, password } = req.body;

    try {
        const connection = await getConnection();
        const query = `INSERT INTO Users (Email, Name, PasswordHash) VALUES (@Email, @Name, @PasswordHash)`;
        const request = new Request(query, (err) => {
            if (err) {
                console.error('Error en la consulta:', err);
                return res.status(500).json({ message: 'Error al registrar el usuario' });
            }
            res.status(200).json({ message: 'Usuario registrado exitosamente' });
            connection.close();
        });

        request.addParameter('Email', TYPES.NVarChar, email);
        request.addParameter('Name', TYPES.NVarChar, name);
        request.addParameter('PasswordHash', TYPES.NVarChar, password);

        connection.execSql(request);
    } catch (err) {
        console.error('Error al conectar:', err);
        res.status(500).json({ message: 'Error de conexión' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Correo electrónico y contraseña son requeridos' });
    }

    try {
        const connection = await getConnection();
        const query = `SELECT UserID, Email, Name, role FROM Users WHERE Email = @Email AND PasswordHash = @PasswordHash`;
        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error al consultar el usuario:', err);
                return res.status(500).json({ message: 'Error en el servidor' });
            }

            if (rowCount === 0) {
                return res.status(401).json({ message: 'Correo o contraseña incorrectos' });
            }

            // Extraer los datos de manera más segura
            const userData = {};
            rows[0].forEach(column => {
                userData[column.metadata.colName] = column.value;
            });

            console.log('Datos del usuario:', userData);

            const token = jwt.sign(
                { 
                    id: userData.UserID, 
                    role: userData.role || 'student'  // Valor por defecto si role es null
                }, 
                'your_jwt_secret', 
                { expiresIn: '1h' }
            );

            res.status(200).json({ 
                token, 
                userId: userData.UserID, 
                role: userData.role || 'student',
                userName: userData.Name || 'Usuario'
            });
            
            connection.close();
        });

        request.addParameter('Email', TYPES.NVarChar, email);
        request.addParameter('PasswordHash', TYPES.NVarChar, password);

        connection.execSql(request);
    } catch (err) {
        console.error('Error al conectar:', err);
        res.status(500).json({ message: 'Error de conexión' });
    }
});

app.get('/api/check-historial', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;

    try {
        const connection = await getConnection();
        const query = 'SELECT materia_id, Status, Semestre FROM HistorialAcademico WHERE UserID = @UserID';
        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error fetching history:', err);
                return res.status(500).json({ error: 'Database error', details: err });
            }

            const historial = rows.map(row => ({
                materia_id: row[0].value,
                status: row[1].value,
                semestre: row[2].value
            }));
            res.json({ historial });
            connection.close();
        });

        request.addParameter('UserID', TYPES.Int, userId);

        connection.execSql(request);
    } catch (err) {
        console.error('Connection error:', err);
        res.status(500).json({ message: 'Connection error' });
    }
});

app.get('/api/materias', async (req, res) => {
    try {
        const connection = await getConnection();
        const query = 'SELECT * FROM Materias';
        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error loading courses:', err);
                return res.status(500).json({ message: 'Error loading courses.' });
            }

            const materias = rows.map(row => ({
                materia_id: row[0].value,
                materia_name: row[1].value,
                // Add other necessary fields
            }));

            res.status(200).json(materias);
            connection.close();
        });

        connection.execSql(request);
    } catch (err) {
        console.error('Connection error:', err);
        res.status(500).json({ message: 'Connection error' });
    }
});

app.post('/api/guardar-historial', ensureAuthenticated, async (req, res) => {
    const { materias } = req.body;
    const userId = req.user.id;

    if (!userId || !materias || !Array.isArray(materias) || materias.length === 0) {
        return res.status(400).json({ message: 'User ID and valid courses array are required' });
    }

    try {
        const connection = await getConnection();
        
        // First, delete existing entries for this user
        const deleteQuery = 'DELETE FROM HistorialAcademico WHERE UserId = @UserId';
        await new Promise((resolve, reject) => {
            const deleteRequest = new Request(deleteQuery, (err) => {
                if (err) {
                    console.error('Error deleting existing entries:', err);
                    reject(err);
                } else {
                    resolve();
                }
            });
            deleteRequest.addParameter('UserId', TYPES.Int, userId);
            connection.execSql(deleteRequest);
        });

        // Now insert new entries
        const insertQuery = `INSERT INTO HistorialAcademico (UserId, materia_id, Status, Semestre) VALUES (@UserId, @materia_id, @Status, @Semestre)`;
        const insertErrors = [];

        for (const materia of materias) {
            await new Promise((resolve, reject) => {
                const request = new Request(insertQuery, (err) => {
                    if (err) {
                        console.error('Error in query:', err);
                        insertErrors.push(err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });

                request.addParameter('UserId', TYPES.Int, userId);
                request.addParameter('materia_id', TYPES.Int, materia.materia_id);
                request.addParameter('Status', TYPES.NVarChar, materia.status);
                request.addParameter('Semestre', TYPES.Int, materia.semestre);

                connection.execSql(request);
            });
        }

        if (insertErrors.length) {
            res.status(500).json({ message: 'Errors saving some courses', errors: insertErrors });
        } else {
            res.status(200).json({ message: 'History saved successfully' });
        }

        connection.close();
    } catch (err) {
        console.error('Error saving history:', err);
        res.status(500).json({ message: 'Error saving history', error: err.message });
    }
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

// Start the server
const server = app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

// Server error handling
server.on('error', (error) => {
    if (error.syscall !== 'listen') {
        throw error;
    }

    const bind = typeof port === 'string'
        ? 'Pipe ' + port
        : 'Port ' + port;

    // Specific error messages for certain listening errors
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
            break;
        default:
            throw error;
    }
});

app.get('/api/user-academic-info', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;

    try {
        const connection = await getConnection();
        const query = `
            SELECT 
                SUM(m.credits) as totalCredits,
                STRING_AGG(CAST(ha.materia_id AS VARCHAR(10)), ',') as approvedSubjects
            FROM HistorialAcademico ha
            JOIN Materias m ON ha.materia_id = m.materia_id
            WHERE ha.UserID = @UserID AND ha.Status = 'Aprobado'
        `;
        
        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error fetching user academic info:', err);
                return res.status(500).json({ error: 'Database error', details: err });
            }

            if (rowCount === 0) {
                return res.json({ totalCredits: 0, approvedSubjects: [] });
            }

            const totalCredits = rows[0][0].value || 0;
            const approvedSubjects = rows[0][1].value ? rows[0][1].value.split(',').map(Number) : [];

            res.json({ totalCredits, approvedSubjects });
            connection.close();
        });

        request.addParameter('UserID', TYPES.Int, userId);
        connection.execSql(request);

    } catch (err) {
        console.error('Connection error:', err);
        res.status(500).json({ message: 'Connection error' });
    }
});

app.get('/api/all-subjects', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;

    try {
        const connection = await getConnection();
        const query = `
            SELECT
                m.materia_id,
                m.materia_name,
                m.credits,
                m.reticula_id,
                m.requerimiento_Creditos,
                pm.prerequisito_materia_id
            FROM Materias m
            LEFT JOIN HistorialAcademico ha ON m.materia_id = ha.materia_id AND ha.UserID = @UserID
            LEFT JOIN PrerequisitosMaterias pm ON m.materia_id = pm.materia_id
            WHERE ha.materia_id IS NULL OR ha.Status != 'Aprobado'
        `;
        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error loading available courses:', err);
                return res.status(500).json({ message: 'Error loading available courses.' });
            }

            const materias = rows.map(row => ({
                materia_id: row[0].value,
                materia_name: row[1].value,
                credits: row[2].value,
                reticula_id: row[3].value,
                requerimiento_Creditos: row[4].value,
                prerequisito_materia_id: row[5].value
            }));

            console.log('Sending response for available courses:', materias);
            res.status(200).json(materias);
            connection.close();
        });

        request.addParameter('UserID', TYPES.Int, userId);
        connection.execSql(request);
    } catch (err) {
        console.error('Connection error:', err);
        res.status(500).json({ message: 'Connection error' });
    }
});

app.get('/api/available-courses', ensureAuthenticated, async (req, res) => {
    console.log('Received request for available courses');
    try {
        const connection = await getConnection();
        const query = 'SELECT * FROM Materias';
        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error loading courses:', err);
                return res.status(500).json({ message: 'Error loading courses.' });
            }

            const materias = rows.map(row => ({
                materia_id: row[0].value,
                materia_name: row[1].value,
            }));

            console.log('Sending response for available courses:', materias);
            res.status(200).json(materias);
            connection.close();
        });

        connection.execSql(request);
    } catch (err) {
        console.error('Connection error:', err);
        res.status(500).json({ message: 'Connection error' });
    }
});

// En server.js
app.get('/api/franjas-horarias', ensureAuthenticated, async (req, res) => {
    try {
        const connection = await getConnection();
        const query = `
                 SELECT 
                        franja_id,
                        CONVERT(VARCHAR(5), hora_inicio, 108) AS hora_inicio,
                        CONVERT(VARCHAR(5), hora_fin, 108) AS hora_fin
                        FROM FranjasHorarias
                        WHERE activo = 1
                        ORDER BY hora_inicio;
                `;

        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error al obtener franjas horarias:', err);
                return res.status(500).json({ 
                    message: 'Error al obtener los intervalos de tiempo' 
                });
            }

            const franjas = rows.map(row => ({
                franja_id: row[0].value,
                hora_inicio: row[1].value,
                hora_fin: row[2].value
            }));

            console.log('Franjas horarias encontradas:', franjas); // Debug
            res.json(franjas);
        });

        connection.execSql(request);
    } catch (err) {
        console.error('Error de conexión:', err);
        res.status(500).json({ 
            message: 'Error al conectar con la base de datos' 
        });
    }
});

app.post('/api/guardar-horarios', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;
    const horarios = req.body;

    console.log('Received request to save schedules:', { userId, horarios });

    let connection; // Declara la variable fuera del bloque `try`

    try {
        connection = await getConnection(); // Asigna la conexión aquí

        // Eliminar preferencias existentes
        const deleteQuery = 'DELETE FROM PreferenciasHorarios WHERE UserID = @UserId';
        await new Promise((resolve, reject) => {
            const deleteRequest = new Request(deleteQuery, (err) => {
                if (err) {
                    console.error('Error deleting existing preferences:', err);
                    reject(err);
                } else {
                    console.log('Existing preferences deleted successfully');
                    resolve();
                }
            });
            deleteRequest.addParameter('UserId', TYPES.Int, userId);
            connection.execSql(deleteRequest);
        });

        // Insertar nuevas preferencias
        const insertQuery = `
            INSERT INTO PreferenciasHorarios 
            (UserID, materia_id, dia_1, dia_2, dia_3, franja_id, semestre, fecha_preferencia) 
            VALUES 
            (@UserId, @materia_id, @dia_1, @dia_2, @dia_3, @franja_id, @semestre, @fecha_preferencia)
        `;

        const insertErrors = [];

        for (const horario of horarios) {
            await new Promise((resolve, reject) => {
                const request = new Request(insertQuery, (err) => {
                    if (err) {
                        console.error('Error inserting preference:', err);
                        insertErrors.push(err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });

                request.addParameter('UserId', TYPES.Int, userId);
                request.addParameter('materia_id', TYPES.Int, horario.materia_id);
                request.addParameter('dia_1', TYPES.VarChar, horario.dia_1);
                request.addParameter('dia_2', TYPES.VarChar, horario.dia_2);
                request.addParameter('dia_3', TYPES.VarChar, horario.dia_3 || null);
                request.addParameter('franja_id', TYPES.Int, horario.franja_id);
                request.addParameter('semestre', TYPES.Int, horario.semestre);
                request.addParameter('fecha_preferencia', TYPES.DateTime, new Date());

                connection.execSql(request);
            });
        }

        if (insertErrors.length) {
            res.status(500).json({ 
                message: 'Errors saving some preferences', 
                errors: insertErrors 
            });
        } else {
            res.status(200).json({ 
                message: 'Preferences saved successfully' 
            });
        }

    } catch (err) {
        console.error('Error in /api/guardar-horarios:', err);
        res.status(500).json({ 
            message: 'Error saving preferences', 
            error: err.message
        });
    } finally {
        // Cierra la conexión si está abierta
        if (connection) {
            connection.close();
        }
    }
});


app.get('/api/horarios-documentation', ensureAuthenticated, ensureAdmin, async (req, res) => {
    console.log('Solicitud recibida para descargar documentación');
    try {
        const connection = await getConnection();
        
        // Función para verificar la estructura de una tabla
        const checkTableStructure = async (tableName) => {
            return new Promise((resolve, reject) => {
                const query = `SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = @TableName`;
                const request = new Request(query, (err, rowCount, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        const columns = rows.map(row => ({
                            name: row[0].value,
                            type: row[1].value
                        }));
                        resolve(columns);
                    }
                });
                request.addParameter('TableName', TYPES.VarChar, tableName);
                connection.execSql(request);
            });
        };

        console.log('Verificando estructura de tablas...');
        const preferenciaColumns = await checkTableStructure('PreferenciasHorarios');
        console.log('Columnas de PreferenciasHorarios:', preferenciaColumns);

        const usersColumns = await checkTableStructure('Users');
        console.log('Columnas de Users:', usersColumns);

        const materiasColumns = await checkTableStructure('Materias');
        console.log('Columnas de Materias:', materiasColumns);

        const franjasColumns = await checkTableStructure('FranjasHorarias');
        console.log('Columnas de FranjasHorarias:', franjasColumns);

        const query = `
            SELECT 
                u.name AS NombreUsuario,
                m.materia_name AS Materia,
                ph.dia_1,
                ph.dia_2,
                ph.dia_3,
                fh.hora_inicio,
                fh.hora_fin,
                ph.semestre
            FROM PreferenciasHorarios ph
            JOIN Users u ON ph.UserID = u.UserID
            JOIN Materias m ON ph.materia_id = m.materia_id
            JOIN FranjasHorarias fh ON ph.franja_id = fh.franja_id
            ORDER BY u.name, ph.semestre, m.materia_name
        `;

        console.log('Ejecutando consulta:', query);

        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error fetching documentation:', err);
                return res.status(500).json({ message: 'Error al obtener la documentación de horarios.', error: err.message });
            }

            console.log(`Rows fetched: ${rowCount}`);

            if (rowCount === 0) {
                return res.status(404).json({ message: 'No se encontraron datos para generar el documento.' });
            }

            console.log('Creando workbook de ExcelJS...');
            const workbook = new ExcelJS.Workbook();
            const worksheet = workbook.addWorksheet('Horarios');

            // Definir encabezados
            worksheet.columns = [
                { header: 'Usuario', key: 'usuario' },
                { header: 'Materia', key: 'materia' },
                { header: 'Día 1', key: 'dia1' },
                { header: 'Día 2', key: 'dia2' },
                { header: 'Día 3', key: 'dia3' },
                { header: 'Hora Inicio', key: 'horaInicio' },
                { header: 'Hora Fin', key: 'horaFin' },
                { header: 'Semestre', key: 'semestre' }
            ];

            // Agregar datos
            rows.forEach(row => {
                worksheet.addRow({
                    usuario: row[0].value,
                    materia: row[1].value,
                    dia1: row[2].value,
                    dia2: row[3].value,
                    dia3: row[4].value,
                    horaInicio: row[5].value,
                    horaFin: row[6].value,
                    semestre: row[7].value
                });
            });

            console.log('Generando archivo Excel...');
            // Generar archivo Excel
            workbook.xlsx.writeBuffer()
                .then(buffer => {
                    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
                    res.setHeader('Content-Disposition', 'attachment; filename=horarios_documentacion.xlsx');
                    res.send(buffer);
                    console.log('Archivo Excel enviado con éxito.');
                })
                .catch(err => {
                    console.error('Error generating Excel file:', err);
                    res.status(500).json({ message: 'Error al generar el archivo Excel', error: err.message });
                });

            connection.close();
        });

        connection.execSql(request);
    } catch (err) {
        console.error('Error de conexión o en la consulta:', err);
        res.status(500).json({ message: 'Error de conexión o en la consulta', error: err.message });
    }
});

// En server.js - Asegúrate que la ruta sea exactamente esta
// En tu server.js

app.get('/api/student-progress', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const connection = await getConnection();
        const query = `
            SELECT 
                u.UserID,
                u.Name,
                u.Email,
                r.reticula_name as carrera,
                COUNT(CASE WHEN ha.Status = 'Aprobado' THEN 1 END) as materias_aprobadas,
                (SELECT COUNT(*) FROM Materias WHERE reticula_id = r.reticula_id) as total_materias
            FROM Users u
            LEFT JOIN HistorialAcademico ha ON u.UserID = ha.UserID
            LEFT JOIN Materias m ON ha.materia_id = m.materia_id
            LEFT JOIN Reticulas r ON m.reticula_id = r.reticula_id
            WHERE u.role != 'admin'
            GROUP BY u.UserID, u.Name, u.Email, r.reticula_name, r.reticula_id
        `;

        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error en la consulta:', err);
                return res.status(500).json({ message: 'Error en la consulta de la base de datos' });
            }

            const estudiantes = rows.map(row => ({
                id: row[0].value,
                nombre: row[1].value,
                email: row[2].value,
                carrera: row[3].value || 'No asignada',
                materiasAprobadas: row[4].value || 0,
                totalMaterias: row[5].value || 0,
                porcentajeAvance: row[4].value && row[5].value 
                    ? ((row[4].value / row[5].value) * 100).toFixed(2) 
                    : 0
            }));

            res.json(estudiantes);
        });

        connection.execSql(request);
    } catch (err) {
        console.error('Error de conexión:', err);
        res.status(500).json({ message: 'Error de conexión a la base de datos' });
    }
});
// En tu server.js

app.get('/api/mi-progreso', ensureAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id; // ID del usuario actual
        const connection = await getConnection();
        
        const query = `
            SELECT 
                u.Name,
                u.Email,
                r.reticula_name as carrera,
                COUNT(CASE WHEN ha.Status = 'Aprobado' THEN 1 END) as materias_aprobadas,
                (SELECT COUNT(*) FROM Materias WHERE reticula_id = m.reticula_id) as total_materias,
                SUM(CASE WHEN ha.Status = 'Aprobado' THEN m.credits ELSE 0 END) as creditos_acumulados,
                (SELECT SUM(credits) FROM Materias WHERE reticula_id = m.reticula_id) as total_creditos
            FROM Users u
            LEFT JOIN HistorialAcademico ha ON u.UserID = ha.UserID
            LEFT JOIN Materias m ON ha.materia_id = m.materia_id
            LEFT JOIN Reticulas r ON m.reticula_id = r.reticula_id
            WHERE u.UserID = @UserId
            GROUP BY u.Name, u.Email, r.reticula_name, m.reticula_id
        `;

        const request = new Request(query, (err, rowCount, rows) => {
            if (err) {
                console.error('Error en la consulta:', err);
                return res.status(500).json({ message: 'Error al obtener el progreso' });
            }

            if (rowCount === 0) {
                return res.status(404).json({ message: 'No se encontraron datos' });
            }

            const progreso = {
                nombre: rows[0][0].value,
                email: rows[0][1].value,
                carrera: rows[0][2].value || 'No asignada',
                materiasAprobadas: rows[0][3].value || 0,
                totalMaterias: rows[0][4].value || 0,
                creditosAcumulados: rows[0][5].value || 0,
                totalCreditos: rows[0][6].value || 0,
                porcentajeAvance: rows[0][3].value && rows[0][4].value 
                    ? ((rows[0][3].value / rows[0][4].value) * 100).toFixed(2) 
                    : 0
            };

            res.json(progreso);
        });

        request.addParameter('UserId', TYPES.Int, userId);
        connection.execSql(request);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({ message: 'Error de conexión' });
    }
});