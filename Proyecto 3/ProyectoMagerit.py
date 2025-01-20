import tkinter as tk #interfaz grafica de usuario
from tkinter import ttk, messagebox #interfaz grafica de usuario
from fpdf import FPDF #libreria para generar pdf
import sqlite3 #base de datos
import requests
import shodan
import socket


# ========================
# Configuración de APIs
# ========================
API_KEY_SHODAN = "KpSMnZX7xqm5UTk7IDyNbZVPnFjSOp2b"
API_KEY_INTELX  = "18adfc1b-0473-465e-b6a8-40817b3a6708"
API_KEY_NVD = "7db96e7b-2061-4bda-bfa1-3ce54b8b3f18  "
API_KEY_WEATHER = "533f90fe7aa476a274c51df4f2759afe"


# ========================
# Configuración de la Base de Datos
# ========================

# Conexión a la base de datos (se crea si no existe)
conn = sqlite3.connect('gestion_riesgos.db')
cursor = conn.cursor()

# Creación de tablas
def crear_tablas():
    #Tabla activos
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activos (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        nombre TEXT NOT NULL,
        tipo TEXT NOT NULL,
        valor INTEGER NOT NULL,
        impacto_empresa TEXT NOT NULL
    )
    """)
    
    #Tabla riesgos
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS riesgos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        activo_id INTEGER NOT NULL,
        amenaza TEXT NOT NULL,
        probabilidad TEXT NOT NULL,
        impacto TEXT NOT NULL,
        nivel_riesgo INTEGER NOT NULL,
        control TEXT,
        efectividad TEXT,
        riesgo_residual INTEGER,
        FOREIGN KEY (activo_id) REFERENCES activos(id)
    )
    """)
    
    conn.commit() #guarda los cambios

crear_tablas()

# ========================
# Funciones para Gestión de Activos
# ========================

# Función para agregar un activo
def agregar_activo():
    nombre = entry_nombre_activo.get().strip()  # Obtiene el nombre del activo
    tipo = combo_tipo_activo.get().strip()  # Obtiene el tipo del activo
    valor = entry_valor_activo.get().strip()  # Obtiene el valor del activo
    impacto_empresa = combo_impacto_empresa_activo.get().strip()  # Obtiene el impacto en la empresa

    # Validación de campos
    if not nombre or not tipo or not valor or not impacto_empresa:
        messagebox.showerror("Error", "Todos los campos son obligatorios y el valor debe ser numérico.")
        return

    if not valor.isdigit():
        messagebox.showerror("Error", "El valor del activo debe ser numérico.")
        return

    # Inserta el activo en la base de datos
    cursor.execute("""
    INSERT INTO activos (nombre, tipo, valor, impacto_empresa)
    VALUES (?, ?, ?, ?)
    """, (nombre, tipo, int(valor), impacto_empresa))
    conn.commit()

    messagebox.showinfo("Éxito", "Activo agregado correctamente.")
    listar_activos()  # Actualiza la lista de activos mostrada
    actualizar_combo_activo_riesgo()  # Actualiza el combo de activos en los riesgos
    limpiar_campos_activo()  # Limpia los campos de entrada

# Función para listar todos los activos en la tabla
def listar_activos():
    for row in tree_activos.get_children():
        tree_activos.delete(row)  # Elimina las filas existentes

    cursor.execute("SELECT * FROM activos")
    activos = cursor.fetchall()
    for activo in activos:
        tree_activos.insert("", "end", values=activo)

# Función para limpiar los campos de entrada de activos
def limpiar_campos_activo():
    entry_nombre_activo.delete(0, tk.END) #elimina texto campo de entrada
    combo_tipo_activo.set("") #limpia el combo
    entry_valor_activo.delete(0, tk.END) #elimina texto campo de entrada
    combo_impacto_empresa_activo.set("")#limpia el combo

# Función para actualizar el combo de activos en los riesgos
def actualizar_combo_activo_riesgo():
    cursor.execute("SELECT id, nombre FROM activos")
    activos = cursor.fetchall()
    combo_activo_riesgo['values'] = [f"{activo[0]}-{activo[1]}" for activo in activos]

# ========================
# Funciones para Gestión de Riesgos
# ========================

# Definición de calcular_riesgo
def calcular_riesgo(probabilidad, impacto):
    valores = {"Muy Baja": 1, "Baja": 2, "Media": 3, "Alta": 4, "Muy Alta": 5}
    prob = valores.get(probabilidad, 1)
    imp = valores.get(impacto, 1)
    return prob * imp

# Función para agregar un riesgo
def agregar_riesgo():
    activo_id_nombre = combo_activo_riesgo.get().strip()  # Obtiene el activo seleccionado
    amenaza = combo_amenaza.get().strip()  # Obtiene la amenaza asociada
    probabilidad = combo_probabilidad.get().strip()  # Obtiene la probabilidad del riesgo
    impacto = combo_impacto.get().strip()  # Obtiene el impacto del riesgo

    # Validación de campos
    if not activo_id_nombre or not amenaza or not probabilidad or not impacto:
        messagebox.showerror("Error", "Todos los campos son obligatorios.")
        return

    try:
        # Extrae el ID del activo seleccionado
        activo_id = int(activo_id_nombre.split("-")[0])
    except ValueError:
        messagebox.showerror("Error", "Formato de Activo inválido.")
        return

    # Calcula el nivel de riesgo basado en probabilidad e impacto
    nivel_riesgo = calcular_riesgo(probabilidad, impacto)

    # Inserta el riesgo en la base de datos
    cursor.execute("""
    INSERT INTO riesgos (activo_id, amenaza, probabilidad, impacto, nivel_riesgo)
    VALUES (?, ?, ?, ?, ?)
    """, (activo_id, amenaza, probabilidad, impacto, nivel_riesgo))
    conn.commit()

    messagebox.showinfo("Éxito", "Riesgo agregado correctamente.")
    listar_riesgos()  # Actualiza la lista de riesgos
    actualizar_combo_riesgo()  # Actualiza el combo de riesgos
    limpiar_campos_riesgo()  # Limpia los campos de entrada de riesgos

# Función para listar todos los riesgos en la tabla
def listar_riesgos():
    for row in tree_riesgos.get_children():
        tree_riesgos.delete(row)  # Elimina las filas existentes

    cursor.execute("""
    SELECT r.id, a.nombre, r.amenaza, r.probabilidad, r.impacto, r.nivel_riesgo, r.control, r.riesgo_residual
    FROM riesgos r
    JOIN activos a ON r.activo_id = a.id
    """)
    riesgos = cursor.fetchall()
    for riesgo in riesgos:
        tree_riesgos.insert("", "end", values=riesgo)

# Función para limpiar los campos de entrada de riesgos
def limpiar_campos_riesgo():
    combo_activo_riesgo.set("")
    combo_amenaza.set("")
    combo_probabilidad.set("")
    combo_impacto.set("")

# Función para actualizar el combo de riesgos
def actualizar_combo_riesgo():
    cursor.execute("""
    SELECT r.id, a.nombre, r.amenaza
    FROM riesgos r
    JOIN activos a ON r.activo_id = a.id
    """)
    riesgos = cursor.fetchall()
    combo_riesgo['values'] = [f"{riesgo[0]}-{riesgo[1]} ({riesgo[2]})" for riesgo in riesgos]

# ========================
# Funciones para Gestión de Controles
# ========================

# Función para calcular el riesgo residual después de aplicar un control
def calcular_riesgo_residual(riesgo_id, efectividad):
    cursor.execute("SELECT probabilidad, impacto FROM riesgos WHERE id = ?", (riesgo_id,))
    result = cursor.fetchone()
    if not result:
        return None
    probabilidad, impacto = result
    valores = {"Muy Baja": 1, "Baja": 2, "Media": 3, "Alta": 4, "Muy Alta": 5}
    factores_reduccion = {"Muy Baja": 0.1, "Baja": 0.2, "Media": 0.4, "Alta": 0.6, "Muy Alta": 0.8}

    probabilidad_actual = valores.get(probabilidad, 1)
    impacto_actual = valores.get(impacto, 1)

    # Calcular el riesgo inherente
    riesgo_inherente = probabilidad_actual * impacto_actual

    # Calcular la reducción basada en la efectividad del control
    #reducción == riesgo_tratado * controles
    reduccion = riesgo_inherente * factores_reduccion.get(efectividad, 0)

    # Calcular el riesgo residual
    # Riesgo residual = Riesgo inherente - Reducción
    riesgo_residual = max(riesgo_inherente - reduccion, 1)

    return riesgo_residual

# Función para agregar un control a un riesgo
def agregar_control():
    riesgo_seleccionado = combo_riesgo.get().strip()  # Obtiene el riesgo seleccionado
    control = combo_control.get().strip()  # Obtiene el control asociado
    efectividad = combo_efectividad.get().strip()  # Obtiene la efectividad del control

    # Validación de campos
    if not riesgo_seleccionado or not control or not efectividad:
        messagebox.showerror("Error", "Todos los campos son obligatorios.")
        return

    try:
        # Extrae el ID del riesgo seleccionado
        riesgo_id = int(riesgo_seleccionado.split("-")[0])
    except ValueError:
        messagebox.showerror("Error", "Formato de Riesgo inválido.")
        return

    # Calcula el riesgo residual
    riesgo_residual = calcular_riesgo_residual(riesgo_id, efectividad)
    if riesgo_residual is None:
        messagebox.showerror("Error", "No se pudo calcular el riesgo residual.")
        return

    # Actualiza el riesgo con el control y efectividad
    cursor.execute("""
    UPDATE riesgos
    SET control = ?, efectividad = ?, riesgo_residual = ?
    WHERE id = ?
    """, (control, efectividad, riesgo_residual, riesgo_id))
    conn.commit()

    messagebox.showinfo("Éxito", "Control agregado correctamente.")
    listar_riesgos()  # Actualiza la lista de riesgos
    limpiar_campos_control()  # Limpia los campos de entrada de controles

# Función para limpiar los campos de entrada de controles
def limpiar_campos_control():
    combo_riesgo.set("")
    combo_control.set("")
    combo_efectividad.set("")

# ========================
# Función para Generar el Reporte en PDF
# ========================

# Función para generar el reporte de riesgos y controles en un archivo PDF
def generar_reporte():
    pdf = FPDF()
    pdf.add_page()

    # Título del reporte
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, txt="Reporte de Riesgos y Controles", ln=True, align="C")
    pdf.ln(10)

    # Activos
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Lista de Activos:", ln=True)
    pdf.set_font("Arial", "", 12)
    cursor.execute("SELECT * FROM activos")
    activos = cursor.fetchall()
    for activo in activos:
        pdf.cell(200, 10, txt=f"ID: {activo[0]} - Nombre: {activo[1]} - Tipo: {activo[2]} - Valor: {activo[3]} - Impacto en la empresa: {activo[4]}", ln=True)

    pdf.ln(10)

    # Riesgos
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Lista de Riesgos:", ln=True)
    pdf.set_font("Arial", "", 12)
    cursor.execute("""
    SELECT r.id, a.nombre, r.amenaza, r.probabilidad, r.impacto, r.nivel_riesgo, r.control, r.riesgo_residual
    FROM riesgos r
    JOIN activos a ON r.activo_id = a.id
    """)
    riesgos = cursor.fetchall()
    for riesgo in riesgos:
        pdf.cell(200, 10, txt=f"ID: {riesgo[0]} - Activo: {riesgo[1]} - Amenaza: {riesgo[2]} - Probabilidad: {riesgo[3]} - Impacto: {riesgo[4]} - Nivel de Riesgo: {riesgo[5]}", ln=True)
        pdf.cell(200, 10, txt=f"Control: {riesgo[6] if riesgo[6] else 'N/A'} - Riesgo Residual: {riesgo[7] if riesgo[7] else 'N/A'}", ln=True)

    # Guardar el archivo PDF
    try:
        pdf.output("reporte_riesgos.pdf")
        messagebox.showinfo("Éxito", "El reporte se ha generado correctamente como 'reporte_riesgos.pdf'.")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo generar el reporte PDF.\n{e}")


# ========================
# Funciones de Integración OSINT
# ========================

def consultar_shodan(ip):
    api = shodan.Shodan(API_KEY_SHODAN)
    try:
        # Obtén los resultados del host específico
        results = api.host(ip)
        
        # Para listar activos, obtenemos todos los datos disponibles
        activos = []
        for result in results.get('data', []):
            activos.append({
                'ip': results.get('ip_str', 'N/A'),
                'org': results.get('org', 'N/A'),
                'hostnames': results.get('hostnames', []),
                'ports': result.get('port', 'N/A'),
                'service': result.get('product', 'N/A'),
                'timestamp': result.get('timestamp', 'N/A'),
            })
        
        return activos  # Devuelve los activos encontrados
    except shodan.APIError as e:
        return {"error": str(e)}

def consultar_intelx_email(email):
    url = f"https://intelx.io/Intelligence/Email/{email}"  # Cambié el endpoint a uno adecuado para correos
    headers = {"apiKey": API_KEY_INTELX}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Error {response.status_code}: {response.text}"}
    except requests.RequestException as e:
        return {"error": str(e)}

def consultar_nvd(keyword):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={keyword}"
    headers = {"apiKey": API_KEY_NVD}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code}: {response.text}"}

def consultar_weather(ciudad):
    url = f"http://api.openweathermap.org/data/2.5/weather?q={ciudad}&appid={API_KEY_WEATHER}&units=metric"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code}: {response.text}"}



# ========================
# Ventana Principal
# ========================

# Ventana principal
ventana = tk.Tk()
ventana.title("Gestión de Riesgos MAGERIT")
ventana.geometry("1920x1080")  # Aumentado tamaño para mejor visualización
notebook = ttk.Notebook(ventana)
notebook.pack(fill="both", expand="yes")


# ========================
# Pestaña Shodan
# ========================
frame_shodan = ttk.Frame(notebook)
notebook.add(frame_shodan, text="Shodan")

label_ip = ttk.Label(frame_shodan, text="IP a consultar:")
label_ip.grid(row=0, column=0, padx=10, pady=5, sticky="E")
entry_ip = ttk.Entry(frame_shodan)
entry_ip.grid(row=0, column=1, padx=10, pady=5)

# Definir resultado_text_shodan para Shodan
resultado_text_shodan = tk.Text(frame_shodan, height=20)
resultado_text_shodan.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

def mostrar_resultados_shodan():
    ip = entry_ip.get().strip()
    resultados = consultar_shodan(ip)
    if "error" in resultados:
        messagebox.showerror("Error", resultados["error"])
    else:
        # Limpiar el campo de resultados
        resultado_text_shodan.delete(1.0, tk.END)

        # Si hay resultados, mostrar solo el primero
        if resultados:
            resultado = resultados[0]  # Mostrar solo el primer resultado
            resultado_text_shodan.insert(tk.END, f"IP: {resultado.get('ip', 'N/A')}\n")
            resultado_text_shodan.insert(tk.END, f"Organización: {resultado.get('org', 'N/A')}\n")
            resultado_text_shodan.insert(tk.END, f"Hostnames: {', '.join(resultado.get('hostnames', []))}\n")
            resultado_text_shodan.insert(tk.END, f"Puertos: {resultado.get('ports', 'N/A')}\n")
            resultado_text_shodan.insert(tk.END, f"Servicio: {resultado.get('service', 'N/A')}\n")
            resultado_text_shodan.insert(tk.END, f"Timestamp: {resultado.get('timestamp', 'N/A')}\n")
            resultado_text_shodan.insert(tk.END, "-"*40 + "\n")  # Separador entre activos
        else:
            resultado_text_shodan.insert(tk.END, "No se encontraron resultados para la IP.\n")

boton_consultar_shodan = ttk.Button(frame_shodan, text="Consultar", command=mostrar_resultados_shodan)
boton_consultar_shodan.grid(row=0, column=2, padx=10, pady=5)


# ========================
# Pestaña Intel X
# ========================
frame_intelx = ttk.Frame(notebook)
notebook.add(frame_intelx, text="IntelX")

label_email = ttk.Label(frame_intelx, text="Correo electrónico a consultar:")
label_email.grid(row=0, column=0, padx=10, pady=5, sticky="E")
entry_email = ttk.Entry(frame_intelx)
entry_email.grid(row=0, column=1, padx=10, pady=5)

# Definir resultado_text para IntelX
resultado_text_intelx = tk.Text(frame_intelx, height=20)
resultado_text_intelx.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

def mostrar_resultados_intelx():
    email = entry_email.get().strip()
    resultados = consultar_intelx_email(email)
    if "error" in resultados:
        messagebox.showerror("Error", resultados["error"])
    else:
        resultado_text_intelx.delete(1.0, tk.END)
        resultado_text_intelx.insert(tk.END, f"Correo: {resultados.get('email', 'N/A')}\n")
        resultado_text_intelx.insert(tk.END, f"Estado: {resultados.get('status', 'N/A')}\n")
        resultado_text_intelx.insert(tk.END, f"Dominios relacionados: {', '.join(resultados.get('domains', []))}\n")

boton_consultar_intelx = ttk.Button(frame_intelx, text="Consultar", command=mostrar_resultados_intelx)
boton_consultar_intelx.grid(row=0, column=2, padx=10, pady=5)
# ========================
# Pestaña NVD API
# ========================
frame_nvd = ttk.Frame(notebook)
notebook.add(frame_nvd, text="NVD API")

label_keyword = ttk.Label(frame_nvd, text="Palabra clave:")
label_keyword.grid(row=0, column=0, padx=10, pady=5, sticky="E")
entry_keyword = ttk.Entry(frame_nvd)
entry_keyword.grid(row=0, column=1, padx=10, pady=5)

def mostrar_resultados_nvd():
    keyword = entry_keyword.get().strip()
    resultados = consultar_nvd(keyword)
    if "error" in resultados:
        messagebox.showerror("Error", resultados["error"])
    else:
        resultado_nvd_text.delete(1.0, tk.END)
        if "result" in resultados:
            for item in resultados["result"]["CVE_Items"]:
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                descripcion = item["cve"]["description"]["description_data"][0]["value"]
                resultado_nvd_text.insert(tk.END, f"CVE: {cve_id} - Descripción: {descripcion}\n")
        else:
            resultado_nvd_text.insert(tk.END, "No se encontraron resultados para la búsqueda.\n")

boton_consultar_nvd = ttk.Button(frame_nvd, text="Consultar", command=mostrar_resultados_nvd)
boton_consultar_nvd.grid(row=0, column=2, padx=10, pady=5)

resultado_nvd_text = tk.Text(frame_nvd, height=20)
resultado_nvd_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# ========================
# Pestaña OpenWeatherMap
# ========================
frame_weather = ttk.Frame(notebook)
notebook.add(frame_weather, text="OpenWeatherMap")

label_ciudad = ttk.Label(frame_weather, text="Ciudad:")
label_ciudad.grid(row=0, column=0, padx=10, pady=5, sticky="E")
entry_ciudad = ttk.Entry(frame_weather)
entry_ciudad.grid(row=0, column=1, padx=10, pady=5)

def mostrar_resultados_weather():
    ciudad = entry_ciudad.get().strip()
    resultados = consultar_weather(ciudad)
    if "error" in resultados:
        messagebox.showerror("Error", resultados["error"])
    else:
        resultado_weather_text.delete(1.0, tk.END)
        resultado_weather_text.insert(tk.END, f"Ciudad: {resultados['name']}\n")
        resultado_weather_text.insert(tk.END, f"Temperatura: {resultados['main']['temp']}°C\n")
        resultado_weather_text.insert(tk.END, f"Condición: {resultados['weather'][0]['description']}\n")

boton_consultar_weather = ttk.Button(frame_weather, text="Consultar", command=mostrar_resultados_weather)
boton_consultar_weather.grid(row=0, column=2, padx=10, pady=5)

resultado_weather_text = tk.Text(frame_weather, height=20)
resultado_weather_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)


# ========================

# Pestañas para gestionar activos, riesgos y controles
notebook = ttk.Notebook(ventana)
notebook.pack(fill="both", expand="yes")

# Pestaña de activos
frame_activos = ttk.Frame(notebook)
notebook.add(frame_activos, text="Activos")

# Campos de entrada y botones para activos
label_nombre_activo = ttk.Label(frame_activos, text="Nombre del Activo:")
label_nombre_activo.grid(row=0, column=0, padx=10, pady=5, sticky="E")
entry_nombre_activo = ttk.Entry(frame_activos)
entry_nombre_activo.grid(row=0, column=1, padx=10, pady=5)

label_tipo_activo = ttk.Label(frame_activos, text="Tipo de Activo:")
label_tipo_activo.grid(row=1, column=0, padx=10, pady=5, sticky="E")
combo_tipo_activo = ttk.Combobox(frame_activos, values=["Tecnológico", "Servidor", "Físico", "Información"], state="readonly")
combo_tipo_activo.grid(row=1, column=1, padx=10, pady=5)

label_valor_activo = ttk.Label(frame_activos, text="Valor del Activo:")
label_valor_activo.grid(row=2, column=0, padx=10, pady=5, sticky="E")
entry_valor_activo = ttk.Entry(frame_activos)
entry_valor_activo.grid(row=2, column=1, padx=10, pady=5)

label_impacto_empresa_activo = ttk.Label(frame_activos, text="Impacto en la empresa:")
label_impacto_empresa_activo.grid(row=3, column=0, padx=10, pady=5, sticky="E")
combo_impacto_empresa_activo = ttk.Combobox(frame_activos, values=["Muy Alta", "Alta", "Media", "Baja", "Muy Baja"], state="readonly")
combo_impacto_empresa_activo.grid(row=3, column=1, padx=10, pady=5)

boton_agregar_activo = ttk.Button(frame_activos, text="Agregar Activo", command=agregar_activo)
boton_agregar_activo.grid(row=4, column=1, padx=10, pady=10, sticky="E")

# Configuración del frame y el Treeview
tree_activos = ttk.Treeview(frame_activos,
                            columns=("ID", "Nombre", "Tipo", "Valor", "Impacto en la empresa"),
                            show="headings")
tree_activos.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Configurar encabezados de columnas
tree_activos.heading("ID", text="ID")
tree_activos.heading("Nombre", text="Nombre")
tree_activos.heading("Tipo", text="Tipo")
tree_activos.heading("Valor", text="Valor")
tree_activos.heading("Impacto en la empresa", text="Impacto en la empresa")

# Configurar el escalado de las columnas
frame_activos.grid_rowconfigure(5, weight=1)
frame_activos.grid_columnconfigure(1, weight=1)

# Scrollbars
scroll_y = ttk.Scrollbar(frame_activos, orient="vertical", command=tree_activos.yview)
scroll_x = ttk.Scrollbar(frame_activos, orient="horizontal", command=tree_activos.xview)

# Configurar los scrollbars con la tabla
tree_activos.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

# Ubicar los scrollbars
scroll_y.grid(row=5, column=3, sticky="ns")  # Barra de scroll vertical
scroll_x.grid(row=6, column=0, columnspan=3, sticky="ew")  # Barra de scroll horizontal

# Pestaña de riesgos
frame_riesgos = ttk.Frame(notebook)
notebook.add(frame_riesgos, text="Riesgos")

# Campos de entrada y botones para riesgos
label_activo_riesgo = ttk.Label(frame_riesgos, text="Activo Afectado:")
label_activo_riesgo.grid(row=0, column=0, padx=10, pady=5, sticky="E")
combo_activo_riesgo = ttk.Combobox(frame_riesgos, state="readonly")
combo_activo_riesgo.grid(row=0, column=1, padx=10, pady=5)

label_amenaza = ttk.Label(frame_riesgos, text="Amenaza:")
label_amenaza.grid(row=1, column=0, padx=10, pady=5, sticky="E")
combo_amenaza = ttk.Combobox(frame_riesgos, values=[
    "Acceso no autorizado",
    "Malware",
    "Phishing",
    "Desastres naturales",
    "Fallas de hardware"
], state="readonly")
combo_amenaza.grid(row=1, column=1, padx=10, pady=5)

label_probabilidad = ttk.Label(frame_riesgos, text="Probabilidad:")
label_probabilidad.grid(row=2, column=0, padx=10, pady=5, sticky="E")
combo_probabilidad = ttk.Combobox(frame_riesgos, values=["Muy Baja", "Baja", "Media", "Alta", "Muy Alta"], state="readonly")
combo_probabilidad.grid(row=2, column=1, padx=10, pady=5)

label_impacto = ttk.Label(frame_riesgos, text="Impacto:")
label_impacto.grid(row=3, column=0, padx=10, pady=5, sticky="E")
combo_impacto = ttk.Combobox(frame_riesgos, values=["Muy Bajo", "Bajo", "Moderado", "Alto", "Muy Alto"], state="readonly")
combo_impacto.grid(row=3, column=1, padx=10, pady=5)

boton_agregar_riesgo = ttk.Button(frame_riesgos, text="Agregar Riesgo", command=agregar_riesgo)
boton_agregar_riesgo.grid(row=4, column=1, padx=10, pady=10, sticky="E")

# Configuración del frame y el Treeview
tree_riesgos = ttk.Treeview(frame_riesgos,
                            columns=("ID", "Activo", "Amenaza", "Probabilidad",
                                     "Impacto", "Nivel Riesgo", "Control", "Riesgo Residual"),
                            show="headings")
tree_riesgos.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Configurar encabezados de columnas
tree_riesgos.heading("ID", text="ID")
tree_riesgos.heading("Activo", text="Activo")
tree_riesgos.heading("Amenaza", text="Amenaza")
tree_riesgos.heading("Probabilidad", text="Probabilidad")
tree_riesgos.heading("Impacto", text="Impacto")
tree_riesgos.heading("Nivel Riesgo", text="Nivel Riesgo")
tree_riesgos.heading("Control", text="Control")
tree_riesgos.heading("Riesgo Residual", text="Riesgo Residual")

# Configurar el escalado de las columnas
frame_riesgos.grid_rowconfigure(5, weight=1)
frame_riesgos.grid_columnconfigure(1, weight=1)

# Scrollbars
scroll_y = ttk.Scrollbar(frame_riesgos, orient="vertical", command=tree_riesgos.yview)
scroll_x = ttk.Scrollbar(frame_riesgos, orient="horizontal", command=tree_riesgos.xview)

# Configurar los scrollbars con la tabla
tree_riesgos.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

# Ubicar los scrollbars
scroll_y.grid(row=5, column=3, sticky="ns")  # Barra de scroll vertical
scroll_x.grid(row=6, column=0, columnspan=3, sticky="ew")  # Barra de scroll horizontal

# Pestaña de controles
frame_controles = ttk.Frame(notebook)
notebook.add(frame_controles, text="Controles")

# Campos de entrada y botones para controles
label_riesgo = ttk.Label(frame_controles, text="Riesgo:")
label_riesgo.grid(row=0, column=0, padx=10, pady=5, sticky="E")
combo_riesgo = ttk.Combobox(frame_controles, state="readonly")
combo_riesgo.grid(row=0, column=1, padx=10, pady=5)

label_control = ttk.Label(frame_controles, text="Control:")
label_control.grid(row=1, column=0, padx=10, pady=5, sticky="E")
combo_control = ttk.Combobox(frame_controles, values=[
    "Firewall",
    "Antivirus",
    "Autenticación de dos factores",
    "Copias de seguridad regulares",
    "Planes de continuidad de negocio"
], state="readonly")
combo_control.grid(row=1, column=1, padx=10, pady=5)

label_efectividad = ttk.Label(frame_controles, text="Efectividad:")
label_efectividad.grid(row=2, column=0, padx=10, pady=5, sticky="E")
combo_efectividad = ttk.Combobox(frame_controles, values=["Muy Baja", "Baja", "Media", "Alta", "Muy Alta"], state="readonly")
combo_efectividad.grid(row=2, column=1, padx=10, pady=5)

boton_agregar_control = ttk.Button(frame_controles, text="Agregar Control", command=agregar_control)
boton_agregar_control.grid(row=3, column=1, padx=10, pady=10, sticky="E")

# Botón para generar reporte
boton_reporte = ttk.Button(ventana, text="Generar Reporte", command=generar_reporte)
boton_reporte.pack(pady=20)

# Función para cargar datos al iniciar la aplicación
def cargar_datos_iniciales():
    listar_activos()
    listar_riesgos()
    actualizar_combo_activo_riesgo()
    actualizar_combo_riesgo()

cargar_datos_iniciales()

# Ejecutar la ventana
ventana.mainloop()

# Cerrar la conexión a la base de datos al cerrar la aplicación
conn.close()