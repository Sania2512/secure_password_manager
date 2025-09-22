from src.db.database import initialize_database
from src.gui.gui_main import launch_gui

if __name__ == "__main__":
    initialize_database()
    print("Base de données initialisée.")
    launch_gui()