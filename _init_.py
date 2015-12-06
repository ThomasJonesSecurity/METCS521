# MODULE PURPOSE _init_.py is called to run the main()
# the GUI and attack work is done by GUI_BrowseAndAttack

import GUI_BrowseAndAttack


def main():
    GUI_BrowseAndAttack.draw_gui()

if __name__ == "__main__":  # stops main execution if imported as module
    main()
