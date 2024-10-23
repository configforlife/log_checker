import re
import json
import tkinter as tk
from tkinter import filedialog, Image
import tkinter.ttk as ttk


# Funkcja wczytywania plików logów
def wczytaj_logi(plik_logu):
    with open(plik_logu, 'r') as plik:
        for linia in plik:
            yield linia.strip()

# Funkcja regex do znajdowania IP
def znajdz_adresy_ip(linia):
    wzorzec_ip = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    adresy = re.findall(wzorzec_ip, linia)
    return adresy if adresy else []

# Funkcja do znajdowania błędów HTTP
def znajdz_bledy_http(linia):
    wzorzec_bledow = r'\s(400|401|403|404|204|508)\s'
    return re.findall(wzorzec_bledow, linia)

# Funkcja do wykrywania podejrzanych sytuacji
def podejrzana_akcja(linia):
    wzor_podejrzenia = r'\b(UNION SELECT|SELECT \*|1=1|; DROP TABLE|--|<script>|javascript:|\.{2}/|php://|eval\()\b'
    return re.findall(wzor_podejrzenia, linia)

# Funkcja do opisu podejrzanych działań
def opis_podejrzanej_akcji(akcja):
    opisy = {
        "UNION SELECT": "Potencjalne atak SQL Injection",
        "SELECT *": "Potencjalne atak SQL Injection",
        "1=1": "Potencjalne atak SQL Injection",
        "; DROP TABLE": "Potencjalne atak SQL Injection",
        "--": "Potencjalne atak SQL Injection",
        "<script>": "Potencjalne XSS",
        "javascript:": "Potencjalne XSS",
        "../": "Potencjalne atak Directory Traversal",
        "php://": "Potencjalne atak Local File Inclusion",
        "eval(": "Potencjalne atak Remote Code Execution"
    }
    return opisy.get(akcja, "Nieznana podejrzana akcja")

# Klasa do analizy logów
class AnalizatorLogow:
    def __init__(self, plik_logu):
        self.plik_logu = plik_logu
        self.wyniki = []

    def analizuj(self):
        for linia in wczytaj_logi(self.plik_logu):
            ip_adresy = znajdz_adresy_ip(linia)
            bledy = znajdz_bledy_http(linia)
            podejrzane = podejrzana_akcja(linia)

            for ip in ip_adresy:
                istnieje = next((wynik for wynik in self.wyniki if wynik['ip'] == ip), None)
                if istnieje:
                    for blad in bledy:
                        istnieje['bledy'][blad] = istnieje['bledy'].get(blad, 0) + 1  # Zliczanie wystąpień błędu
                    for akcja in podejrzane:
                        istnieje['podejrzane'][akcja] = istnieje['podejrzane'].get(akcja, 0) + 1  # Zliczanie wystąpień podejrzanego działania
                else:
                    nowe_bledy = {blad: 1 for blad in bledy}  # Zainicjuj nowy słownik błędów
                    nowe_podejrzane = {akcja: 1 for akcja in podejrzane}  # Zainicjuj nowy słownik podejrzanych działań
                    self.wyniki.append({
                        "ip": ip,
                        "bledy": nowe_bledy,
                        "podejrzane": nowe_podejrzane
                    })
    # Funkcja do zapisu wyników do .json
    def zapisz_do_json(self, plik_wyjscia):
        with open(plik_wyjscia, 'w') as f:
            json.dump(self.wyniki, f, indent=4)

    def wczytaj_z_json(self, plik_json):
        with open(plik_json, 'r') as f:
            self.wyniki = json.load(f)

# Funkcja do wyświetlania wyników w GUI
def pokaz_wyniki():
    plik_logu = filedialog.askopenfilename(title="Wybierz plik logu", filetypes=(("Pliki tekstowe", "*.txt"), ("Wszystkie pliki", "*.*")))
    if plik_logu:
        analizator = AnalizatorLogow(plik_logu)
        analizator.analizuj()
        analizator.zapisz_do_json('wyniki.json')

        # Wyczyść Treeview
        for row in tree.get_children():
            tree.delete(row)

        # Dodaj wyniki do Treeview
        for wynik in analizator.wyniki:
            if wynik['bledy'] or wynik['podejrzane']:  # Sprawdź, czy są błędy lub podejrzane działania
                bledy_str = ', '.join(f"{blad} wystąpienia: {liczba}" for blad, liczba in wynik['bledy'].items()) if wynik['bledy'] else 'Brak błędów'
                podejrzane_str = ', '.join(f"{akcja} wystąpienia: {liczba}" for akcja, liczba in wynik['podejrzane'].items()) if wynik['podejrzane'] else 'Brak podejrzanych działań'

                # Dodanie opisu do podejrzanych działań
                opisy_podejrzane = [f"{opis_podejrzanej_akcji(akcja)} (wystąpienia: {liczba})" for akcja, liczba in wynik['podejrzane'].items()]
                opisy_str = ', '.join(opisy_podejrzane) if opisy_podejrzane else 'Brak opisów'

                tree.insert("", tk.END, values=(wynik['ip'], bledy_str, podejrzane_str, opisy_str))

# Tworzenie GUI
root = tk.Tk()
root.title("Analizator logów serwera")
root.geometry("900x500")
root.configure(bg="white")

# Dodanie ikony
photo = tk.PhotoImage(file='uwikona.png')
root.iconphoto(False, photo)

# Ustawienie tła
background_image = tk.PhotoImage(file='bguw.png')
background_image_i = tk.Label(root, image=background_image, bg='white', )
background_image_i.grid(row=4)

# Dodanie Treeview do GUI
tree = ttk.Treeview(root, columns=('IP', 'Błędy', 'Podejrzane', 'Opisy'), show='headings')
tree.heading('IP', text='IP')
tree.heading('Błędy', text='Błędy')
tree.heading('Podejrzane', text='Podejrzane linijki logu')
tree.heading('Opisy', text='Opisy podejrzanych działań')
tree.grid(column=0, row=0, sticky='nsew')
tree.column('Opisy', width=300)

# Przyciski i etykiety
label = tk.Label(root, text='Wczytaj plik logu klikając w przycisk.', font=('Helvetica', 16, 'bold'), bg='lightblue')
label.grid(column=0, row=1, pady=10)

przycisk = tk.Button(root, text="Wybierz plik logu i analizuj", command=pokaz_wyniki, bg='blue', fg='white', font=('Helvetica', 14))
przycisk.grid(column=0, row=2, pady=10)

root.mainloop()
