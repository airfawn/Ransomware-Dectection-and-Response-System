#!/usr/bin/env python3
import os
import sys

BASE_DIR = os.path.join(os.path.dirname(__file__), 'tester')


def ensure_tester_dir():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, exist_ok=True)


def create_file():
    filename = input('Enter filename to create: ').strip()
    if not filename:
        print('Filename cannot be empty.')
        return

    filepath = os.path.join(BASE_DIR, filename)
    if os.path.exists(filepath):
        print(f'File already exists: {filepath}')
        return

    content = input('Enter text content for the new file: ')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f'Created file: {filepath}')


def delete_file():
    filename = input('Enter filename to delete: ').strip()
    if not filename:
        print('Filename cannot be empty.')
        return

    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.exists(filepath):
        print(f'File does not exist: {filepath}')
        return

    os.remove(filepath)
    print(f'Deleted file: {filepath}')


def modify_file():
    filename = input('Enter filename to modify: ').strip()
    if not filename:
        print('Filename cannot be empty.')
        return

    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.exists(filepath):
        print(f'File does not exist: {filepath}')
        return

    current_text = ''
    with open(filepath, 'r', encoding='utf-8') as f:
        current_text = f.read()

    print('Current file content:')
    print('---')
    print(current_text)
    print('---')

    print('Enter new content for the file. Leave blank to keep existing content.')
    new_content = input('New content: ')
    if new_content == '':
        print('No changes made.')
        return

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f'Modified file: {filepath}')


def choose_action():
    print('Choose an action for the tester folder:')
    print('  1) create')
    print('  2) delete')
    print('  3) modify')
    print('  4) exit')

    choice = input('Enter choice: ').strip().lower()
    return choice


def main():
    ensure_tester_dir()

    while True:
        choice = choose_action()

        if choice in ('1', 'create'):
            create_file()
        elif choice in ('2', 'delete'):
            delete_file()
        elif choice in ('3', 'modify'):
            modify_file()
        elif choice in ('4', 'exit', 'quit'):
            print('Exiting.')
            break
        else:
            print('Unknown choice. Please type create, delete, modify, or exit.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nInterrupted. Exiting.')
        sys.exit(0)
