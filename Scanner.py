import nmap


def main():
    scanner = nmap.PortScanner()

    print("Welcome, this is a simple nmap automation tool")
    print("<----------------------------------------------------->")

    # Get target IP address from user
    target = input("Please enter the target IP address or hostname: ")

    # Get scan type from user
    print("Select the type of scan you want to perform:")
    print("1. TCP SYN Scan (default)")
    print("2. TCP Connect Scan")
    print("3. Service Version Detection")
    print("4. OS Detection")
    print("5. Vulnerability Scan")
    scan_type = input("Enter the number of the scan type (1/2/3/4/5): ")

    # Perform the selected scan
    try:
        if scan_type == '1':
            print("Performing TCP SYN Scan...")
            scanner.scan(target, arguments='-sS -p-')
        elif scan_type == '2':
            print("Performing TCP Connect Scan...")
            scanner.scan(target, arguments='-sT -p-')
        elif scan_type == '3':
            print("Performing Service Version Detection...")
            scanner.scan(target, arguments='-sV -p-')
        elif scan_type == '4':
            print("Performing OS Detection...")
            scanner.scan(target, arguments='-O -p-')
        elif scan_type == '5':
            print("Performing Vulnerability Scan...")
            scanner.scan(target, arguments=f"--script vuln -p-")
        else:
            print("Invalid selection. Please choose 1, 2, 3, 4, or 5.")
            return

        # Display the scan results
        print("<----------------------------------------------------->")
        print(f"Scan results for {target}:")
        if target in scanner.all_hosts():
            print(scanner[target])
        else:
            print("No scan results found.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()