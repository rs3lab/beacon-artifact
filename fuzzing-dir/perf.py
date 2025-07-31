import csv
from collections import defaultdict
import argparse
import sys

def gen_time_distribution_data(file_path, is_regen):
    sums = []  # To store the sum of the 7th, 8th, and 9th columns for each row
    range_counts = defaultdict(int)  # To count sums in specified ranges
    percent1 = []
    percent2 = []
    percent3 = []
    total_time = 0
    opt_total_time = 0

    ranges = [
        (0, 5),
        (5, 10),
        (10, 20),
        (20, 40),
        (40, 500),
    ]



    # Read the CSV file
    with open(file_path, 'r') as file:
        reader = csv.reader(file, delimiter='\t')
        
        for row in reader:
            try:
                row_sum = float(row[6]) + float(row[7]) + float(row[8])
                sums.append(row_sum)
                percent1.append(float(row[6])/row_sum)
                percent2.append(float(row[7])/row_sum)
                percent3.append(float(row[8])/row_sum)

                total_time += float(row[7])
                opt_total_time += float(row[12])

                # Count the sum in the specified ranges
                for start, end in ranges:
                    if start*1000000 <= row_sum < end*1000000:
                        range_counts[(start, end)] += 1
                        break
            except (ValueError, IndexError):
                print(f"Skipping invalid row: {row}")
                continue

    if sums:
        min_value = min(sums)
        max_value = max(sums)
        avg_value = sum(sums) / len(sums)

        output = ""
        for (start, end), count in sorted(range_counts.items()):
            percent = count*100 / len(sums);
            output += f"{start}-{end},{count},{percent}\n"

        fn = ""
        if is_regen:
            fn = "./data/total-time-2.dat"
        else:
            fn = "./data/total-time-1.dat"
        
        with open(fn, "w") as f:
            f.write(output)

    else:
        print("No valid data to process.")

def gen_sample_impv_data(file_path, is_regen):

    total_time = 0
    opt_total_time = 0

    # Read the CSV file
    with open(file_path, 'r') as file:
        reader = csv.reader(file, delimiter='\t')

        for row in reader:
            try:
                opt_total_time += float(row[7])
                if float(row[12]) == 0:
                    total_time += float(row[7])
                else:
                    total_time += float(row[12])
            except (ValueError, IndexError):
                print(f"Skipping invalid row: {row}")
                continue
    if is_regen:
        fn = "./data/sample-impv-2.dat"
    else:
        fn = "./data/sample-impv-1.dat"

    with open(fn, "w") as f:
        f.write(f"{opt_total_time},{total_time}\n")


# Example usage
if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Parse files for process time distribution and improvements."
    )

    parser.add_argument(
        '-regen',
        action='store_true',
        help='Generate the figure for the new data'
    )

    parser.add_argument(
        '-time',
        type=str,
        required=False,
        help='Path to the file containing process time distribution data.'
    )

    parser.add_argument(
        '-impv',
        type=str,
        required=False,
        help='Path to the file containing process improvements data.'
    )

    args = parser.parse_args()

    if args.time:
        gen_time_distribution_data(args.time, args.regen)

    if args.impv:
        gen_sample_impv_data(args.impv, args.regen)
