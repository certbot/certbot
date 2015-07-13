"""Tests Let's Encrypt plugins against different server configurations."""
import parser
import util


def main():
    """Main test script execution."""
    args = parser.parse_args()

    print util.setup_tmp_dir(args.tar)

if __name__ == "__main__":
    main() 
