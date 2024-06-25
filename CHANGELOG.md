# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2024-06-21

### Added
- Initial changelog documentation.
- Unified functionalities of various Satochip tools into a single application.
- Initial version of satochip-utils

### Changed
- Displaying the device certificat, even if, the card is not genuine in check_authenticity
- Cancelling th insert_card popup when a card is inserted
- Changing radio button disposition for passphrase in setup seed
- Deleting the indicative content into an entry or a textbox when user Focuses in
- 

### Fixed
- Alignement into check_authenticity frame
- Pin that was always asked into about
- Syntax calling of self.version to self.app_version
- Syntax correction in popup and change pin frame
- Add control for blank, none and Type your passphrase here
- Correction of version parsing in about
