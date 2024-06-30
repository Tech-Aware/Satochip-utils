import logging
from os import urandom, path
import sys
from configparser import ConfigParser
from mnemonic import Mnemonic
from pysatochip.CardConnector import (CardConnector, UninitializedSeedError)

seed = None
if (len(sys.argv) >= 2) and (sys.argv[1] in ['-v', '--verbose']):
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - [%(filename)s:%(lineno)d] - %(levelname)s - %(name)s - %(funcName)s() - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
else:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - [%(filename)s:%(lineno)d] - %(levelname)s - %(name)s - %(funcName)s() - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Controller:
    def __init__(self, cc, view, loglevel=logging.INFO):
        logger.setLevel(loglevel)
        self.view = view
        self.view.controller = self
        self.pin_left = None

        try:
            self.cc = CardConnector(self, loglevel=loglevel)
            logger.info("CardConnector initialized successfully.")
        except Exception as e:
            logger.error("Failed to initialize CardConnector.", exc_info=True)
            raise

        self.show_popup_open = False

        # card infos
        self.card_present = None
        self.card_version = None
        self.needs2FA = None
        self.is_seeded = None
        self.setup_done = None
        self.card_type = None
        self.card_label = None
        self.two_FA = None

        try:
            if self.cc.card_type == "Satodime":
                self.truststore = {}
                self.authentikey = None
                self.authentikey_comp_hex = None
                self.window = None
                self.max_num_keys = 0
                self.satodime_keys_status = []
                self.satodime_keys_info = []
                self.card_event = True  # force update at start
                self.card_event_slots = []

                # get apikeys from file
                self.apikeys = {}
                try:
                    if getattr(sys, 'frozen', False):
                        if sys.platform == "darwin":  # MacOS
                            self.pkg_dir = sys._MEIPASS + "/SatodimeTool"  # for pyinstaller
                        else:
                            self.pkg_dir = sys._MEIPASS  # for pyinstaller
                    else:
                        self.pkg_dir = path.split(path.realpath(__file__))[0]

                    apikeys_path = path.join(self.pkg_dir, "api_keys.ini")
                    config = ConfigParser()
                    if path.isfile(apikeys_path):
                        config.read(apikeys_path)
                        if config.has_section('APIKEYS'):
                            self.apikeys = config['APIKEYS']
                            logger.debug(f'APIKEYS loaded: {self.apikeys}')
                        else:
                            logger.warning("APIKEYS section not found in the configuration file.")
                    else:
                        logger.warning("API keys file not found.")
                except Exception as e:
                    logger.error("Error reading API keys.", exc_info=True)
                    raise

            elif self.cc.card_type == "SeedKeeper":
                self.truststore = {}
                self.card_event = False
            logger.info(f"Initialization complete for card type: {self.cc.card_type}")
        except Exception as e:
            logger.error("Error during initialization of card-specific settings.", exc_info=True)
            raise

    def get_card_status(self):
        if self.cc.card_present:
            logger.info("In get_card_status")
            try:
                response, sw1, sw2, d = self.cc.card_get_status()
                card_status = d
                if card_status:
                    logger.info("Card satus is not None")
                    logger.debug(f"{d}")
                else:
                    logger.error(f"Failed to retrieve card_status, card_status is: {card_status}")

                self.card_present = True if self.cc.card_present else False
                # self.card_is_pin = card_status['card_is_pin']
                self.card_version = card_status['applet_major_version']
                self.needs2FA = card_status['needs2FA']
                self.is_seeded = card_status['is_seeded']
                self.setup_done = card_status['setup_done']
                self.card_type = self.cc.card_type
                self.pin_left = card_status['PIN0_remaining_tries']
                self.two_FA = card_status['needs2FA']
                self.nfc = self.cc.nfc_policy
                self.applet_version = f"{card_status['protocol_major_version']}.{card_status['protocol_minor_version']}-{card_status['applet_major_version']}.{card_status['applet_minor_version']}"

                # self.card_label = self.cc.card_label

                return (self.card_present, self.card_version, self.needs2FA, self.is_seeded,
                        self.setup_done, self.card_type, self.pin_left)

            except Exception as e:
                logger.error(f"Failed to retrieve card status: {e}")
                # Vous pouvez également ajouter d'autres actions en cas d'erreur, comme définir des valeurs par défaut
                self.card_present = False
                self.card_version = None
                self.needs2FA = None
                self.is_seeded = None
                self.setup_done = None
                self.card_type = None
                self.card_label = None

    def request(self, request_type, *args):
        logger.info(str(request_type))

        method_to_call = getattr(self.view, request_type)
        reply = method_to_call(*args)
        return reply

    # def disconnect_the_card(self):
    #     self.cc.card_disconnect()

    def setup_card_pin(self, pin, pin_confirm):
        if pin:
            if len(pin) >= 4:
                if pin == pin_confirm:
                    logger.info("Setup my card PIN: PINs match and are valid.")
                    self.card_setup_native_pin(pin)
                else:
                    logger.warning("Setup my card PIN: PINs do not match.")
                    self.view.show('ERROR', "Pin and pin confirm do not match!", 'Ok',
                                   None, "./pictures_db/icon_change_pin_popup.jpg")
            else:
                logger.warning("Setup my card PIN: PIN is too short.")
                self.view.show("ERROR",
                               "Pin must contain at least 4 characters",
                               'Ok', None,
                               "./pictures_db/icon_change_pin_popup.jpg")
        else:
            self.view.show("ERROR", "You have to set up a PIN to continue.", 'Ok',
                           None, "./pictures_db/icon_change_pin_popup.jpg")

    def change_card_pin(self, current_pin, new_pin, new_pin_confirm):
        try:
            if self.cc.card_present and self.cc.card_type != "Satodime":

                if len(new_pin) < 4:
                    logger.warning("New PIN is too short.")
                    self.view.show("ERROR",
                                   "Pin must contain at least 4 characters", 'Ok',
                                   None, "./pictures_db/icon_change_pin_popup.jpg")

                if new_pin != new_pin_confirm:
                    logger.warning("New PINs do not match.")
                    self.view.show("WARNING",
                                   "The PIN values do not match! Please type PIN again!",
                                   "Ok", None,
                                   "./pictures_db/icon_change_pin_popup.jpg")
                else:
                    current_pin = list(current_pin.encode('utf8'))
                    new_pin = list(new_pin.encode('utf8'))
                    (response, sw1, sw2) = self.cc.card_change_PIN(0, current_pin, new_pin)
                    if sw1 == 0x90 and sw2 == 0x00:
                        logger.info("PIN changed successfully.")
                        msg = "PIN changed successfully!"
                        self.view.show("SUCCESS", msg, 'Ok',
                                       None, "./pictures_db/icon_change_pin_popup.jpg")
                        self.view.start_setup()
                    else:
                        logger.error(f"Failed to change PIN with error code: {hex(sw1)}{hex(sw2)}")
                        msg = f"Failed to change PIN with error code: {hex(sw1)}{hex(sw2)}"
                        self.view.show("ERROR", f"{msg}\n Probably too long", 'Ok',
                                       None, "./pictures_db/icon_change_pin_popup.jpg")
        except Exception as e:
            logger.error(f"Error changing PIN: {e}")
            self.view.show("ERROR", "Failed to change PIN.", "Ok",
                           None, "./pictures_db/icon_change_pin_popup.jpg")

    def generate_random_seed(self, mnemonic_length):
        try:
            logger.info(f"In generate_random_seed(), mnemonic_length: {mnemonic_length}")
            strength = 128 if mnemonic_length == 12 else 256 if mnemonic_length == 24 else None

            if strength:
                MNEMONIC = Mnemonic(language="english")
                mnemonic = MNEMONIC.generate(strength=strength)
                return mnemonic
            else:
                logger.warning("generate_random_seed: invalid mnemonic length {mnemonic_length}")
                return f"Error: invalid mnemonic length {mnemonic_length}"

        except Exception as e:
            logger.error(f"generate_random_seed: Error generating seed: {e}")
            return f"Exception: {e}"

    def import_seed(self, mnemonic, passphrase =None):
        """Import a seed (and optional passphrase) into a Satochip"""
        try:
            MNEMONIC = Mnemonic(language="english")
            if MNEMONIC.check(mnemonic):  # check that seed is valid
                logger.info("Imported seed is valid.")
                if passphrase is not None:
                    if passphrase in ["", " ", "Type your passphrase here"]:
                        logger.error("Passphrase is blank or empy")
                        self.view.show('WARNING', 'Wrong passphrase: incorrect or blank', 'Ok')
                    else:
                        seed = Mnemonic.to_seed(mnemonic, passphrase)
                        self.card_setup_native_seed(seed)
                else:
                    seed = Mnemonic.to_seed(mnemonic)
                    self.card_setup_native_seed(seed)
            else:
                logger.warning("Imported seed is invalid!")
                self.view.show('WARNING',
                               "Warning!\nInvalid BIP39 seedphrase, please retry.",
                               'Ok', None,
                               "./pictures_db/icon_seed_popup.jpg")

        except Exception as e:
            logger.error(f"Error while importing seed: {e}")
            self.view.show("ERROR", "Failed to import seed.", "Ok", None,
                           "./pictures_db/icon_seed_popup.jpg")

    def edit_label(self, label):
        try:
            logger.info(f"New label to set: {label}")
            (response, sw1, sw2) = self.cc.card_set_label(label)
            if sw1 == 0x90 and sw2 == 0x00:
                response, sw1, sw2, label = self.cc.card_get_label()
                logger.info(f"New label set successfully: {label}")
                self.card_label = label
                self.view.show("SUCCESS",
                               f"New label set successfully",
                               "Ok", self.view.start_setup(),
                               "./pictures_db/icon_edit_label_popup.jpg")
            else:
                logger.warning("Failed to set new label.")
                self.view.show("ERROR", f"Failed to set label (code {hex(sw1*256+sw2)})", "oK",
                               None, "./pictures_db/icon_edit_label_popup.jpg")

        except Exception as e:
            logger.error(f"Failed to edit label: {e}")
            self.view.show("ERROR", f"Failed to edit label: {e}", "Ok", None,
                           "./pictures_db/icon_edit_label_popup.jpg")

    def get_card_label_infos(self):
        """Get label info"""
        if self.cc.card_present:
            response, sw1, sw2, label = self.cc.card_get_label()
            if label is None:
                logger.info("Label is None")
            if label == "":
                logger.info("Label is Blank")
            else:
                logger.info(f"Label found: {label}")
                return label
        else:
            logger.info("Card is not Satodime")

    # for PIN
    def PIN_dialog(self, msg):
        try:
            logger.info("Entering PIN_dialog method")

            def switch_unlock_to_false_and_quit():
                self.view.spot_if_unlock = False
                self.view.start_setup()
                self.view.update_status()

            while True:
                try:
                    logger.debug("Requesting passphrase")
                    pin = self.view.get_passphrase(msg)
                    logger.debug(f"Passphrase received: pin={'***' if pin else None}")

                    if pin is None:
                        logger.info("Passphrase request cancelled or window closed")
                        self.view.show("INFO",
                                       'Device cannot be unlocked without PIN code!',
                                       'Ok',
                                       lambda: switch_unlock_to_false_and_quit(),
                                       "./pictures_db/icon_change_pin_popup.jpg")
                        break

                    elif len(pin) < 4:
                        logger.warning("PIN length is less than 4 characters")
                        msg = "PIN must have at least 4 characters."
                        self.view.show("INFO", msg, 'Ok', None,
                                       "./pictures_db/icon_change_pin_popup.jpg")
                    elif len(pin) > 16:
                        logger.warning("PIN length is more than 16 characters")
                        msg = "PIN must have maximum 16 characters."
                        self.view.show("INFO", msg, 'Ok', None,
                                       "./pictures_db/icon_change_pin_popup.jpg")
                    else:
                        logger.info("PIN length is valid")
                        pin = pin.encode('utf8')
                        try:
                            self.cc.card_verify_PIN_simple(pin)
                            break
                        except Exception as e:
                            logger.info("exception from pin dialog")
                            self.view.show('ERROR', str(e), 'Ok', None,
                                           "./pictures_db/icon_change_pin_popup.jpg")

                except Exception as e:
                    logger.error(f"An error occurred while requesting passphrase: {e}", exc_info=True)
                    return (False, None)

        except Exception as e:
            logger.critical(f"An unexpected error occurred in PIN_dialog: {e}", exc_info=True)
            return (False, None)

    # only for satochip and seedkeeper
    def card_setup_native_pin(self, pin):
        try:
            logger.info("In card_setup_native_pin")
            logger.info("Setting up card pin and applet references")

            pin_0 = list(pin.encode('utf8'))
            pin_tries_0 = 0x05
            ublk_tries_0 = 0x01
            ublk_0 = list(urandom(16))  # PUK code
            pin_tries_1 = 0x01
            ublk_tries_1 = 0x01
            pin_1 = list(urandom(16))  # Second pin
            ublk_1 = list(urandom(16))
            secmemsize = 32  # Number of slots reserved in memory cache
            memsize = 0x0000  # RFU
            create_object_ACL = 0x01  # RFU
            create_key_ACL = 0x01  # RFU
            create_pin_ACL = 0x01  # RFU

            logger.info("Sending setup native pin command to card")
            (response, sw1, sw2) = self.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                                                      pin_tries_1, ublk_tries_1, pin_1, ublk_1,
                                                      secmemsize, memsize,
                                                      create_object_ACL, create_key_ACL, create_pin_ACL)
            logger.info(f"Response from card: {response}, sw1: {hex(sw1)}, sw2: {hex(sw2)}")

            if sw1 != 0x90 or sw2 != 0x00:
                logger.warning(f"Unable to set up applet! sw12={hex(sw1)} {hex(sw2)}")
                self.view.show('ERROR', f"Unable to set up applet! sw12={hex(sw1)} {hex(sw2)}")
                return False
            else:
                logger.info("Applet setup successfully")
                self.setup_done = True
                self.view.update_status()
                self.view.start_setup()
        except Exception as e:
            logger.error(f"An error occurred in card_setup_native_pin: {e}", exc_info=True)

    # only for satochip
    def card_setup_native_seed(self, seed):
        # get authentikey
        try:
            authentikey = self.cc.card_bip32_get_authentikey()
        except UninitializedSeedError:
            # Option: setup 2-Factor-Authentication (2FA)
            # self.init_2FA()
            # seed dialog...
            logger.info(f"seed: {seed}")
            authentikey = self.cc.card_bip32_import_seed(seed)
            logger.info(f"authentikey: {authentikey}")
            if authentikey:
                self.is_seeded = True
                self.view.show('SUCCESS',
                               'Your card is now seeded!',
                               'Ok',
                               lambda: None,
                               "./pictures_db/icon_seed_popup.jpg")
                self.view.update_status()
                self.view.start_setup()

                hex_authentikey = authentikey.get_public_key_hex()
                logger.info(f"Authentikey={hex_authentikey}")
            else:
                self.view.show('ERROR', 'Error when importing seed to Satochip!', 'Ok', None,
                               "./pictures_db/icon_seed_popup.jpg")

    # def check_card_authenticity(self):
    #     logger.info("check_card_authenticity")
    #     if self.card_present:
    #         is_authentic, txt_ca, txt_subca, txt_device, txt_error = self.cc.card_verify_authenticity()
    #         logger.info(f"is_authentic: {is_authentic}")
    #         logger.info(f"txt_ca: {txt_ca}")
    #         logger.info(f"txt_subca: {txt_subca}")
    #         logger.info(f"txt_device: {txt_device}")
    #         logger.info(f"txt_error: {txt_error}")
    #         return is_authentic, txt_ca, txt_subca, txt_device, txt_error
    #     else:
    #         pass
