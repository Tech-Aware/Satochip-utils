import logging
from os import urandom, path
import sys
from configparser import ConfigParser
from pysatochip.pysatochip.CardConnector import (CardConnector, UninitializedSeedError)
from pysatochip.pysatochip.version import *

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

                if self.card_type == "Satochip":
                    self.applet_version = f"MajorVersion: 0.{str(SATOCHIP_PROTOCOL_MAJOR_VERSION)} - MinorVersion: 0.{str(SATOCHIP_PROTOCOL_MINOR_VERSION)}"
                elif self.card_type == "SeedKeeper":
                    self.applet_version = f"MajorVersion: 0.{str(SEEDKEEPER_PROTOCOL_MAJOR_VERSION)} - MinorVersion: 0.{str(SEEDKEEPER_PROTOCOL_MINOR_VERSION)}"
                elif self.card_type == "Satodime":
                    self.applet_version = f"MajorVersion: 0.{str(SATODIME_PROTOCOL_MAJOR_VERSION)} - MinorVersion:0.{str(SATODIME_PROTOCOL_MINOR_VERSION)}"


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

    def card_transmit_reset(self):
        try:
            logger.debug("In card_transmit_reset")
            while self.cc.card_present:
                try:
                    # transmit apdu
                    apdu = [0xB0, 0xFF, 0x00, 0x00, 0x00]
                    response, sw1, sw2 = self.cc.cardservice.connection.transmit(apdu)
                    logger.info("APDU transmitted successfully")
                    return response, sw1, sw2
                except Exception as e:
                    logger.error(f"ERROR: An error occurred during APDU transmission: {e}")
                    raise
        except Exception as e:
            logger.error(f"ERROR: An error occurred in card_transmit_reset: {e}")
            raise

    def request(self, request_type, *args):
        logger.info(str(request_type))

        method_to_call = getattr(self.view, request_type)
        reply = method_to_call(*args)
        return reply

    def disconnect_the_card(self):
        self.cc.card_disconnect()

    def handle_user_action(self,
                           frame_concerned,
                           button_clicked=None,
                           first_entry_value=None,
                           second_entry_value=None,
                           third_entry_value=None
                           ):

        global seed, passphrase, mnemonic

        logger.info("In handle_user_action:")

        try:
            if first_entry_value and not second_entry_value and not third_entry_value:
                logger.info(
                    f"frame concerned = {frame_concerned}, button_clicked = {button_clicked}, entry_value = {first_entry_value}")
            if first_entry_value and second_entry_value and not third_entry_value:
                logger.info(
                    f"frame concerned = {frame_concerned}, button_clicked = {button_clicked}, entry_value = {first_entry_value} {second_entry_value}")
            if first_entry_value and second_entry_value and third_entry_value:
                logger.info(
                    f"frame concerned = {frame_concerned}, button_clicked = {button_clicked}, entry_value = {first_entry_value} {second_entry_value} {third_entry_value}")

            if frame_concerned == "welcome" and button_clicked == "Let's Go!":
                logger.info("Welcome frame: Starting setup.")
                self.request("start_setup")

            if frame_concerned == "setup_my_card_pin":
                if button_clicked == "Cancel":
                    logger.info("Setup my card PIN: Cancelled by user.")
                    self.request("start_setup")

                if button_clicked == "Finish":
                    pin = first_entry_value
                    pin_confirm = second_entry_value

                    if pin:
                        if len(pin) >= 4:
                            if pin == pin_confirm:
                                logger.info("Setup my card PIN: PINs match and are valid.")
                                self.card_setup_native_pin(pin)
                            else:
                                logger.warning("Setup my card PIN: PINs do not match.")
                                self.request('show', 'ERROR',
                                             "Pin and pin confirm do not match!", 'Ok',
                                             None, "./pictures_db/icon_change_pin_popup.jpg")
                        else:
                            logger.warning("Setup my card PIN: PIN is too short.")
                            self.request("show", "ERROR",
                                         "Pin must contain at least 4 characters", 'Ok',
                                         None, "./pictures_db/icon_change_pin_popup.jpg")
                    else:
                        self.request("show", "ERROR",
                                     "You have to set up a PIN to continue.", 'Ok',
                                     None, "./pictures_db/icon_change_pin_popup.jpg")

            if frame_concerned == "setup_my_card_seed":
                from mnemonic import Mnemonic

                if button_clicked == "Cancel":
                    logger.info("Setup my card seed: Cancelled by user.")
                    self.request("start_setup")

                if button_clicked == "generate_seed_button":
                    try:
                        logger.info(f"IN setup my card seed, sev: {second_entry_value}")
                        strength = 128 if second_entry_value == 12 else 256 if second_entry_value == 24 else None

                        if strength:
                            MNEMONIC = Mnemonic(language="english")
                            mnemonic = MNEMONIC.generate(strength=strength)
                            seed = mnemonic
                            if first_entry_value is not None:
                                passphrase = third_entry_value
                                logger.info(f"Generated seed: {seed}, passphrase: {passphrase}")
                            else:
                                passphrase = None
                                logger.info(f"Generated seed: {seed}")
                            if passphrase is not None:
                                self.request("update_textbox", seed)
                                seed = Mnemonic.to_seed(mnemonic, passphrase) if mnemonic else None
                                logger.info(f"Generate see: {seed}. Corresponding to {mnemonic} as mnemonic and passphrase {passphrase})")
                            else:
                                self.request("update_textbox", seed)
                                seed = Mnemonic.to_seed(mnemonic) if mnemonic else None
                            self.request("show",
                                         "WARNING",
                                         "Your mnemonic is very important!\nBe sure to copy it in a safe place.", 'Ok',
                                         None, "./pictures_db/icon_seed_popup.jpg")
                        else:
                            logger.warning("Setup my card seed: Invalid strength value.")
                            self.request("show", "ERROR", "Invalid strength value.", 'Ok', None,
                                         "./pictures_db/icon_seed_popup.jpg")
                    except Exception as e:
                        logger.error(f"Error generating seed: {e}")
                        self.request("show", "ERROR", "Failed to generate seed.", 'ok', None,
                                     "./pictures_db/icon_seed_popup.jpg")

                if button_clicked == "import_seed_button":
                    try:
                        MNEMONIC = Mnemonic(language="english")
                        if first_entry_value is not None:
                            mnemonic = first_entry_value
                            passphrase = third_entry_value if second_entry_value is not None else None
                            logger.info(f"Seed to import: {mnemonic}, passphrase: {passphrase}")
                            if MNEMONIC.check(mnemonic):  # check that seed is valid
                                logger.info("Imported seed is valid.")
                                if passphrase is not None:
                                    if passphrase in ["", " ", "Type your passphrase here"]:
                                        logger.error("Passphrase is blank or empy")
                                        self.request('show', 'WARNING', 'Wrong passphrase: incorrect or blank', 'Ok')
                                    else:
                                        seed = Mnemonic.to_seed(mnemonic, passphrase) if mnemonic else None
                                        logger.info(f"seed:{seed}")
                                        logger.info(f"mnemonic: {mnemonic}")
                                        logger.info(f"passphrase: {passphrase}")
                                        self.card_setup_native_seed(seed)
                                else:
                                    seed = Mnemonic.to_seed(mnemonic) if mnemonic else None
                                    logger.info(f"seed:{seed}")
                                    logger.info(f"mnemonic: {mnemonic}")
                                    logger.info(f"passphrase: {passphrase}")
                                    self.card_setup_native_seed(seed)
                            else:
                                logger.warning("Imported seed is invalid.")
                                self.request('show', 'WARNING',
                                             "Warning!\nInvalid BIP39 seedphrase, please retry.", 'Ok',
                                             None, "./pictures_db/icon_seed_popup.jpg")
                    except Exception as e:
                        logger.error(f"Error importing seed: {e}")
                        self.request("show", "ERROR", "Failed to import seed.", "Ok", None,
                                     "./pictures_db/icon_seed_popup.jpg")

                if button_clicked == "Finish":
                    try:
                        MNEMONIC = Mnemonic(language="english")
                        if first_entry_value is not None:
                            mnemonic = first_entry_value
                            passphrase = third_entry_value if second_entry_value is not None else ''
                            logger.info(f"Seed to import: {mnemonic}, passphrase: {passphrase}")
                            if MNEMONIC.check(mnemonic):  # check that seed is valid
                                logger.info("Imported seed is valid.")
                                seed = Mnemonic.to_seed(mnemonic, passphrase) if mnemonic else None
                                self.card_setup_native_seed(seed)
                            else:
                                logger.warning("Imported seed is invalid.")
                                self.request('show', 'ERROR', "Invalid BIP39 seed! Please type again!", 'Ok',
                                             None, "./pictures_db/icon_seed_popup.jpg")
                    except Exception as e:
                        logger.error(f"Error importing seed: {e}")
                        self.request("show", "ERROR", "Failed to import seed.", "Ok", None,
                                     "./pictures_db/icon_seed_popup.jpg")

            if frame_concerned == "edit_label":
                try:
                    if self.cc.card_present:
                        if button_clicked == "Cancel":
                            self.request('start_setup')

                        if button_clicked == "Finish":
                            if first_entry_value:
                                label = first_entry_value
                                logger.info(f"New label to set: {label}")
                                (response, sw1, sw2) = self.cc.card_set_label(label)
                                if sw1 == 0x90 and sw2 == 0x00:
                                    response, sw1, sw2, label = self.cc.card_get_label()
                                    logger.info(f"New label set successfully: {label}")
                                    self.card_label = label
                                    self.request("show", "SUCCESS",
                                                 f"New label set successfully",
                                                 "Ok",
                                                 self.request("start_setup"), "./pictures_db/icon_edit_label_popup.jpg")
                                else:
                                    logger.warning("Failed to set new label.")
                                    self.request("show", "ERROR", "Failed to set label: too long.", "oK", None,
                                                 "./pictures_db/icon_edit_label_popup.jpg")
                            else:
                                logger.warning("Blank label cannot be set.")
                                self.request("show",
                                             "WARNING",
                                             "You can't set a blank label!",
                                             "Ok!",
                                             self.request("edit_label"), "./pictures_db/icon_edit_label_popup.jpg")
                except Exception as e:
                    logger.error(f"Error editing label: {e}")
                    self.request("show", "ERROR", "Failed to edit label.", "Ok", None,
                                 "./pictures_db/icon_edit_label_popup.jpg")

            if frame_concerned == "change_pin":
                logger.info("In change_pin")
                try:
                    if self.cc.card_present and self.cc.card_type != "Satodime":
                        if button_clicked == "Finish":
                            current_pin = first_entry_value
                            new_pin = second_entry_value
                            new_pin_confirm = third_entry_value

                            if len(new_pin) <= 3:
                                logger.warning("New PIN is too short.")
                                self.request("show", "ERROR",
                                             "Pin must contain at least 4 characters", 'Ok',
                                             None, "./pictures_db/icon_change_pin_popup.jpg")

                            if new_pin != new_pin_confirm:
                                logger.warning("New PINs do not match.")
                                self.request("show", "WARNING",
                                             "The PIN values do not match! Please type PIN again!", "Ok",
                                             None, "./pictures_db/icon_change_pin_popup.jpg")
                            else:
                                current_pin = list(current_pin.encode('utf8'))
                                new_pin = list(new_pin.encode('utf8'))
                                (response, sw1, sw2) = self.cc.card_change_PIN(0, current_pin, new_pin)
                                if sw1 == 0x90 and sw2 == 0x00:
                                    logger.info("PIN changed successfully.")
                                    msg = "PIN changed successfully!"
                                    self.request("show", "SUCCESS", msg, 'Ok',
                                                 None, "./pictures_db/icon_change_pin_popup.jpg")
                                    self.request('start_setup')
                                else:
                                    logger.error(f"Failed to change PIN with error code: {hex(sw1)}{hex(sw2)}")
                                    msg = f"Failed to change PIN with error code: {hex(sw1)}{hex(sw2)}"
                                    self.request("show", "ERROR", f"{msg}\n Probably too long", 'Ok',
                                                 None, "./pictures_db/icon_change_pin_popup.jpg")
                except Exception as e:
                    logger.error(f"Error changing PIN: {e}")
                    self.request("show", "ERROR", "Failed to change PIN.", "Ok",
                                 None, "./pictures_db/icon_change_pin_popup.jpg")
        except Exception as e:
            logger.error(f"Error in handle_user_action: {e}")
            self.request("show", "ERROR", "An unexpected error occurred.", "Ok",
                         None, "./pictures_db/icon_change_pin_popup.jpg")

    # interaction with card
    # for label
    def get_card_label_infos(self):
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
                self.request('start_setup')
                self.request('update_status')

            while True:
                try:
                    logger.debug("Requesting passphrase")
                    pin = self.request('get_passphrase', msg)
                    logger.debug(f"Passphrase received: pin={'***' if pin else None}")

                    if pin is None:
                        logger.info("Passphrase request cancelled or window closed")
                        self.request("show", "INFO", 'Device cannot be unlocked without PIN code!', 'Ok',
                                     lambda: switch_unlock_to_false_and_quit(), "./pictures_db/icon_change_pin_popup.jpg")
                        break

                    elif len(pin) < 4:
                        logger.warning("PIN length is less than 4 characters")
                        msg = "PIN must have at least 4 characters."
                        self.request("show", "INFO", msg, 'Ok',
                                     None, "./pictures_db/icon_change_pin_popup.jpg")

                    elif len(pin) > 64:
                        logger.warning("PIN length is more than 64 characters")
                        msg = "PIN must have less than 64 characters."
                        self.request("show", "INFO", msg, 'Ok',
                                     None, "./pictures_db/icon_change_pin_popup.jpg")

                    else:
                        logger.info("PIN length is valid")
                        pin = pin.encode('utf8')
                        try:
                            self.cc.card_verify_PIN_simple(pin)
                            break
                        except Exception as e:
                            logger.info("exception from pin dialog")
                            self.request('show', 'ERROR', str(e), 'Ok', None,
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
                self.request('show', 'ERROR', f"Unable to set up applet! sw12={hex(sw1)} {hex(sw2)}")
                return False
            else:
                logger.info("Applet setup successfully")
                self.setup_done = True
                self.request('update_status')
                self.request('start_setup')
        except Exception as e:
            logger.error(f"An error occurred in card_setup_native_pin: {e}", exc_info=True)

            # I put this option between docstring to use it later in another part of the code
            """# set card label
            try:
                (response, sw1, sw2) = self.cc.card_set_label(label)
                self.request('show',
                             'SUCCESS',
                             f"Your Satochip has now a label and a PIN code.",
                             "Let's seed it ..." if self.cc.card_type == "Satochip" else "End",
                             self.request("setup_my_card_seed") if self.cc.card_type == "Satochip" else self.request("start_setup"))
            except Exception as ex:
                logger.warning(f"Error while setting card label: {str(ex)}")"""

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
                self.request('show',
                             'SUCCESS',
                             'Your card is now seeded!',
                             'Ok',
                             lambda: None,
                             "./pictures_db/icon_seed_popup.jpg")
                self.request('update_status')
                self.request('start_setup')

                hex_authentikey = authentikey.get_public_key_hex()
                logger.info(f"Authentikey={hex_authentikey}")
            else:
                self.request('show', 'ERROR', 'Error when importing seed to Satochip!', 'Ok', None,
                             "./pictures_db/icon_seed_popup.jpg")

    def check_card_authenticity(self):
        logger.info("check_card_authenticity")
        if self.card_present:
            is_authentic, txt_ca, txt_subca, txt_device, txt_error = self.cc.card_verify_authenticity()
            logger.info(f"is_authentic: {is_authentic}")
            logger.info(f"txt_ca: {txt_ca}")
            logger.info(f"txt_subca: {txt_subca}")
            logger.info(f"txt_device: {txt_device}")
            logger.info(f"txt_error: {txt_error}")
            return is_authentic, txt_ca, txt_subca, txt_device, txt_error
        else:
            pass




