from Processors.AckProcessor import AckProcessor

from Processors.BlockedProcessor import BlockedProcessor
from Processors.CongestionFeedbackProcessor import CongestionFeedbackProcessor
from Processors.ConnectionCloseProcessor import ConnectionCloseProcessor
from Processors.GoAwayProcessor import GoAwayProcessor
from Processors.PaddingProcessor import PaddingProcessor
from Processors.PingProcessor import PingProcessor
from Processors.RSTStreamProcessor import RSTStreamProcessor
from Processors.StopWaitingProcessor import StopWaitingProcessor
from Processors.StreamProcessor import StreamProcessor
from Processors.UnknownProcessor import UnknownProcessor
from Processors.WindowsUpdateProcessor import WindowUpdateProcessor


class FramesProcessor:
    """
    This class is responsible for processing all the streams in a body
    """

    packet_body = None

    def __init__(self, packet_body) -> None:
        super().__init__()
        self.packet_body = packet_body

    def process(self):

        print(self.packet_body)

        # self.packet_body = ['A3', '70', '7F', '20', '71', '3F', '38', 'A7', 'D9', 'DE', '27', '2C', 'CD', '99', 'A5',
        #                     '92', 'A4', '5C', 'B6', '5F', '9E', '8A', '21', 'A8', '84', 'BC', 'A4', '46', '70', 'CD',
        #                     'C9', 'DA', 'D9', 'DA', 'AC', '03', 'CA', '05', '17', '1B', 'FF', 'DB', '6B', 'C7', '26',
        #                     '9F', 'D3', '74', 'AF', 'A3', '02', 'EB', 'F9', '8B', '6A', 'E1', 'C9', 'DE', '9C', '2E',
        #                     'CB', 'BE', 'AA', '56', 'C8', '22', 'DF', 'E1', 'E5', '04', 'A2', '29', '3B', '99', 'BA',
        #                     '48', '78', '03', '9C', '23', '4E', 'BF', 'E1', '61', 'AD', 'D5', 'FF', '4E', '4A', '4B',
        #                     'B0', '79', 'FB', '77', '03', '52', '94', '47', '39', '8C', 'E2', 'C4', 'AF', '4D', 'D9',
        #                     '10', '1D', '95', 'DA', 'F0', '02', 'FD', 'C4', '25', '26', '71', '6D', '83', 'BC', '18',
        #                     'FB', '2D', '60', '91', 'B2', 'F1', '30', 'A5', '72', '8F', '25', '16', '63', '5F', 'A6',
        #                     '3F', '4E', '81', '91', 'F8', '60', '2E', 'CA', '63', 'F3', '4C', 'C6', 'A5', 'D7', '5A',
        #                     'E1', 'FB', '95', '3F', '96', '7E', 'DF', 'D1', 'FD', '44', '03', '89', '09', '5F', '58',
        #                     '81', '69', '31', '3A', '96', '8E', '6D', 'BB', '9A', '3F', 'FC', 'CE', '6E', '67', 'C5',
        #                     'A6', '03', '0E', '66', '68', '99', '80', '44', 'F6', '99', '69', '53', '26', '81', '9D',
        #                     'C6', '05', '18', 'B0', 'A6', '76', '46', '7A', 'EC', '14', '62', 'FC', 'B1', '26', '39',
        #                     'FB', '07', '36', 'D2', 'A6', '05', '9C', '4F', 'BA', 'DC', 'ED', 'CA', '84', '32', '1B',
        #                     '2E', 'B8', 'BF', 'C1', 'BE', '5B', '58', 'C9', '11', '98', '92', '24', '4B', 'B4', 'C0',
        #                     '59', '00', '45', '75', '3D', '1D', '85', 'CB', 'BC', '93', '0A', '69', '33', 'FE', '15',
        #                     '6D', '77', '57', '43', '99', 'C7', '54', '9E', '0E', 'D4', '97', 'CB', 'F0', '76', '31',
        #                     '87', 'E8', '94', '3D', '84', '20', '84', '19', 'C1', '27', '55', '28', '86', 'E5', '93',
        #                     'AA', 'A6', '2E', 'F1', '3E', 'C0', '5F', 'F2', '25', 'CA', '6B', 'B6', '35', '55', '80',
        #                     '8D', '96', '5C', 'D6', 'B4', '4A', '4D', 'DE', '2D', '1A', 'F4', '7B', 'B6', '3C', 'D8',
        #                     '62', '68', '15', 'B8', 'A7', '99', 'B0', '14', 'D1', 'ED', 'DC', 'B6', '65', '7B', '6A',
        #                     'BC', 'E7', '00', 'C0', 'CA', '1B', '21', '54', 'F6', '83', 'BE', 'BE', '48', '99', '01',
        #                     '8F', '6D', '4F', 'F3', '67', 'BF', 'BC', 'B2', '29', '17', '2A', '6A', '4A', 'AC', 'F3',
        #                     'CF', 'E2', '5B', 'B4', '3A', 'DF', 'FE', 'E6', 'E4', 'F3', '1D', 'C4', '51', '30', '0B',
        #                     '76', '31', '39', 'D6', '1A', '0E', '2E', 'CE', 'CA', 'DE', '03', 'BE', '59', '3D', '17',
        #                     '1B', 'AF', 'F1', 'B3', '68', 'CE', 'EC', '86', '50', '4B', '80', '9C', 'EA', 'CC', 'A0',
        #                     '48', 'E2', 'E7', '54', 'A5', '82', '61', '8C', 'D0', 'F6', '6D', '9C', '56', '1D', 'F6',
        #                     'A1', '69', '9C', '27', '76', '54', '07', '95', '52', 'A6', '5D', '65', '3C', '95', '72',
        #                     'B4', '58', 'C1', 'EF', '96', '13', '8F', 'CB', 'DE', '1A', '7C', 'F6', '4B', '23', 'C4',
        #                     'C9', '1C', '0F', '11', 'FF', 'D1', 'A8', '74', '43', '81', '53', '9C', '4C', 'DA', '40',
        #                     '7D', '79', '12', '59', '66', 'C3', '4D', 'C4', '1B', '5B', '1A', '44', 'F2', 'F3', 'FD',
        #                     '17', '53', 'C3', '23', '33', 'D3', 'A9', 'DE', '98', '6F', '9F', 'C0', '1F', 'D7', 'FD',
        #                     '74', '33', '87', 'E2', 'C4', '7C', '45', '36', '32', '78', 'CC', '08', '71', '80', '58',
        #                     '9A', '30', 'DD', 'BD', '60', '74', 'DA', '16', 'BE', '43', '50', '28', 'D8', '65', '47',
        #                     'B2', '92', '74', 'B9', '17', '03', 'DD', 'C6', '0E', '97', '8C', '39', '5D', '90', '8B',
        #                     '09', '03', 'E8', '5D', 'B7', 'F8', '69', '8D', '38', 'F3', '09', '1E', '84', '8C', '1F',
        #                     '1B', 'F3', '18', 'C3', '44', '49', '2D', '59', '09', 'EC', '35', '22', '8C', 'A6', 'CA',
        #                     '28', '1E', '76', 'C6', 'D8', '65', 'EA', 'F0', 'A4', '80', '98', '1C', '47', '14', 'CD',
        #                     '74', '83', 'AF', '48', '65', 'E1', '1F', '9C', 'AC', '8E', '90', '98', '0E', '2C', '2C',
        #                     '47', '38', '72', '89', '0B', '95', 'E3', 'D8', '41', '80', 'CE', '1F', '04', '72', 'D9',
        #                     '09', 'C5', '5B', '78', '19', '5D', '61', '7C', '24', '09', '1E', '39', '1E', 'B7', 'D2',
        #                     '09', '95', 'DF', '79', '75', 'D5', '69', 'F2', '21', '6E', 'FA', '5C', 'E0', '94', '18',
        #                     'C8', 'F2', 'E3', '1F', '3F', 'ED', '7D', 'D7', 'CB', '96', '16', 'C5', '90', 'F8', '02',
        #                     'C4', '30', 'BB', 'EF', '98', 'B8', '9B', 'D3', '79', '29', '26', 'A0', '7F', '67', 'E6',
        #                     '9C', 'DF', 'A6', 'C2', 'F8', 'E2', 'C6', 'B1', '03', '75', '14', 'CB', '77', '38', 'AB',
        #                     'F8', '0A', 'CE', '70', '4B', 'B5', 'EF', 'AE', 'FA', 'DD', '8A', '87', '47', '38', '69',
        #                     'C4', '38', 'B7', 'F9', '27', 'B1', '28', '1D', '17', '9D', 'F9', 'CC', '57', '90', '99',
        #                     '7D', '99', '5A', 'B3', '8E', '5A', 'C1', '31', '86', 'A8', '14', 'AB', '8C', '4C', 'E2',
        #                     '18', '03', 'FC', '74', '96', 'EE', 'D6', '37', '6F', '6C', 'DA', 'D5', 'A2', '27', '12',
        #                     '8E', '59', '1B', 'E7', 'A7', '18', '87', '22', '6F', 'D7', 'F3', '10', '5C', '0B', 'D1',
        #                     '92', '88', '93', 'E6', '11', 'BA', 'C5', '58', '16', '06', 'B8', '20', 'C1', '26', '75',
        #                     'D3', '2F', 'BF', 'C2', '2D', '77', '4B', '33', 'D4', '4D', 'CF', 'E3', 'EF', 'DB', 'B8',
        #                     '44', '80', '4E', 'E0', 'DB', 'EA', '8C', '47', 'E6', 'E0', '7A', '8F', '9B', '82', '4C',
        #                     'A2', '79', '8E', 'BB', 'EF', 'C4', 'C2', '33', '29', 'FF', '48', '72', '1B', 'A1', 'A8',
        #                     '00', '91', '5B', 'C5', '6E', '0B', 'BC', 'C7', 'C9', '2D', 'FF', '11', '2B', '3F', '12',
        #                     '6C', '3A', 'FD', 'F6', '8C', '60', 'D0', 'F1', '5D', '02', '57', '9A', 'C5', 'BA', '6F',
        #                     '54', 'DC', '59', '36', '15', '7D', '6B', '94', 'F2', 'AE', '47', 'DA', '39', 'E2', '94',
        #                     '75', '88', 'B4', 'BB', 'F3', '0A', 'B4', '32', '4A', '54', '47', '98', '84', '2F', '20',
        #                     'FE', '61', '5B', '1B', '28', '96', '64', '96', '1B', '22', 'B5', 'ED', '2E', '18', '69',
        #                     '67', '71', '8B', '94', 'FE', '1A', 'EF', '57', '87', '3E', '23', 'DF', '1F', '07', '28',
        #                     '6B', '33', '8C', 'F5', '01', '62', '8A', 'E4', '10', 'D1', 'FA', 'C3', '89', 'B0', '42',
        #                     '4C', 'E9', '9A', 'BB', '22', '1A', '1C', '27', '12', 'A8', '60', '54', '4A', '59', 'C4',
        #                     '1F', 'BF', 'C1', '5B', 'B3', 'F8', '93', '80', '62', 'A1', '7B', '60', '1B', 'D1', 'B9',
        #                     '4B', 'AC', 'EA', 'E2', 'D9', '35', 'AA', 'E8', '3A', 'B3', '36', '81', '15', 'EE', '6A',
        #                     '79', '03', 'EB', '2B', '01', '2D', '7D', '7A', '15', '2A', 'BD', '4D', '76', '2D', '95',
        #                     'B9', 'A9', 'FC', '76', 'C7', '02', '5A', 'FE', '23', '7E', 'B3', 'FC', '71', '4E', '68',
        #                     '0F', 'C8', '02', 'AB', 'C9', 'E8', '92', '0A', '24', '6E', '10', 'EA']

        processors = [
            {
                'processor': AckProcessor(),
                'processes': 0
            },
            {
                'processor': BlockedProcessor(),
                'processes': 0
            },
            {
                'processor': CongestionFeedbackProcessor(),
                'processes': 0
            },
            {
                'processor': ConnectionCloseProcessor(),
                'processes': 0
            },
            {
                'processor': GoAwayProcessor(),
                'processes': 0
            },
            {
                'processor': PaddingProcessor(),
                'processes': 0
            },
            {
                'processor': PingProcessor(),
                'processes': 0
            },
            {
                'processor': RSTStreamProcessor(),
                'processes': 0
            },
            {
                'processor': StopWaitingProcessor(),
                'processes': 0
            },
            {
                'processor': StreamProcessor(),
                'processes': 0
            },
            {
                'processor': WindowUpdateProcessor(),
                'processes': 0
            },
            {
                'processor': UnknownProcessor(),
                'processes': -999999
            }
        ]

        # print(self.packet_body)

        while len(self.packet_body) > 0:
            # As long as we need to process the packet body
            for processor in processors:
                processor['processor'].receive(self.packet_body)
                if processor['processor'].my_frame():
                    print("Processed by {}".format(processor))
                    processor['processor'].process()
                    self.packet_body = processor['processor'].result()
                    processor['processes'] += 1
                    break

# f = FramesProcessor("")
# f.process()
