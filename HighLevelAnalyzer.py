# MCP2515 High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from enum import IntEnum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from typing import List, Union


class Instructions(IntEnum):
    RESET = 0b1100_0000
    READ = 0b0000_0011
    WRITE = 0b0000_0010
    READ_STATUS = 0b1010_0000
    RX_STATUS = 0b1011_0000
    BIT_MODIFY = 0b0000_0101


REGISTER_MAP = [
    ['RXF0SIDH', 'RXF3SIDH', 'RXM0SIDH', 'TXB0CTRL', 'TXB1CTRL', 'TXB2CTRL', 'RXB0CTRL', 'RXB1CTRL'],
    ['RXF0SIDL', 'RXF3SIDL', 'RXM0SIDL', 'TXB0SIDH', 'TXB1SIDH', 'TXB2SIDH', 'RXB0SIDH', 'RXB1SIDH'],
    ['RXF0EID8', 'RXF3EID8', 'RXM0EID8', 'TXB0SIDL', 'TXB1SIDL', 'TXB2SIDL', 'RXB0SIDL', 'RXB1SIDL'],
    ['RXF0EID0', 'RXF3EID0', 'RXM0EID0', 'TXB0EID8', 'TXB1EID8', 'TXB2EID8', 'RXB0EID8', 'RXB1EID8'],
    ['RXF1SIDH', 'RXF4SIDH', 'RXM1SIDH', 'TXB0EID0', 'TXB1EID0', 'TXB2EID0', 'RXB0EID0', 'RXB1EID0'],
    ['RXF1SIDL', 'RXF4SIDL', 'RXM1SIDL', 'TXB0DLC', 'TXB1DLC', 'TXB2DLC', 'RXB0DLC', 'RXB1DLC'],
    ['RXF1EID8', 'RXF4EID8', 'RXM1EID8', 'TXB0D0', 'TXB1D0', 'TXB2D0', 'RXB0D0', 'RXB1D0'],
    ['RXF1EID0', 'RXF4EID0', 'RXM1EID0', 'TXB0D1', 'TXB1D1', 'TXB2D1', 'RXB0D1', 'RXB1D1'],
    ['RXF2SIDH', 'RXF5SIDH', 'CNF3', 'TXB0D2', 'TXB1D2', 'TXB2D2', 'RXB0D2', 'RXB1D2'],
    ['RXF2SIDL', 'RXF5SIDL', 'CNF2', 'TXB0D3', 'TXB1D3', 'TXB2D3', 'RXB0D3', 'RXB1D3'],
    ['RXF2EID8', 'RXF5EID8', 'CNF1', 'TXB0D4', 'TXB1D4', 'TXB2D4', 'RXB0D4', 'RXB1D4'],
    ['RXF2EID0', 'RXF5EID0', 'CANINTE', 'TXB0D5', 'TXB1D5', 'TXB2D5', 'RXB0D5', 'RXB1D5'],
    ['BFPCTRL', 'TEC', 'CANINTF', 'TXB0D6', 'TXB1D6', 'TXB2D6', 'RXB0D6', 'RXB1D6'],
    ['TXRTSCTRL', 'REC', 'EFLG', 'TXB0D7', 'TXB1D7', 'TXB2D7', 'RXB0D7', 'RXB1D7'],
    ['CANSTAT', 'CANSTAT', 'CANSTAT', 'CANSTAT', 'CANSTAT', 'CANSTAT', 'CANSTAT', 'CANSTAT'],
    ['CANCTRL', 'CANCTRL', 'CANCTRL', 'CANCTRL', 'CANCTRL', 'CANCTRL', 'CANCTRL', 'CANCTRL']
]


def get_register_name(register: int) -> str:
    lo = (register & 0x0F)
    hi = (register & 0xF0) >> 4
    return REGISTER_MAP[lo][hi]


def data_to_str(data: bytes) -> str:
    return ' '.join((f'0x{byte:02X}' for byte in data))


class MCP2515Hla(HighLevelAnalyzer):
    result_types = {
        'instruction': {
            'format': '{{data.instruction}}'
        },
        'control_reg': {
            'format': '{{data.control_reg}}'
        },
        'mask': {
            'format': 'Mask: {{data.mask}}'
        },
        'data': {
            'format': 'Data: {{data.data}}'
        },
    }

    def __init__(self) -> None:
        self.frames = []

    def decode(self, frame: AnalyzerFrame) -> Union[AnalyzerFrame, List[AnalyzerFrame], None]:
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        if frame.type == 'enable':
            self.frames = []
        elif frame.type == 'result':
            self.frames.append(frame)
        elif frame.type == 'disable':
            return self._decode_frames(self.frames)
        else:
            raise RuntimeError(f'Unexpected frame type: {frame.type}. Please select SPI as an input analyzer.')

        return None

    def _decode_frames(self, frames: List[AnalyzerFrame]) -> List[AnalyzerFrame]:
        output = []

        if len(frames) >= 1:
            instruction_frame = frames[0]
            instruction = Instructions(instruction_frame.data['mosi'][0])
            frame = AnalyzerFrame('instruction',
                                  instruction_frame.start_time,
                                  instruction_frame.end_time,
                                  {
                                      'instruction': instruction.name,
                                  })
            output.append(frame)

        if len(frames) >= 2:
            control_reg_frame = frames[1]
            control_reg_name = get_register_name(control_reg_frame.data['mosi'][0])
            frame = AnalyzerFrame('control_reg',
                                  control_reg_frame.start_time,
                                  control_reg_frame.end_time,
                                  {
                                      'control_reg': control_reg_name,
                                  })
            output.append(frame)

        if len(frames) >= 3:
            if instruction == Instructions.BIT_MODIFY:
                mask_frame = frames[2]
                mask = mask_frame.data['mosi'][0]
                frame = AnalyzerFrame('mask',
                                      mask_frame.start_time,
                                      mask_frame.end_time,
                                      {
                                          'mask': f'0x{mask:02X}',
                                      })
                output.append(frame)

                data_frames = frames[3:]
            else:
                data_frames = frames[2:]

            if len(data_frames) > 0:
                miso = bytearray()
                mosi = bytearray()
                for frame in data_frames:
                    miso.extend(frame.data['miso'])
                    mosi.extend(frame.data['mosi'])

                if instruction == Instructions.READ:
                    data = miso
                else:
                    data = mosi

                frame = AnalyzerFrame('data',
                                      data_frames[0].start_time,
                                      data_frames[-1].end_time,
                                      {
                                          'data': data_to_str(data),
                                      })
                output.append(frame)

        return output
