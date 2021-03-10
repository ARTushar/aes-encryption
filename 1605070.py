from BitVector import *
from math import ceil
from typing import List
from time import time

mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"),
     BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"),
     BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"),
     BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"),
     BitVector(hexstring="01"), BitVector(hexstring="02")]
]

inv_mixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"),
     BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"),
     BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"),
     BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"),
     BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

AES_modulus = BitVector(bitstring='100011011')

sbox = None
inv_sbox = None


class AESKeySchedule:

  def __init__(self, key: str, total_word: int, total_rounds: int, max_key_length: int) -> None:
    self.total_word = total_word
    self.max_key_length = max_key_length
    self.total_rounds = total_rounds
    self.key = key
    self.modified_key = None
    self.byte_length = 8
    self.word_length = 32
    self.encryption_keys = None

    self.calculate_expanded_keys()

  def get_encryption_keys(self):
    return self.encryption_keys

  def calculate_rcoli(self) -> list:
    rci = []
    rcoli = []
    rci.append(1)

    for i in range(1, self.total_rounds-1):
      if rci[i-1] < 0x80:
        rci.append(rci[i-1] * 2)
      else:
        rci.append((2 * rci[i-1]) ^ 0x11B)

    for i in range(len(rci)):
      rcoli.append([
          BitVector(intVal=rci[i], size=8),
          BitVector(intVal=0, size=8),
          BitVector(intVal=0, size=8),
          BitVector(intVal=0, size=8)
      ])

    return rcoli

  def rotate_word_left(self, word: List[BitVector]) -> List[BitVector]:
    new_word = [None] * len(word)
    for i in range(len(word)-1):
      new_word[i] = word[i+1].deep_copy()
    new_word[len(word)-1] = word[0].deep_copy()
    return new_word

  def get_sval(self, hex_val) -> int:
    return sbox[int(hex_val[0], 16) * 16 + int(hex_val[1], 16)]

  def sub_word(self, word: List[BitVector]) -> List[BitVector]:
    new_word = [None] * len(word)
    for i in range(len(word)):
      new_word[i] = BitVector(intVal=self.get_sval(
          word[i].get_bitvector_in_hex()), size=8)
    return new_word

  def xor_words(self, word1: List[BitVector], word2: List[BitVector]) -> List[BitVector]:
    new_word = [None] * len(word1)
    for i in range(len(word1)):
      new_word[i] = word1[i] ^ word2[i]

    return new_word

  def create_root_key(self) -> List[List[BitVector]]:
    root_key = BitVector(textstring=self.key)
    if root_key.size < self.max_key_length:
      root_key.pad_from_right(self.max_key_length - root_key.size)
    elif root_key.size > self.max_key_length:
      root_key = root_key[0:self.max_key_length]
    
    self.modified_key = root_key

    root_words = []
    total_index = int(self.max_key_length / self.word_length)
    for i in range(total_index):
      temp = []
      for j in range(self.total_word):
        start = i * self.word_length + j * self.byte_length
        end = start + self.byte_length
        temp.append(root_key[start: end])
      root_words.append(temp)

    return root_words

  def print_word(self, word):
    for byte in word:
      print(byte.get_bitvector_in_hex(), end=" ")
    print()

  def print_keys(self, keys=None):
    if(keys is None):
      keys = self.encryption_keys
    round = 0
    for i, key in enumerate(keys):
      if i % 4 == 0:
        if(i != 0):
          print()
        print("Round " + str(round) + ":", end=" ")
        round += 1
      for byte in key:
        print(byte.get_bitvector_in_hex().upper(), end=" ")

  def calculate_expanded_keys(self):
    rcoli = self.calculate_rcoli()

    root_keys = self.create_root_key()
    expanded_keys = []

    for i in range(4 * self.total_rounds):
      if i < self.total_word:
        expanded_keys.append(root_keys[i])
      elif i % self.total_word == 0:
        temp1 = self.sub_word(self.rotate_word_left(expanded_keys[i-1]))
        temp2 = self.xor_words(rcoli[int(i/self.total_word) - 1], temp1)
        expanded_keys.append(self.xor_words(
            temp2, expanded_keys[i-self.total_word]))
      elif self.total_word > 6 and i % self.total_word == 4:
        temp1 = self.sub_word(expanded_keys[i-1])
        temp2 = self.xor_words(expanded_keys[i-self.total_word], temp1)
        expanded_keys.append(temp2)
      else:
        expanded_keys.append(self.xor_words(
            expanded_keys[i-1], expanded_keys[i-self.total_word]))
      # print_word(expanded_keys[i])
    self.encryption_keys = expanded_keys
    return expanded_keys


class State:
  def __init__(self, row: int, col: int) -> None:
    self.row = row
    self.col = col
    self.matrix = None

  def generate_initial_matrix(self):
    self.matrix = [None] * self.row
    for i in range(self.row):
      self.matrix[i] = [None] * self.col
      for j in range(self.col):
        self.matrix[i][j] = BitVector(intVal=0, size=8)
    return self.matrix

  def get_Matrix(self) -> List[List[BitVector]]:
    return self.matrix

  def generate_from_vector(self, vector: BitVector) -> None:
    self.matrix = [None] * self.row
    hex_str = vector.get_bitvector_in_hex()
    k = 0
    for i in range(self.row):
      self.matrix[i] = [None] * self.col

    for i in range(self.row):
      for j in range(self.col):
        self.matrix[j][i] = BitVector(intVal=int(hex_str[k: k+2], 16), size=8)
        k += 2
    return self.matrix

  def generate_from_list(self, list: List[List[BitVector]]) -> None:
    self.matrix = [None] * self.row
    for i in range(self.row):
      self.matrix[i] = [None] * self.col

    for i in range(self.row):
      for j in range(self.col):
        self.matrix[j][i] = list[i][j].deep_copy()
    return self.matrix

  def __str__(self) -> str:
    str = ""
    for row in self.matrix:
      for col in row:
        str += col.get_bitvector_in_hex() + " "
      str += '\n'
    return str

  def get_hexstr(self) -> str:
    str = ""
    for i in range(self.col):
      for j in range(self.row):
        str += self.matrix[j][i].get_bitvector_in_hex()
    return str
  
  def get_ascii_str(self) -> str:
    str = ""
    for i in range(self.col):
      for j in range(self.row):
        str += self.matrix[j][i].get_bitvector_in_ascii()
    return str


class Matrix:
  def __init__(self) -> None:
      pass

  @staticmethod
  def xor(a: State, b: State) -> State:
    assert a.row == b.row and a.col == b.col
    result = State(a.row, a.col)
    result.matrix = [None] * result.row
    for i in range(a.row):
      result.matrix[i] = [None] * result.col
      for j in range(b.col):
        result.matrix[i][j] = a.get_Matrix()[i][j] ^ b.get_Matrix()[i][j]

    return result

  @staticmethod
  def multiply(a: State, b: State) -> State:
    assert a.col == b.row

    row = a.row
    col = b.col
    result_state = State(row, col)
    result_state.generate_initial_matrix()
    for i in range(row):
      for j in range(col):
        for k in range(a.col):
          result_state.get_Matrix()[i][j] ^= a.get_Matrix()[i][k].gf_multiply_modular(
              b.get_Matrix()[k][j], AES_modulus, 8)

    return result_state


class AES:

  def __init__(self, plain_text: str, keySchedule: AESKeySchedule, is_object=False) -> None:
    self.plain_text = plain_text
    self.keySchedule = keySchedule
    self.slice_length = 128
    self.round_keys = []
    self.mix_state = State(4, 4)
    self.mix_state.matrix = mixer
    self.inverse_mix_state = State(4, 4)
    self.inverse_mix_state.matrix = inv_mixer
    self.cypher_states = []
    self.decypher_states = []
    self.is_object = is_object
    self._organize_round_keys()

  def _pad_plain_text(self):
    total_chars = int(self.slice_length / 8)
    if(len(self.plain_text) % total_chars != 0):
      for i in range(total_chars - len(self.plain_text) % total_chars):
        self.plain_text += " "

  def _organize_round_keys(self):
    i = 0
    keys = self.keySchedule.get_encryption_keys()
    total_keys = self.keySchedule.total_rounds
    self.round_keys = [None] * total_keys
    for i in range(total_keys):
      self.round_keys[i] = keys[i*4: i*4+4]

  def slice_plain_text(self) -> List[BitVector]:
    self._pad_plain_text()
    vector = BitVector(textstring=self.plain_text)
    vectors = []
    # print(vector.size)
    total_index = ceil(vector.size / self.slice_length)

    for i in range(total_index):
      start = i * self.slice_length
      end = start + self.slice_length
      vectors.append(vector[start: end])

    return vectors
  
  def slice_file(self) -> List[BitVector]:
    bv = BitVector(filename=self.plain_text)
    vectors = []
    i = 0
    while True:
      vectors.append(bv.read_bits_from_file(self.slice_length))
      if vectors[i].size < self.slice_length:
        if vectors[i].size == 0:
          vectors.pop()
        else:
          textstr = vectors[i].get_bitvector_in_ascii()
          self.total_padded_space = int(self.slice_length / 8) - len(textstr)
          for _ in range(self.total_padded_space):
            textstr += " "
          vectors[i] = BitVector(textstring=textstr)
        break
      i += 1
    bv.close_file_object()
    return vectors

  def create_deciphered_file(self):
    textstr = ""
    for state in self.decypher_states:
      textstr += state.get_ascii_str()
    textstr = textstr[: len(textstr) - self.total_padded_space]

    bv = BitVector(textstring=textstr)
    file = open("deciphered_"+self.plain_text, 'wb')
    bv.write_to_file(file)
    file.close()

  def add_round_key(self, current_state: State, round_no) -> State:
    key_state = State(4, 4)
    key_state.generate_from_list(self.round_keys[round_no])
    return Matrix.xor(current_state, key_state)

  def _get_sval(self, hex_val) -> int:
    return sbox[int(hex_val[0], 16) * 16 + int(hex_val[1], 16)]

  def _get_inverse_sval(self, hex_val) -> int:
    return inv_sbox[int(hex_val[0], 16) * 16 + int(hex_val[1], 16)]

  def _sub_word(self, word: List[BitVector], inverse) -> List[BitVector]:
    new_word = [None] * len(word)
    for i in range(len(word)):
      if not inverse:
        new_word[i] = BitVector(intVal=self._get_sval(
            word[i].get_bitvector_in_hex()), size=8)
      else:
        new_word[i] = BitVector(intVal=self._get_inverse_sval(
            word[i].get_bitvector_in_hex()), size=8)

    return new_word

  def substitute_bytes(self, current_state: State, inverse=False) -> State:
    new_state = State(current_state.row, current_state.col)
    new_state.matrix = [None] * new_state.row
    for i in range(current_state.row):
      new_state.matrix[i] = self._sub_word(
          current_state.get_Matrix()[i], inverse)
    return new_state

  def _shift_i_left_row(self, row: List[BitVector], i):
    new_row = [None] * len(row)
    for j in range(len(row)):
      new_row[j-i] = row[j]
    return new_row

  def _shift_i_right_row(self, row: List[BitVector], i):
    new_row = [None] * len(row)
    for j in range(len(row)):
      new_row[(j+i) % len(row)] = row[j]
    return new_row

  def shift_rows(self, current_state: State, left=True) -> State:
    new_state = State(current_state.row, current_state.col)
    new_state.matrix = [None] * new_state.row

    for i in range(0, current_state.row):
      if left:
        new_state.matrix[i] = self._shift_i_left_row(
            current_state.get_Matrix()[i], i)
      else:
        new_state.matrix[i] = self._shift_i_right_row(
            current_state.matrix[i], i)

    return new_state

  def mix_column(self, current_state: State, inverse=False) -> State:
    if not inverse:
      return Matrix.multiply(self.mix_state, current_state)
    else:
      return Matrix.multiply(self.inverse_mix_state, current_state)

  def perform_encrypt_round(self, current_state: State, round_no: int) -> State:
    new_state = self.substitute_bytes(current_state)
    new_state = self.shift_rows(new_state)
    if self.keySchedule.total_rounds-1 != round_no:
      new_state = self.mix_column(new_state)
    new_state = self.add_round_key(new_state, round_no)
    return new_state

  def perform_decrypt_round(self, current_state: State, round_no: int) -> State:
    new_state = self.shift_rows(current_state, left=False)
    new_state = self.substitute_bytes(new_state, inverse=True)
    new_state = self.add_round_key(new_state, round_no)
    if round_no != 0:
      new_state = self.mix_column(new_state, inverse=True)
    return new_state

  def print_cypher(self):
    print("Cipher Text:")
    for i in range(len(self.cypher_states)):
      print(self.cypher_states[i].get_hexstr() + " [In HEX]")
      print(self.cypher_states[i].get_ascii_str() + " [In ASCII]")

  def print_decypher(self):
    print("Deciphered Text:")
    for i in range(len(self.decypher_states)):
      print(self.decypher_states[i].get_hexstr() + " [In HEX]")
      print(self.decypher_states[i].get_ascii_str() + " [In ASCII]")

  def encrypt(self):
    vectors = None
    if not self.is_object:
      vectors = self.slice_plain_text()
    else:
      vectors = self.slice_file()

    for vector in vectors:
      current_state = State(4, 4)
      current_state.generate_from_vector(vector)
      current_state = self.add_round_key(current_state, 0)
      total_rounds = self.keySchedule.total_rounds
      for i in range(1, total_rounds):
        current_state = self.perform_encrypt_round(current_state, i)
      self.cypher_states.append(current_state)
      # print(current_state)

  def decrypt(self):
    for current_state in self.cypher_states:
      current_key = self.keySchedule.total_rounds-1
      current_state = self.add_round_key(current_state, current_key)
      for i in range(current_key-1, -1, -1):
        current_state = self.perform_decrypt_round(current_state, i)
      self.decypher_states.append(current_state)

  def test(self):
    state_b = State(4, 4)
    state_b.matrix = [
        [BitVector(hexstring="63"), BitVector(hexstring="EB"),
         BitVector(hexstring="9F"), BitVector(hexstring="A0")],
        [BitVector(hexstring="2F"), BitVector(hexstring="93"),
         BitVector(hexstring="92"), BitVector(hexstring="C0")],
        [BitVector(hexstring="AF"), BitVector(hexstring="C7"),
         BitVector(hexstring="AB"), BitVector(hexstring="30")],
        [BitVector(hexstring="A2"), BitVector(hexstring="20"),
         BitVector(hexstring="CB"), BitVector(hexstring="2B")],
    ]
    current_state = Matrix.multiply(self.mix_state, state_b)
    print(current_state)

    state_c = State(4, 4)
    state_c.matrix = [
        [BitVector(hexstring="e2"), BitVector(hexstring="91"),
         BitVector(hexstring="b1"), BitVector(hexstring="d6")],
        [BitVector(hexstring="32"), BitVector(hexstring="12"),
         BitVector(hexstring="59"), BitVector(hexstring="79")],
        [BitVector(hexstring="fc"), BitVector(hexstring="91"),
         BitVector(hexstring="e4"), BitVector(hexstring="a2")],
        [BitVector(hexstring="f1"), BitVector(hexstring="88"),
         BitVector(hexstring="e6"), BitVector(hexstring="93")],
    ]

    current_state = Matrix.xor(current_state, state_c)
    print(current_state)

    current_state = self.substitute_bytes(current_state)
    print(current_state)

    current_state = self.shift_rows(current_state, False)
    print(current_state)

    current_state = self.mix_column(current_state)
    print(current_state)


def rotate_left(val, rotate, max_bits=8):
  return (val << rotate % max_bits) & (2 ** max_bits - 1) \
      | ((val & (2 ** max_bits - 1)) >> (max_bits - (rotate % max_bits)))


def calculate_sbox_inverse_sbox():
  p = 1
  q = 1

  sbox = [None] * 256
  inverse_sbox = [None] * 256

  for i in range(1, 256):
    b = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8)
    b = b.intValue()

    s = b ^ rotate_left(b, 1) ^ rotate_left(b, 2) ^ \
        rotate_left(b, 3) ^ rotate_left(b, 4) ^ 0x63

    sbox[i] = s
    # print(sbox[p])
    inverse_sbox[s] = i

  sbox[0] = 0x63
  inverse_sbox[0x63] = 0

  return sbox, inverse_sbox

def main():
  plain_text = input()
  encryption_key = input()

  # scheduling
  schedule_time = time()
  schedule = AESKeySchedule(encryption_key, 4, 11, 128)
  schedule_time = time() - schedule_time

  aes = AES(plain_text, schedule, True)
  # aes.test()
  #  encryption
  encryption_time = time()
  aes.encrypt()
  encryption_time = time() - encryption_time

  # decryption
  decryption_time = time()
  aes.decrypt()
  decryption_time = time() - decryption_time

  # information
  print("Plain Text:")
  print(plain_text + " [In ASCII]")
  print(BitVector(textstring=plain_text).get_bitvector_in_hex() + " [In HEX]")
  print()
  print("Key:")
  print(schedule.modified_key.get_bitvector_in_ascii() + " [In ASCII]")
  print(schedule.modified_key.get_bitvector_in_hex() + " [In HEX]")
  print()
  aes.print_cypher()
  print()
  aes.print_decypher()

  print("Execution Time")
  print("Key Scheduling: " + str(schedule_time))
  print("Encryption Time: " + str(encryption_time))
  print("Decryption Time: " + str(decryption_time))

  aes.create_deciphered_file()


if __name__ == '__main__':
  sbox, inv_sbox =  calculate_sbox_inverse_sbox()
  main()
