from operator import xor
from constants import *
from math import ceil
from typing import List


class AESKeySchedule:

  def __init__(self, key: str, total_word: int, total_rounds: int, max_key_length: int) -> None:
    self.total_word = total_word
    self.max_key_length = max_key_length
    self.total_rounds = total_rounds
    self.key = key
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
      for j in range(self.col):
        self.matrix[j][i] = BitVector(intVal=int(hex_str[k: k+2], 16), size=8)
        k += 2
    return self.matrix
  
  def generate_from_list(self, list: List[List[BitVector]]) -> None:
    self.matrix = [None] * self.row
    k = 0
    for i in range(self.row):
      self.matrix[i] = [None] * self.col
      for j in range(self.col):
        self.matrix[j][i] = list[i][j].deep_copy()
    return self.matrix


class Matrix:
  def __init__(self) -> None:
      pass

  @staticmethod
  def xor(a: State, b: State) -> State:
    assert a.row == b.row and a.col == b.col
    result = [None] * a.row
    for i in range(a.row):
      result[i] = [None] * a.col
      for j in range(b.col):
        result[i][j] = a.get_Matrix()[i][j] ^ b.get_Matrix()[i][j]

    return result

  @staticmethod
  def multiply(a: State, b: State) -> State:
    assert a.col == b.row

    row = a.row
    col = b.col
    result_state = State(row, col)
    result_state.generate_initial_matrix()
    for i in range(row):
      for j in col:
        for k in range(a.col):
          result_state.get_Matrix[i][j] ^= a.get_Matrix()[i][k].gf_multiply_modular(
              b.get_Matrix()[k][j], AES_modulus, 8)

    return result_state


class AES:

  def __init__(self, plain_text: str, keySchedule: AESKeySchedule) -> None:
    self.plain_text = plain_text
    self.keySchedule = keySchedule
    self.slice_length = 128
    self.round_keys = []
    self.mix_state = State(4, 4)
    self.mix_state.matrix = mixer

    self._pad_plain_text()
    self._organize_round_keys()

  def _pad_plain_text(self):
    total_chars = self.slice_length / 8
    if(len(self.plain_text) % total_chars != 0):
      for i in range(total_chars - len(self.plain_text) % total_chars):
        self.plain_text += " "
  
  def _organize_round_keys(self):
    i = 0
    keys = self.keySchedule.get_encryption_keys()
    total_keys = self.keySchedule.total_rounds
    self.round_keys = [None] * total_keys
    for i in range(total_keys):
      self.round_keys.append(keys[i*4: i*4+4])

  def slice_plain_text(self) -> List[BitVector]:
    vector = BitVector(textstring=self.plain_text)
    vectors = []
    # print(vector.size)
    total_index = ceil(vector.size / self.slice_length)

    for i in range(total_index):
      start = i * self.slice_length
      end = start + self.slice_length
      vectors.append(vector[start: end])

    return vectors
  
  def add_round_key(self, current_state: State, round_no) -> State:
    key_state = State(4, 4)
    key_state.generate_from_list(self.round_keys[round_no])
    return Matrix.xor(current_state, key_state)

  def substitute_bytes(self, current_state: State) -> State:
    new_state = State(current_state.row, current_state.col)
    new_state.matrix = [None] * new_state.row
    for i in range(current_state.row):
      new_state.matrix[i] = self.keySchedule.sub_word(current_state.get_Matrix[i])
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

  def shift_rows(self, current_state: State) -> State:
    new_state = State(current_state.row, current_state.col)
    new_state.matrix = [None] * new_state.row

    for i in range(1, current_state.row):
      new_state.matrix[i] = self._shift_i_left_row(
          current_state.get_Matrix[i], i)

    return new_state

  def mix_column(self, current_state: State) -> State:
    return Matrix.multiply(self.mix_column, current_state)

  def perform_common_encrypt_round(self, current_state: State, round_no: int) -> State:
    new_state = self.substitute_bytes(current_state)
    new_state = self.shift_rows(new_state)
    new_state = self.mix_column(new_state)
    new_state = self.add_round_key(new_state, round_no)
    return new_state

  def perform_last_encrypt_round(self, current_state: State, round_no: int) -> State:
    new_state = self.substitute_bytes(current_state)
    new_state = self.shift_rows(new_state)
    new_state = self.add_round_key(new_state, round_no)
    return new_state

  def encrypt(self):
    vectors = self.slice_plain_text()
    for vector in vectors:
      current_state = State(4, 4)
      current_state.generate_from_vector(vector)
      current_state = self.add_round_key(current_state, 0)
      total_rounds = self.keySchedule.total_rounds
      for i in range(1, total_rounds-1):
        current_state = self.perform_common_encrypt_round(current_state, i)
      current_state = self.perform_last_encrypt_round(total_rounds-1)


def main():
  plain_text = input()
  encryption_key = input()
  vectors = slice_plain_text(plain_text=encryption_key)
  # for vect in vectors:
  # print(vect.get_bitvector_in_hex())
  encryptionMechanism = AESKeySchedule(encryption_key, 4, 11, 128)
  encryptionMechanism.print_keys()


if __name__ == '__main__':
  main()
