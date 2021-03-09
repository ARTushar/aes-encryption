from constants import *
from math import ceil
from typing import List


class EncryptionKeyGeneration:

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


def slice_plain_text(plain_text: str, slice_length=128) -> List[BitVector]:
  vector = BitVector(textstring=plain_text)
  vectors = []
  # print(vector.size)
  total_index = ceil(vector.size / slice_length)

  for i in range(total_index):
    upto = i * slice_length + slice_length
    if upto > vector.size:
      upto = vector.size
    # print(upto, i)
    vectors.append(vector[i * slice_length: upto])

  if total_index != vector.size / slice_length:
    vectors[total_index -
            1].pad_from_right(slice_length-vectors[total_index-1].size)

  return vectors


def main():
  plain_text = input()
  encryption_key = input()
  vectors = slice_plain_text(plain_text=encryption_key)
  # for vect in vectors:
  # print(vect.get_bitvector_in_hex())
  encryptionMechanism = EncryptionKeyGeneration(encryption_key, 4, 11, 128)
  encryptionMechanism.print_keys()


if __name__ == '__main__':
  main()
