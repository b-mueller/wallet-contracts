pragma solidity ^0.6.8;
pragma experimental ABIEncoderV2;


abstract contract IModuleAuth {
  /**
   * @notice Hashed _data to be signed
   * @param _data Data to be hashed
   * @return hashed data for this wallet
   */
  function _hashData(
    bytes memory _data
  ) internal virtual view returns (bytes32);

  /**
   * @notice Verify if signer is default wallet owner
   * @param _hash Hashed signed message
   * @param _signature Encoded signature
   * @return True is the signature is valid
   */
  function _signatureValidation(
    bytes32 _hash,
    bytes memory _signature
  ) internal virtual view returns (bool);
}

interface  IERC1271Wallet {

  /**
   * @notice Verifies whether the provided signature is valid with respect to the provided data
   * @dev MUST return the correct magic value if the signature provided is valid for the provided data
   *   > The bytes4 magic value to return when signature is valid is 0x20c13b0b : bytes4(keccak256("isValidSignature(bytes,bytes)")
   *   > This function MAY modify Ethereum's state
   * @param _data       Arbitrary length data signed on the behalf of address(this)
   * @param _signature  Signature byte array associated with _data
   * @return magicValue Magic value 0x20c13b0b if the signature is valid and 0x0 otherwise
   */
  function isValidSignature(
    bytes calldata _data,
    bytes calldata _signature)
    external
    view
    returns (bytes4 magicValue);

  /**
   * @notice Verifies whether the provided signature is valid with respect to the provided hash
   * @dev MUST return the correct magic value if the signature provided is valid for the provided hash
   *   > The bytes4 magic value to return when signature is valid is 0x20c13b0b : bytes4(keccak256("isValidSignature(bytes,bytes)")
   *   > This function MAY modify Ethereum's state
   * @param _hash       keccak256 hash that was signed
   * @param _signature  Signature byte array associated with _data
   * @return magicValue Magic value 0x20c13b0b if the signature is valid and 0x0 otherwise
   */
  function isValidSignature(
    bytes32 _hash,
    bytes calldata _signature)
    external
    view
    returns (bytes4 magicValue);
}/*
  Copyright 2018 ZeroEx Intl.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  This is a truncated version of the original LibBytes.sol library from ZeroEx.
*/



library LibBytes {
  using LibBytes for bytes;

  /***********************************|
  |        Pop Bytes Functions        |
  |__________________________________*/

  /**
   * @dev Pops the last byte off of a byte array by modifying its length.
   * @param b Byte array that will be modified.
   * @return result The byte that was popped off.
   */
  function popLastByte(bytes memory b)
    internal
    pure
    returns (bytes1 result)
  {
    require(
      b.length > 0,
      "LibBytes#popLastByte: GREATER_THAN_ZERO_LENGTH_REQUIRED"
    );

    // Store last byte.
    result = b[b.length - 1];

    assembly {
      // Decrement length of byte array.
      let newLen := sub(mload(b), 1)
      mstore(b, newLen)
    }
    return result;
  }


  /***********************************|
  |        Read Bytes Functions       |
  |__________________________________*/

  /**
   * @dev Read firsts uint16 value.
   * @param data Byte array to be read.
   * @return a uint16 value of data at index zero.
   * @return newIndex Updated index after reading the values.
   */
  function readFirstUint16(
    bytes memory data
  ) internal pure returns (
    uint16 a,
    uint256 newIndex
  ) {
    assembly {
      let word := mload(add(32, data))
      a := shr(240, word)
      newIndex := 2
    }
    require(2 <= data.length, "LibBytes#readFirstUint16: OUT_OF_BOUNDS");
  }

  /**
   * @dev Reads consecutive bool (8 bits) and uint8 values.
   * @param data Byte array to be read.
   * @param index Index in byte array of uint8 and uint8 values.
   * @return a uint8 value of data at given index.
   * @return b uint8 value of data at given index + 8.
   * @return newIndex Updated index after reading the values.
   */
  function readUint8Uint8(
    bytes memory data,
    uint256 index
  ) internal pure returns (
    uint8 a,
    uint8 b,
    uint256 newIndex
  ) {
    assembly {
      let word := mload(add(index, add(32, data)))
      a := shr(248, word)
      b := and(shr(240, word), 0xff)
      newIndex := add(index, 2)
    }
    require(newIndex <= data.length, "LibBytes#readUint8Uint8: OUT_OF_BOUNDS");
  }

  /**
   * @dev Reads an address value from a position in a byte array.
   * @param data Byte array to be read.
   * @param index Index in byte array of address value.
   * @return a address value of data at given index.
   * @return newIndex Updated index after reading the value.
   */
  function readAddress(
    bytes memory data,
    uint256 index
  ) internal pure returns (
    address a,
    uint256 newIndex
  ) {
    assembly {
      let word := mload(add(index, add(32, data)))
      a := and(shr(96, word), 0xffffffffffffffffffffffffffffffffffffffff)
      newIndex := add(index, 20)
    }
    require(newIndex <= data.length, "LibBytes#readAddress: OUT_OF_BOUNDS");
  }

  /**
   * @dev Reads 66 bytes from a position in a byte array.
   * @param data Byte array to be read.
   * @param index Index in byte array of 66 bytes value.
   * @return a 66 bytes bytes array value of data at given index.
   * @return newIndex Updated index after reading the value.
   */
  function readBytes66(
    bytes memory data,
    uint256 index
  ) internal pure returns (
    bytes memory a,
    uint256 newIndex
  ) {
    a = new bytes(66);
    assembly {
      let offset := add(32, add(data, index))
      mstore(add(a, 32), mload(offset))
      mstore(add(a, 64), mload(add(offset, 32)))
      mstore(add(a, 66), mload(add(offset, 34)))
      newIndex := add(index, 66)
    }
    require(newIndex <= data.length, "LibBytes#readBytes66: OUT_OF_BOUNDS");
  }

  /**
   * @dev Reads a bytes32 value from a position in a byte array.
   * @param b Byte array containing a bytes32 value.
   * @param index Index in byte array of bytes32 value.
   * @return result bytes32 value from byte array.
   */
  function readBytes32(
    bytes memory b,
    uint256 index
  )
    internal
    pure
    returns (bytes32 result)
  {
    require(
      b.length >= index + 32,
      "LibBytes#readBytes32: GREATER_OR_EQUAL_TO_32_LENGTH_REQUIRED"
    );

    // Arrays are prefixed by a 256 bit length parameter
    uint256 pos = index + 32;

    // Read the bytes32 from array memory
    assembly {
      result := mload(add(b, pos))
    }
    return result;
  }
}


abstract contract ModuleERC165 {
  /**
   * @notice Query if a contract implements an interface
   * @param _interfaceID The interface identifier, as specified in ERC-165
   * @return `true` if the contract implements `_interfaceID`
   */
  function supportsInterface(bytes4 _interfaceID) virtual public pure returns (bool) {
    return _interfaceID == this.supportsInterface.selector;
  }
}


contract ModuleSelfAuth {
  modifier onlySelf() {
    require(msg.sender == address(this), "ModuleSelfAuth#onlySelf: NOT_AUTHORIZED");
    _;
  }
}



interface IModuleCreator {
  /**
   * @notice Creates a contract forwarding eth value
   * @param _code Creation code of the contract
   * @return addr The address of the created contract
   */
  function createContract(bytes calldata _code) external payable returns (address addr);
}



library LibAddress {
  function isContract(address account) internal view returns (bool) {
    uint256 csize;
    // solhint-disable-next-line no-inline-assembly
    assembly { csize := extcodesize(account) }
    return csize != 0;
  }
}

/**
 * @dev Allows modules to access the implementation slot
 */
contract Implementation {
  /**
   * @notice Updates the Wallet implementation
   * @param _imp New implementation address
   * @dev The wallet implementation is stored on the storage slot
   *   defined by the address of the wallet itself
   *   WARNING updating this value may brick the wallet
   */
  function _setImplementation(address _imp) internal {
    assembly {
      sstore(address(), _imp)
    }
  }

  /**
   * @notice Returns the Wallet implementation
   * @return _imp The address of the current Wallet implementation
   */
  function _getImplementation() internal view returns (address _imp) {
    assembly {
      _imp := sload(address())
    }
  }
}



interface IModuleUpdate {
  /**
   * @notice Updates the implementation of the base wallet
   * @param _implementation New main module implementation
   * @dev WARNING Updating the implementation can brick the wallet
   */
  function updateImplementation(address _implementation) external;
}

library ModuleStorage {

  // MYTHX INSTRUMENTATION

  function writeBytes32(bytes32 _key, bytes32 _val) internal {
    assembly { sstore(_key, _val) }
  }

  function readBytes32(bytes32 _key) internal view returns (bytes32 val) {
    assembly { val := sload(_key) }
  }

  function writeBytes32Map(bytes32 _key, bytes32 _subKey, bytes32 _val) internal {
    bytes32 key = keccak256(abi.encode(_key, _subKey));
    assembly { sstore(key, _val) }
  }

  function readBytes32Map(bytes32 _key, bytes32 _subKey) internal view returns (bytes32 val) {
    bytes32 key = keccak256(abi.encode(_key, _subKey));
    assembly { val := sload(key) }
  }
}



interface IERC223Receiver {
  function tokenFallback(address, uint256, bytes calldata) external;
}



interface IERC721Receiver {
  function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
}



interface IERC1155Receiver {
  function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4);
  function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external returns (bytes4);
}



interface IModuleHooks {
  /**
   * @notice Reads the implementation hook of a signature
   * @param _signature Signature function
   * @return The address of the implementation hook, address(0) if none
  */
  function readHook(bytes4 _signature) external view returns (address);

  /**
   * @notice Adds a new hook to handle a given function selector
   * @param _signature Signature function linked to the hook
   * @param _implementation Hook implementation contract
   */
  function addHook(bytes4 _signature, address _implementation) external;

  /**
   * @notice Removes a registered hook
   * @param _signature Signature function linked to the hook
   */
  function removeHook(bytes4 _signature) external;
}


/**
    Minimal upgradeable proxy implementation, delegates all calls to the address
    defined by the storage slot matching the wallet address.

    Inspired by EIP-1167 Implementation (https://eips.ethereum.org/EIPS/eip-1167)

    deployed code:

        0x00    0x36         0x36      CALLDATASIZE      cds
        0x01    0x3d         0x3d      RETURNDATASIZE    0 cds
        0x02    0x3d         0x3d      RETURNDATASIZE    0 0 cds
        0x03    0x37         0x37      CALLDATACOPY
        0x04    0x3d         0x3d      RETURNDATASIZE    0
        0x05    0x3d         0x3d      RETURNDATASIZE    0 0
        0x06    0x3d         0x3d      RETURNDATASIZE    0 0 0
        0x07    0x36         0x36      CALLDATASIZE      cds 0 0 0
        0x08    0x3d         0x3d      RETURNDATASIZE    0 cds 0 0 0
        0x09    0x30         0x30      ADDRESS           addr 0 cds 0 0 0
        0x0A    0x54         0x54      SLOAD             imp 0 cds 0 0 0
        0x0B    0x5a         0x5a      GAS               gas imp 0 cds 0 0 0
        0x0C    0xf4         0xf4      DELEGATECALL      suc 0
        0x0D    0x3d         0x3d      RETURNDATASIZE    rds suc 0
        0x0E    0x82         0x82      DUP3              0 rds suc 0
        0x0F    0x80         0x80      DUP1              0 0 rds suc 0
        0x10    0x3e         0x3e      RETURNDATACOPY    suc 0
        0x11    0x90         0x90      SWAP1             0 suc
        0x12    0x3d         0x3d      RETURNDATASIZE    rds 0 suc
        0x13    0x91         0x91      SWAP2             suc 0 rds
        0x14    0x60 0x18    0x6018    PUSH1             0x18 suc 0 rds
    /-- 0x16    0x57         0x57      JUMPI             0 rds
    |   0x17    0xfd         0xfd      REVERT
    \-> 0x18    0x5b         0x5b      JUMPDEST          0 rds
        0x19    0xf3         0xf3      RETURN

    flat deployed code: 0x363d3d373d3d3d363d30545af43d82803e903d91601857fd5bf3

    deploy function:

        0x00    0x60 0x3a    0x603a    PUSH1             0x3a
        0x02    0x60 0x0e    0x600e    PUSH1             0x0e 0x3a
        0x04    0x3d         0x3d      RETURNDATASIZE    0 0x0e 0x3a
        0x05    0x39         0x39      CODECOPY
        0x06    0x60 0x1a    0x601a    PUSH1             0x1a
        0x08    0x80         0x80      DUP1              0x1a 0x1a
        0x09    0x51         0x51      MLOAD             imp 0x1a
        0x0A    0x30         0x30      ADDRESS           addr imp 0x1a
        0x0B    0x55         0x55      SSTORE            0x1a
        0x0C    0x3d         0x3d      RETURNDATASIZE    0 0x1a
        0x0D    0xf3         0xf3      RETURN
        [...deployed code]

    flat deploy function: 0x603a600e3d39601a805130553df3363d3d373d3d3d363d30545af43d82803e903d91601857fd5bf3
*/
library Wallet {
  bytes internal constant creationCode = hex"603a600e3d39601a805130553df3363d3d373d3d3d363d30545af43d82803e903d91601857fd5bf3";
}



/**
 * @dev Contains logic for signature validation.
 * Signatures from wallet contracts assume ERC-1271 support (https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1271.md)
 * Notes: Methods are strongly inspired by contracts in https://github.com/0xProject/0x-monorepo/blob/development/
 */
contract SignatureValidator {
  using LibBytes for bytes;

  /***********************************|
  |             Variables             |
  |__________________________________*/

  // bytes4(keccak256("isValidSignature(bytes,bytes)"))
  bytes4 constant internal ERC1271_MAGICVALUE = 0x20c13b0b;

  // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
  bytes4 constant internal ERC1271_MAGICVALUE_BYTES32 = 0x1626ba7e;

  // Allowed signature types.
  uint256 private constant SIG_TYPE_EIP712 = 1;
  uint256 private constant SIG_TYPE_ETH_SIGN = 2;

  /***********************************|
  |        Signature Functions        |
  |__________________________________*/

 /**
   * @notice Recover the signer of hash, assuming it's an EOA account
   * @dev Only for SignatureType.EIP712 and SignatureType.EthSign signatures
   * @param _hash      Hash that was signed
   *   encoded as (bytes32 r, bytes32 s, uint8 v, ... , SignatureType sigType)
   */
  function recoverSigner(
    bytes32 _hash,
    bytes memory _signature
  ) internal pure returns (address signer) {
    // Pop last byte off of signature byte array.
    uint256 signatureType = uint8(_signature.popLastByte());

    // Variables are not scoped in Solidity.
    uint8 v = uint8(_signature[64]);
    bytes32 r = _signature.readBytes32(0);
    bytes32 s = _signature.readBytes32(32);

    // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
    // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
    // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
    // signatures from current libraries generate a unique signature with an s-value in the lower half order.
    //
    // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
    // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
    // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
    // these malleable signatures as well.
    //
    // Source OpenZeppelin
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/cryptography/ECDSA.sol

    if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
      revert("SignatureValidator#recoverSigner: invalid signature 's' value");
    }

    if (v != 27 && v != 28) {
      revert("SignatureValidator#recoverSigner: invalid signature 'v' value");
    }

    // Signature using EIP712
    if (signatureType == SIG_TYPE_EIP712) {
      signer = ecrecover(_hash, v, r, s);

    // Signed using web3.eth_sign() or Ethers wallet.signMessage()
    } else if (signatureType == SIG_TYPE_ETH_SIGN) {
      signer = ecrecover(
        keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash)),
        v,
        r,
        s
      );

    } else {
      // Anything other signature types are illegal (We do not return false because
      // the signature may actually be valid, just not in a format
      // that we currently support. In this case returning false
      // may lead the caller to incorrectly believe that the
      // signature was invalid.)
      revert("SignatureValidator#isValidSignature: UNSUPPORTED_SIGNATURE_TYPE");
    }

    // Prevent signer from being 0x0
    require(
      signer != address(0x0),
      "SignatureValidator#isValidSignature: INVALID_SIGNER"
    );

    return signer;
  }
}



abstract contract ModuleAuth is IModuleAuth, ModuleERC165, SignatureValidator, IERC1271Wallet {
  using LibBytes for bytes;

  uint256 private constant FLAG_SIGNATURE = 0;
  uint256 private constant FLAG_ADDRESS = 1;

  bytes4 private constant SELECTOR_ERC1271_BYTES_BYTES = 0x20c13b0b;
  bytes4 private constant SELECTOR_ERC1271_BYTES32_BYTES = 0x1626ba7e;

  function _signatureValidation(
    bytes32 _hash,
    bytes memory _signature
  )
    internal override view returns (bool)
  {
    // _signatureValidationOriginal(_hash, _signature);

    return true;
  }

  /**
   * @notice Verify if signer is default wallet owner
   * @param _hash       Hashed signed message
   * @param _signature  Array of signatures with signers ordered
   *                    like the the keys in the multisig configs
   *
   * @dev The signature must be solidity packed and contain the total number of owners,
   *      the threshold, the weigth and either the address or a signature for each owner.
   *
   *      Each weight & (address or signature) pair is prefixed by a flag that signals if such pair
   *      contains an address or a signature. The aggregated weight of the signatures must surpass the threshold.
   *
   *      Flag types:
   *        0x00 - Signature
   *        0x01 - Address
   *
   *      E.g:
   *      abi.encodePacked(
   *        uint8 nSigners, uint16 threshold,
   *        uint8 01,  uint8 weight_1, address signer_1,
   *        uint8 00, uint8 weight_2, bytes signature_2,
   *        ...
   *        uint8 01,  uint8 weight_5, address signer_5
   *      )
   */
  function _signatureValidationOriginal(
    bytes32 _hash,
    bytes memory _signature
  )
    internal view returns (bool)
  {
    (
      uint16 threshold,  // required threshold signature
      uint256 rindex     // read index
    ) = _signature.readFirstUint16();

    // Start image hash generation
    bytes32 imageHash = bytes32(uint256(threshold));

    // Acumulated weight of signatures
    uint256 totalWeight;

    // Iterate until the image is completed
    while (rindex < _signature.length) {
      // Read next item type and addrWeight
      uint256 flag; uint256 addrWeight; address addr;
      (flag, addrWeight, rindex) = _signature.readUint8Uint8(rindex);

      if (flag == FLAG_ADDRESS) {
        // Read plain address
        (addr, rindex) = _signature.readAddress(rindex);
      } else if (flag == FLAG_SIGNATURE) {
        // Read single signature and recover signer
        bytes memory signature;
        (signature, rindex) = _signature.readBytes66(rindex);
        addr = recoverSigner(_hash, signature);

        // Acumulate total weight of the signature
        totalWeight += addrWeight;
      } else {
        revert("ModuleAuth#_signatureValidation INVALID_FLAG");
      }

      // Write weight and address to image
      imageHash = keccak256(abi.encode(imageHash, addrWeight, addr));
    }

    return totalWeight >= threshold && _isValidImage(imageHash);
  }

  /**
   * @notice Validates the signature image
   * @param _imageHash Hashed image of signature
   * @return true if the signature image is valid
   */
  function _isValidImage(bytes32 _imageHash) internal virtual view returns (bool);

  /**
   * @notice Will hash _data to be signed (similar to EIP-712)
   * @param _data Data to be hashed
   * @return hashed data for this wallet
   */
  function _hashData(bytes memory _data) internal override view returns (bytes32) {
    uint256 chainId; assembly { chainId := chainid() }
    return keccak256(
      abi.encodePacked(
        "\x19\x01",
        chainId,
        address(this),
        keccak256(_data)
      )
    );
  }

  /**
   * @notice Verifies whether the provided signature is valid with respect to the provided data
   * @dev MUST return the correct magic value if the signature provided is valid for the provided data
   *   > The bytes4 magic value to return when signature is valid is 0x20c13b0b : bytes4(keccak256("isValidSignature(bytes,bytes)"))
   * @param _data       Arbitrary length data signed on the behalf of address(this)
   * @param _signatures Signature byte array associated with _data.
   *                    Encoded as abi.encode(Signature[], Configs)
   * @return magicValue Magic value 0x20c13b0b if the signature is valid and 0x0 otherwise
   */
  function isValidSignature(
    bytes calldata _data,
    bytes calldata _signatures
  ) external override view returns (bytes4) {
    // Validate signatures
    if (_signatureValidation(_hashData(_data), _signatures)) {
      return SELECTOR_ERC1271_BYTES_BYTES;
    }
  }

  /**
   * @notice Verifies whether the provided signature is valid with respect to the provided hash
   * @dev MUST return the correct magic value if the signature provided is valid for the provided hash
   *   > The bytes4 magic value to return when signature is valid is 0x1626ba7e : bytes4(keccak256("isValidSignature(bytes32,bytes)"))
   * @param _hash       keccak256 hash that was signed
   * @param _signatures Signature byte array associated with _data.
   *                    Encoded as abi.encode(Signature[], Configs)
   * @return magicValue Magic value 0x1626ba7e if the signature is valid and 0x0 otherwise
   */
  function isValidSignature(
    bytes32 _hash,
    bytes calldata _signatures
  ) external override view returns (bytes4) {
    // Validate signatures
    if (_signatureValidation(_hash, _signatures)) {
      return SELECTOR_ERC1271_BYTES32_BYTES;
    }
  }

  /**
   * @notice Query if a contract implements an interface
   * @param _interfaceID The interface identifier, as specified in ERC-165
   * @return `true` if the contract implements `_interfaceID`
   */
  function supportsInterface(bytes4 _interfaceID) public override virtual pure returns (bool) {
    if (
      _interfaceID == type(IModuleAuth).interfaceId ||
      _interfaceID == type(IERC1271Wallet).interfaceId
    ) {
      return true;
    }

    return super.supportsInterface(_interfaceID);
  }
}



/**
 *  Implements ModuleAuth by validating the signature image against
 *  the salt used to deploy the contract
 *
 *  This module allows wallets to be deployed with a default configuration
 *  without using any aditional contract storage
 */
abstract contract ModuleAuthFixed is ModuleAuth {
  bytes32 public immutable INIT_CODE_HASH;
  address public immutable FACTORY;

  constructor() public {
    // Build init code hash of the deployed wallets using that module
    // bytes32 initCodeHash = keccak256(abi.encodePacked(Wallet.creationCode, uint256(address(this))));
    bytes32 initCodeHash = bytes32(0x0000000000000000000000000000000000000000000000000000000000000000);

    INIT_CODE_HASH = initCodeHash;
    FACTORY = 0xafFEaFFEAFfeAfFEAffeaFfEAfFEaffeafFeAFfE;
  }

  /**
   * @notice Validates the signature image with the salt used to deploy the contract
   * @param _imageHash Hash image of signature
   * @return true if the signature image is valid
   */
  function _isValidImage(bytes32 _imageHash) internal override view returns (bool) {
    return address(
      uint256(
        keccak256(
          abi.encodePacked(
            byte(0xff),
            FACTORY,
            _imageHash,
            INIT_CODE_HASH
          )
        )
      )
    ) == address(this);
  }
}

abstract contract ModuleHooks is IERC1155Receiver, IERC721Receiver, IModuleHooks, ModuleERC165, ModuleSelfAuth {
  //                       HOOKS_KEY = keccak256("org.arcadeum.module.hooks.hooks");
  bytes32 private constant HOOKS_KEY = bytes32(0xbe27a319efc8734e89e26ba4bc95f5c788584163b959f03fa04e2d7ab4b9a120);

  /**
   * @notice Reads the implementation hook of a signature
   * @param _signature Signature function
   * @return The address of the implementation hook, address(0) if none
  */
  function readHook(bytes4 _signature) external override view returns (address) {
    return _readHook(_signature);
  }

  /**
   * @notice Adds a new hook to handle a given function selector
   * @param _signature Signature function linked to the hook
   * @param _implementation Hook implementation contract
   */
  function _addHook(bytes4 _signature, address _implementation) internal onlySelf {
    require(_readHook(_signature) == address(0), "ModuleHooks#addHook: HOOK_ALREADY_REGISTERED");
    _writeHook(_signature, _implementation);
  }

  /**
   * @notice Removes a registered hook
   * @param _signature Signature function linked to the hook
   */
  function _removeHook(bytes4 _signature) internal onlySelf {
    require(_readHook(_signature) != address(0), "ModuleHooks#removeHook: HOOK_NOT_REGISTERED");
    _writeHook(_signature, address(0));
  }

  /**
   * @notice Reads the implementation hook of a signature
   * @param _signature Signature function
   * @return The address of the implementation hook, address(0) if none
  */
  function _readHook(bytes4 _signature) internal view returns (address) {
    return address(uint256(ModuleStorage.readBytes32Map(HOOKS_KEY, _signature)));
  }

  /**
   * @notice Writes the implementation hook of a signature
   * @param _signature Signature function
   * @param _implementation Hook implementation contract
  */
  function _writeHook(bytes4 _signature, address _implementation) internal {
    ModuleStorage.writeBytes32Map(HOOKS_KEY, _signature, bytes32(uint256(_implementation)));
  }

  /**
   * @notice Handle the receipt of a single ERC1155 token type.
   * @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`
   */
  function onERC1155Received(
    address,
    address,
    uint256,
    uint256,
    bytes calldata
  ) external override returns (bytes4) {
    return ModuleHooks.onERC1155Received.selector;
  }

  /**
   * @notice Handle the receipt of multiple ERC1155 token types.
   * @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`
   */
  function onERC1155BatchReceived(
    address,
    address,
    uint256[] calldata,
    uint256[] calldata,
    bytes calldata
  ) external override returns (bytes4) {
    return ModuleHooks.onERC1155BatchReceived.selector;
  }

  /**
   * @notice Handle the receipt of a single ERC721 token.
   * @return `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`
   */
  function onERC721Received(address, address, uint256, bytes calldata) external override returns (bytes4) {
    return ModuleHooks.onERC721Received.selector;
  }

  function _moduleHooksFallback() internal {
   address target = _readHook(msg.sig);
    if (target != address(0)) {
      (bool success, bytes memory result) = target.delegatecall(msg.data);
      assembly {
        if iszero(success)  {
          revert(add(result, 0x20), mload(result))
        }

        return(add(result, 0x20), mload(result))
      }
    }
  }

  /**
   * @notice Routes fallback calls through hooks
   */
  fallback() external payable {
    _moduleHooksFallback();
  }

  /**
   * @notice Allows the wallet to receive ETH
   */
  receive() external payable { }

  /**
   * @notice Query if a contract implements an interface
   * @param _interfaceID The interface identifier, as specified in ERC-165
   * @return `true` if the contract implements `_interfaceID`
   */
  function supportsInterface(bytes4 _interfaceID) public override virtual pure returns (bool) {
    if (
      _interfaceID == type(IModuleHooks).interfaceId ||
      _interfaceID == type(IERC1155Receiver).interfaceId ||
      _interfaceID == type(IERC721Receiver).interfaceId ||
      _interfaceID == type(IERC223Receiver).interfaceId
    ) {
      return true;
    }

    return super.supportsInterface(_interfaceID);
  }
}

interface IModuleCalls {
  // Events
  event NonceChange(uint256 _space, uint256 _newNonce);
  event TxFailed(bytes32 _tx, bytes _reason);
  event TxExecuted(bytes32 _tx) anonymous;

  // Transaction structure
  struct Transaction {
    bool delegateCall;   // Performs delegatecall
    bool revertOnError;  // Reverts transaction bundle if tx fails
    uint256 gasLimit;    // Maximum gas to be forwarded
    address target;      // Address of the contract to call
    uint256 value;       // Amount of ETH to pass with the call
    bytes data;          // calldata to pass
  }

  /**
   * @notice Returns the next nonce of the default nonce space
   * @dev The default nonce space is 0x00
   * @return The next nonce
   */
  function nonce() external view returns (uint256);

  /**
   * @notice Returns the next nonce of the given nonce space
   * @param _space Nonce space, each space keeps an independent nonce count
   * @return The next nonce
   */
  function readNonce(uint256 _space) external view returns (uint256);

  /**
   * @notice Allow wallet owner to execute an action
   * @param _txs        Transactions to process
   * @param _nonce      Signature nonce (may contain an encoded space)
   * @param _signature  Encoded signature
   */
  function execute(
    Transaction[] calldata _txs,
    uint256 _nonce,
    bytes calldata _signature
  ) external;

  /**
   * @notice Allow wallet to execute an action
   *   without signing the message
   * @param _txs  Transactions to execute
   */
  function selfExecute(
    Transaction[] calldata _txs
  ) external;
}

abstract contract ModuleCalls is IModuleCalls, IModuleAuth, ModuleERC165, ModuleSelfAuth {
  //                       NONCE_KEY = keccak256("org.arcadeum.module.calls.nonce");
  bytes32 private constant NONCE_KEY = bytes32(0x8d0bf1fd623d628c741362c1289948e57b3e2905218c676d3e69abee36d6ae2e);

  uint256 private constant NONCE_BITS = 96;
  bytes32 private constant NONCE_MASK = bytes32((1 << NONCE_BITS) - 1);

  /**
   * @notice Returns the next nonce of the default nonce space
   * @dev The default nonce space is 0x00
   * @return The next nonce
   */
  function nonce() external override view returns (uint256) {
    return readNonce(0);
  }

  /**
   * @notice Returns the next nonce of the given nonce space
   * @param _space Nonce space, each space keeps an independent nonce count
   * @return The next nonce
   */
  function readNonce(uint256 _space) public override view returns (uint256) {
    return uint256(ModuleStorage.readBytes32Map(NONCE_KEY, bytes32(_space)));
  }

  /**
   * @notice Changes the next nonce of th given nonce space
   * @param _space Nonce space, each space keeps an independent nonce count
   * @param _nonce Nonce to write on the space
   */
  function _writeNonce(uint256 _space, uint256 _nonce) private {
    ModuleStorage.writeBytes32Map(NONCE_KEY, bytes32(_space), bytes32(_nonce));
  }

  /**
   * @notice Allow wallet owner to execute an action
   * @param _txs        Transactions to process
   * @param _nonce      Signature nonce (may contain an encoded space)
   * @param _signature  Encoded signature
   */
  function _execute(
    Transaction[] memory _txs,
    uint256 _nonce,
    bytes memory _signature
  ) internal {
    // Validate and update nonce
    _validateNonce(_nonce);

    // Hash transaction bundle
    bytes32 txHash = _hashData(abi.encode(_nonce, _txs));

    // Verify that signatures are valid
    require(
      _signatureValidation(txHash, _signature),
      "MainModule#_signatureValidation: INVALID_SIGNATURE"
    );

    // Execute the transactions
    _execute(txHash, _txs);
  }

  /**
   * @notice Allow wallet to execute an action
   *   without signing the message
   * @param _txs  Transactions to execute
   */
  function _selfExecute(
    Transaction[] memory _txs
  ) internal onlySelf {
    // Hash transaction bundle
    bytes32 txHash = _hashData(abi.encode('self:', _txs));

    // Execute the transactions
    _execute(txHash, _txs);
  }

  /**
   * @notice Executes a list of transactions
   * @param _txHash  Hash of the batch of transactions
   * @param _txs  Transactions to execute
   */
  function _execute(
    bytes32 _txHash,
    Transaction[] memory _txs
  ) private {
    // Execute transaction
    for (uint256 i = 0; i < _txs.length; i++) {
      Transaction memory transaction = _txs[i];

      bool success;
      bytes memory result;

      if (transaction.delegateCall) {
        (success, result) = transaction.target.delegatecall{
          gas: transaction.gasLimit
        }(transaction.data);
      } else {
        (success, result) = transaction.target.call{
          value: transaction.value,
          gas: transaction.gasLimit
        }(transaction.data);
      }

      if (success) {
        emit TxExecuted(_txHash);
      } else {
        _revertBytes(transaction, _txHash, result);
      }
    }
  }

  /**
   * @notice Verify if a nonce is valid
   * @param _rawNonce Nonce to validate (may contain an encoded space)
   * @dev A valid nonce must be above the last one used
   *   with a maximum delta of 100
   */
  function _validateNonce(uint256 _rawNonce) private {
    // Retrieve current nonce for this wallet
    (uint256 space, uint256 providedNonce) = _decodeNonce(_rawNonce);
    uint256 currentNonce = readNonce(space);

    // Verify if nonce is valid
    require(
      providedNonce == currentNonce,
      "MainModule#_auth: INVALID_NONCE"
    );

    // Update signature nonce
    uint256 newNonce = providedNonce + 1;
    _writeNonce(space, newNonce);
    emit NonceChange(space, newNonce);
  }

  /**
   * @notice Logs a failed transaction, reverts if the transaction is not optional
   * @param _tx      Transaction that is reverting
   * @param _txHash  Hash of the transaction
   * @param _reason  Encoded revert message
   */
  function _revertBytes(
    Transaction memory _tx,
    bytes32 _txHash,
    bytes memory _reason
  ) internal {
    if (_tx.revertOnError) {
      assembly { revert(add(_reason, 0x20), mload(_reason)) }
    } else {
      emit TxFailed(_txHash, _reason);
    }
  }

  /**
   * @notice Decodes a raw nonce
   * @dev A raw nonce is encoded using the first 160 bits for the space
   *  and the last 96 bits for the nonce
   * @param _rawNonce Nonce to be decoded
   * @return _space The nonce space of the raw nonce
   * @return _nonce The nonce of the raw nonce
   */
  function _decodeNonce(uint256 _rawNonce) internal pure returns (uint256 _space, uint256 _nonce) {
    _nonce = uint256(bytes32(_rawNonce) & NONCE_MASK);
    _space = _rawNonce >> NONCE_BITS;
  }

  /**
   * @notice Query if a contract implements an interface
   * @param _interfaceID The interface identifier, as specified in ERC-165
   * @return `true` if the contract implements `_interfaceID`
   */
  function supportsInterface(bytes4 _interfaceID) public override virtual pure returns (bool) {
    if (_interfaceID == type(IModuleCalls).interfaceId) {
      return true;
    }

    return super.supportsInterface(_interfaceID);
  }
}


abstract contract ModuleUpdate is IModuleUpdate, ModuleERC165, ModuleSelfAuth, Implementation {
  using LibAddress for address;

  /**
   * @notice Updates the implementation of the base wallet
   * @param _implementation New main module implementation
   * @dev WARNING Updating the implementation can brick the wallet
   */
  function _updateImplementation(address _implementation) internal onlySelf {
    require(_implementation.isContract(), "ModuleUpdate#updateImplementation: INVALID_IMPLEMENTATION");
    _setImplementation(_implementation);
  }

  /**
   * @notice Query if a contract implements an interface
   * @param _interfaceID The interface identifier, as specified in ERC-165
   * @return `true` if the contract implements `_interfaceID`
   */
  function supportsInterface(bytes4 _interfaceID) public override virtual pure returns (bool) {
    if (_interfaceID == type(IModuleUpdate).interfaceId) {
      return true;
    }

    return super.supportsInterface(_interfaceID);
  }
}

abstract contract ModuleCreator is IModuleCreator, ModuleERC165, ModuleSelfAuth {
  event CreatedContract(address _contract);

  /**
   * @notice Creates a contract forwarding eth value
   * @param _code Creation code of the contract
   * @return addr The address of the created contract
   */
  function _createContract(bytes memory _code) internal onlySelf returns (address addr) {
    assembly { addr := create(callvalue(), add(_code, 32), mload(_code)) }
    emit CreatedContract(addr);
  }

  /**
   * @notice Query if a contract implements an interface
   * @param _interfaceID The interface identifier, as specified in ERC-165
   * @return `true` if the contract implements `_interfaceID`
   */
  function supportsInterface(bytes4 _interfaceID) public override virtual pure returns (bool) {
    if (_interfaceID == type(IModuleCreator).interfaceId) {
      return true;
    }

    return super.supportsInterface(_interfaceID);
  }
}


/**
 * Contains the core functionality arcadeum wallets will inherit.
 */
abstract contract MainModule is
  ModuleAuthFixed,
  ModuleCalls,
  ModuleUpdate,
  ModuleHooks,
  ModuleCreator
{

  /**
   * @notice Query if a contract implements an interface
   * @param _interfaceID The interface identifier, as specified in ERC-165
   * @return `true` if the contract implements `_interfaceID`
   */
  function supportsInterface(
    bytes4 _interfaceID
  ) public override(
    ModuleAuth,
    ModuleCalls,
    ModuleUpdate,
    ModuleHooks,
    ModuleCreator
  ) pure returns (bool) {
    return super.supportsInterface(_interfaceID);
  }
}

/**
 * Verification contract
 */
contract MythXVerifySimpleProperties is MainModule {

  event AssertionFailed(string message);

  address MYTHX_FACTORY = 0xafFEaFFEAFfeAfFEAffeaFfEAfFEaffeafFeAFfE;
  bytes32 MYTHX_INIT_CODE_HASH = 0x0000000000000000000000000000000000000000000000000000000000000000;

  bytes4  MYTHX_HOOK_KEY_1;
  bytes4  MYTHX_HOOK_KEY_2;
  address MYTHX_WALLET_ADDRESS;

  address _prev_factory;
  address _prev_implementation;
  address _prev_hook_1;
  address _prev_hook_2;
  

  constructor() public {
    // threshold + weight + address
    MYTHX_HOOK_KEY_1 = 0x00000001;
    MYTHX_HOOK_KEY_2 = 0x00000002;

    _writeHook(MYTHX_HOOK_KEY_1, 0xAaAAAaaAAAAAAaaAAAaaaaAaAaAAAAaAAaAaAaA1);
    _setImplementation(0xAaAaaAAAaAaaAaAaAaaAAaAaAAAAAaAAAaaAaAa2);
  }

  modifier checkInvariants {
      
    _prev_factory = FACTORY; 
    _prev_implementation = _getImplementation();
    _prev_hook_1 = _readHook(MYTHX_HOOK_KEY_1);
    _prev_hook_2 = _readHook(MYTHX_HOOK_KEY_2);
    
    _;

    // Verify safety of state vars

    if (!(_prev_factory == FACTORY)) {
      emit AssertionFailed("[P1] Factory state variable must be constant.");
    }

    if (!(_prev_implementation == _getImplementation() || msg.sender == address(this))) {
      emit AssertionFailed("[P2] Implementation must be constant unless sender is the address of this contract acccount.");
    }

    if (_getImplementation() == address(0)) {
      emit AssertionFailed("[P3] It must not be possible to set the implementation to the zero address.");
    }

    if (!(_readHook(MYTHX_HOOK_KEY_1) == _prev_hook_1 && _readHook(MYTHX_HOOK_KEY_2) == _prev_hook_2)) {
       emit AssertionFailed("[P4] It must not be possible to set or unset a hook unless the sender is this contract account.");
    }

  }

  // Wrap all state-modifying public functions

  // ModuleCalls

  function execute(Transaction[] memory _txs, uint256 _nonce, bytes memory _signature) public override checkInvariants {

    (uint256 space, uint256 _provided_nonce) = _decodeNonce(_nonce);
    uint256 old_nonce = readNonce(space);

    _execute(_txs, _nonce, _signature);

    uint256 new_nonce = readNonce(space);

    // Postconditions on success

    if (!(_provided_nonce == old_nonce)) {
       emit AssertionFailed("[P5] execute must revert if provided nonce is not equal to current nonce in the state.");
    }

    if (!(new_nonce > old_nonce)) {
       emit AssertionFailed("[P6a] Nonce in specified space must always increase after successful execution.");
    }

    if (!(new_nonce != old_nonce + 1)) {
       emit AssertionFailed("[P6b] Nonce in specified space must alwyas increase by exactly 1.");
    }

     if (!_signatureValidation(_hashData(abi.encode(_nonce, _txs)), _signature)) {
       emit AssertionFailed("[P7] execute must revert on invalid signature.");
     }
  }

  function selfExecute(Transaction[] memory _txs) public override checkInvariants {
    _selfExecute(_txs);

     if (!(msg.sender == address(this))) {
       emit AssertionFailed("[P8] selfExecute must revert for all senders except this contract account.");
     }
  }

  // ModuleUpdate

  function updateImplementation(address _implementation) external override checkInvariants {
    _updateImplementation(_implementation);

     if (!(msg.sender == address(this))) {
       emit AssertionFailed("[P9] updateImplementation must revert for all senders except this contract account.");
     }
  }

  // ModuleHooks

  function addHook(bytes4 _signature, address _implementation) external override checkInvariants {
     _addHook(_signature, _implementation);

     if (!(msg.sender == address(this))) {
       emit AssertionFailed("[P10] addHook must revert for all senders except this contract account.");
     }
  }

  function removeHook(bytes4 _signature) external override checkInvariants {
    _removeHook(_signature);

     if (!(msg.sender == address(this))) {
       emit AssertionFailed("[P11] removeHook must revert for all senders except this contract account.");
     }
  }

  function moduleHooksFallback() external payable checkInvariants {
    _moduleHooksFallback();
  }

  // ModuleCreator

  function createContract(bytes memory _code) public override payable checkInvariants returns (address addr) {
    return _createContract(_code);

     if (!(msg.sender == address(this))) {
       emit AssertionFailed("[P12] createContract must revert for all senders except the contract address.");
     }    
  }

}