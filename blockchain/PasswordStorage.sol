pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@truffle/hdwallet-provider/contracts/IPFS.sol";

contract PasswordStorage {
    using Strings for uint256;
    using IPFS for IPFS.Bytes;
    using PragmaticPGPEncryptionLib for bytes32;

    struct UserData {
        bytes32 encryptedX;
        bytes32 encryptedParams;
        uint256[] shares;
    }

    mapping(bytes32 => string) public userData;
    mapping(bytes32 => string) public usernameToData;

    event Registration(bytes32 indexed cid);
    event Authentication(bool success);

    function register(bytes32 encryptedX, bytes32 encryptedParams, uint256[] calldata shares, bytes32 usernameHash) external returns (string memory) {
        require(shares.length >= 3, "Insufficient shares for secret reconstruction");

        bytes memory data = abi.encode(encryptedX, encryptedParams, shares);
        string memory cid = storeOnIPFS(data);

        userData[keccak256(abi.encodePacked(cid))] = cid;
        usernameToData[usernameHash] = cid;

        emit Registration(bytes32(cid));
        return cid;
    }

    function getEncryptedDataAndShares(bytes32 usernameHash) external view returns (bytes32, uint256[] memory) {
    string memory cid = usernameToData[usernameHash];
    if (bytes(cid).length == 0) {
        return (bytes32(0), new uint256[](0));
    }

    bytes memory encryptedData = fetchFromIPFS(cid);
    (bytes32 encryptedX, , uint256[] memory shares) = abi.decode(encryptedData, (bytes32, bytes32, uint256[]));

    return (encryptedX, shares);
    }

    function fetchFromIPFS(string memory cid) internal view returns (bytes memory) {
        IPFS.Bytes memory ipfsData = IPFS.Bytes(abi.encodePacked(cid));
        return ipfsData.fetchFromIPFS();
    }

    function authenticate(bytes32 usernameHash, bytes32 passwordHash, uint256 secretFromClient) external view returns (bool, uint256, uint256, uint256, uint256) {
        string memory cid = usernameToData[usernameHash];
        if (bytes(cid).length == 0) {
            emit Authentication(false);
            return (false, 0, 0, 0, 0); // User not found
        }

        bytes32 dataHash = keccak256(abi.encodePacked(cid));
        bytes memory encryptedData = abi.encodePacked(userData[dataHash]);
        (bytes32 encryptedX, bytes32 encryptedParams, uint256[] memory shares) = abi.decode(encryptedData, (bytes32, bytes32, uint256[]));

        bytes memory decryptedParams = decrypt(encryptedParams, passwordHash);
        (uint256 r, uint256 p, uint256 q, uint256 g, uint256 h) = abi.decode(decryptedParams, (uint256, uint256, uint256, uint256, uint256));

        uint256 secretFromContract = (pow(g, passwordHash, p) * pow(h, r, p)) % p;

        bool success = secretFromClient == secretFromContract;
        emit Authentication(success);
        return (success, p, q, g, h);
    }

    function storeOnIPFS(bytes memory data) internal view returns (string memory) {
        IPFS.Bytes memory ipfsData = IPFS.Bytes(data);
        return ipfsData.storeOnIPFS();
    }

    function decrypt(bytes32 encryptedData, bytes32 key) internal pure returns (bytes memory) {
        // Implement decryption logic using the provided key
        return abi.decode(encryptedData.dec(key), (bytes));
    }

    function pow(uint256 base, uint256 exponent, uint256 modulus) internal pure returns (uint256) {
        uint256 result = 1;
        for (uint256 i = 0; i < exponent; i++) {
            result = mulmod(result, base, modulus);
        }
        return result;
    }

    function mulmod(uint256 a, uint256 b, uint256 modulus) internal pure returns (uint256) {
        return mulmod(a, b, modulus, 5);
    }

    function mulmod(uint256 a, uint256 b, uint256 modulus, uint256 iterations) internal pure returns (uint256 result) {
        assembly {
            result := mulmod(a, b, modulus)
        }
        if (iterations == 0) {
            return result;
        }
        return mulmod(a, mulmod(b, result, modulus, iterations - 1), modulus, iterations - 1);
    }
}