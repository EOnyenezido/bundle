(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const assert = require('assert')
const ldap = require('ldapjs')

// convert a SearchResultEntry object in ldapjs 3.0
// to a user object to maintain backward compatibility

function _searchResultToUser(pojo) {
  assert(pojo.type == 'SearchResultEntry')
  let user = { dn: pojo.objectName }
  pojo.attributes.forEach((attribute) => {
    user[attribute.type] =
      attribute.values.length == 1 ? attribute.values[0] : attribute.values
  })
  return user
}
// bind and return the ldap client
function _ldapBind(dn, password, starttls, ldapOpts) {
  return new Promise(function (resolve, reject) {
    ldapOpts.connectTimeout = ldapOpts.connectTimeout || 5000
    var client = ldap.createClient(ldapOpts)

    client.on('connect', function () {
      if (starttls) {
        client.starttls(ldapOpts.tlsOptions, null, function (error) {
          if (error) {
            reject(error)
            return
          }
          client.bind(dn, password, function (err) {
            if (err) {
              reject(err)
              client.unbind()
              return
            }
            ldapOpts.log && ldapOpts.log.trace('bind success!')
            resolve(client)
          })
        })
      } else {
        client.bind(dn, password, function (err) {
          if (err) {
            reject(err)
            client.unbind()
            return
          }
          ldapOpts.log && ldapOpts.log.trace('bind success!')
          resolve(client)
        })
      }
    })

    //Fix for issue https://github.com/shaozi/ldap-authentication/issues/13
    client.on('timeout', (err) => {
      reject(err)
    })
    client.on('connectTimeout', (err) => {
      reject(err)
    })
    client.on('error', (err) => {
      reject(err)
    })

    client.on('connectError', function (error) {
      if (error) {
        reject(error)
        return
      }
    })
  })
}

// search a user and return the object
async function _searchUser(
  ldapClient,
  searchBase,
  usernameAttribute,
  username,
  attributes = null
) {
  return new Promise(function (resolve, reject) {
    var filter = new ldap.filters.EqualityFilter({
      attribute: usernameAttribute,
      value: username,
    })
    let searchOptions = {
      filter: filter,
      scope: 'sub',
      attributes: attributes,
    }
    if (attributes) {
      searchOptions.attributes = attributes
    }
    ldapClient.search(searchBase, searchOptions, function (err, res) {
      var user = null
      if (err) {
        reject(err)
        ldapClient.unbind()
        return
      }
      res.on('searchEntry', function (entry) {
        user = _searchResultToUser(entry.pojo)
      })
      res.on('searchReference', function (referral) {
        // TODO: we don't support reference yet
        // If the server was able to locate the entry referred to by the baseObject
        // but could not search one or more non-local entries,
        // the server may return one or more SearchResultReference messages,
        // each containing a reference to another set of servers for continuing the operation.
        // referral.uris
      })
      res.on('error', function (err) {
        reject(err)
        ldapClient.unbind()
      })
      res.on('end', function (result) {
        if (result.status != 0) {
          reject(new Error('ldap search status is not 0, search failed'))
        } else {
          resolve(user)
        }
        ldapClient.unbind()
      })
    })
  })
}

// search a groups which user is member
async function _searchUserGroups(
  ldapClient,
  searchBase,
  user,
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn'
) {
  return new Promise(function (resolve, reject) {
    ldapClient.search(
      searchBase,
      {
        filter: `(&(objectclass=${groupClass})(${groupMemberAttribute}=${user[groupMemberUserAttribute]}))`,
        scope: 'sub',
      },
      function (err, res) {
        var groups = []
        if (err) {
          reject(err)
          ldapClient.unbind()
          return
        }
        res.on('searchEntry', function (entry) {
          groups.push(entry.object)
        })
        res.on('searchReference', function (referral) {})
        res.on('error', function (err) {
          reject(err)
          ldapClient.unbind()
        })
        res.on('end', function (result) {
          if (result.status != 0) {
            reject(new Error('ldap search status is not 0, search failed'))
          } else {
            resolve(groups)
          }
          ldapClient.unbind()
        })
      }
    )
  })
}

async function authenticateWithAdmin(
  adminDn,
  adminPassword,
  userSearchBase,
  usernameAttribute,
  username,
  userPassword,
  starttls,
  ldapOpts,
  groupsSearchBase,
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn',
  attributes = null
) {
  var ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(
      adminDn,
      adminPassword,
      starttls,
      ldapOpts
    )
  } catch (error) {
    throw { admin: error }
  }
  var user = await _searchUser(
    ldapAdminClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes
  )
  ldapAdminClient.unbind()
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `admin did not find user! (${usernameAttribute}=${username})`
      )
    throw new LdapAuthenticationError(
      'user not found or usernameAttribute is wrong'
    )
  }
  var userDn = user.dn
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  } catch (error) {
    throw error
  }
  ldapUserClient.unbind()
  if (groupsSearchBase && groupClass && groupMemberAttribute) {
    try {
      ldapAdminClient = await _ldapBind(
        adminDn,
        adminPassword,
        starttls,
        ldapOpts
      )
    } catch (error) {
      throw error
    }
    var groups = await _searchUserGroups(
      ldapAdminClient,
      groupsSearchBase,
      user,
      groupClass,
      groupMemberAttribute,
      groupMemberUserAttribute
    )
    user.groups = groups
    ldapAdminClient.unbind()
  }
  return user
}

async function authenticateWithUser(
  userDn,
  userSearchBase,
  usernameAttribute,
  username,
  userPassword,
  starttls,
  ldapOpts,
  groupsSearchBase,
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn',
  attributes = null
) {
  let ldapUserClient
  try {
    ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
  } catch (error) {
    throw error
  }
  if (!usernameAttribute || !userSearchBase) {
    // if usernameAttribute is not provided, no user detail is needed.
    ldapUserClient.unbind()
    return true
  }
  var user = await _searchUser(
    ldapUserClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes
  )
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `user logged in, but user details could not be found. (${usernameAttribute}=${username}). Probabaly wrong attribute or searchBase?`
      )
    throw new LdapAuthenticationError(
      'user logged in, but user details could not be found. Probabaly usernameAttribute or userSearchBase is wrong?'
    )
  }
  ldapUserClient.unbind()
  if (groupsSearchBase && groupClass && groupMemberAttribute) {
    try {
      ldapUserClient = await _ldapBind(userDn, userPassword, starttls, ldapOpts)
    } catch (error) {
      throw error
    }
    var groups = await _searchUserGroups(
      ldapUserClient,
      groupsSearchBase,
      user,
      groupClass,
      groupMemberAttribute,
      groupMemberUserAttribute
    )
    user.groups = groups
    ldapUserClient.unbind()
  }
  return user
}

async function verifyUserExists(
  adminDn,
  adminPassword,
  userSearchBase,
  usernameAttribute,
  username,
  starttls,
  ldapOpts,
  groupsSearchBase,
  groupClass,
  groupMemberAttribute = 'member',
  groupMemberUserAttribute = 'dn',
  attributes = null
) {
  var ldapAdminClient
  try {
    ldapAdminClient = await _ldapBind(
      adminDn,
      adminPassword,
      starttls,
      ldapOpts
    )
  } catch (error) {
    throw { admin: error }
  }
  var user = await _searchUser(
    ldapAdminClient,
    userSearchBase,
    usernameAttribute,
    username,
    attributes
  )
  ldapAdminClient.unbind()
  if (!user || !user.dn) {
    ldapOpts.log &&
      ldapOpts.log.trace(
        `admin did not find user! (${usernameAttribute}=${username})`
      )
    throw new LdapAuthenticationError(
      'user not found or usernameAttribute is wrong'
    )
  }
  if (groupsSearchBase && groupClass && groupMemberAttribute) {
    try {
      ldapAdminClient = await _ldapBind(
        adminDn,
        adminPassword,
        starttls,
        ldapOpts
      )
    } catch (error) {
      throw error
    }
    var groups = await _searchUserGroups(
      ldapAdminClient,
      groupsSearchBase,
      user,
      groupClass,
      groupMemberAttribute,
      groupMemberUserAttribute
    )
    user.groups = groups
    ldapAdminClient.unbind()
  }
  return user
}

async function authenticate(options) {
  if (!options.userDn) {
    assert(options.adminDn, 'Admin mode adminDn must be provided')
    assert(options.adminPassword, 'Admin mode adminPassword must be provided')
    assert(options.userSearchBase, 'Admin mode userSearchBase must be provided')
    assert(
      options.usernameAttribute,
      'Admin mode usernameAttribute must be provided'
    )
    assert(options.username, 'Admin mode username must be provided')
  } else {
    assert(options.userDn, 'User mode userDn must be provided')
  }
  assert(
    options.ldapOpts && options.ldapOpts.url,
    'ldapOpts.url must be provided'
  )
  if (options.verifyUserExists) {
    assert(options.adminDn, 'Admin mode adminDn must be provided')
    assert(
      options.adminPassword,
      'adminDn and adminPassword must be both provided.'
    )
    return await verifyUserExists(
      options.adminDn,
      options.adminPassword,
      options.userSearchBase,
      options.usernameAttribute,
      options.username,
      options.starttls,
      options.ldapOpts,
      options.groupsSearchBase,
      options.groupClass,
      options.groupMemberAttribute,
      options.groupMemberUserAttribute
    )
  }
  assert(options.userPassword, 'userPassword must be provided')
  if (options.adminDn) {
    assert(
      options.adminPassword,
      'adminDn and adminPassword must be both provided.'
    )
    return await authenticateWithAdmin(
      options.adminDn,
      options.adminPassword,
      options.userSearchBase,
      options.usernameAttribute,
      options.username,
      options.userPassword,
      options.starttls,
      options.ldapOpts,
      options.groupsSearchBase,
      options.groupClass,
      options.groupMemberAttribute,
      options.groupMemberUserAttribute,
      options.attributes
    )
  }
  assert(options.userDn, 'adminDn/adminPassword OR userDn must be provided')
  return await authenticateWithUser(
    options.userDn,
    options.userSearchBase,
    options.usernameAttribute,
    options.username,
    options.userPassword,
    options.starttls,
    options.ldapOpts,
    options.groupsSearchBase,
    options.groupClass,
    options.groupMemberAttribute,
    options.groupMemberUserAttribute,
    options.attributes
  )
}

class LdapAuthenticationError extends Error {
  constructor(message) {
    super(message)
    // Ensure the name of this error is the same as the class name
    this.name = this.constructor.name
    // This clips the constructor invocation from the stack trace.
    // It's not absolutely essential, but it does make the stack trace a little nicer.
    //  @see Node.js reference (bottom)
    Error.captureStackTrace(this, this.constructor)
  }
}

module.exports.authenticate = authenticate
module.exports.LdapAuthenticationError = LdapAuthenticationError

},{"assert":96,"ldapjs":148}],2:[function(require,module,exports){
'use strict'

const BerReader = require('./lib/ber/reader')
const BerWriter = require('./lib/ber/writer')
const BerTypes = require('./lib/ber/types')
const bufferToHexDump = require('./lib/buffer-to-hex-dump')

module.exports = {
  BerReader,
  BerTypes,
  BerWriter,
  bufferToHexDump
}

},{"./lib/ber/reader":3,"./lib/ber/types":4,"./lib/ber/writer":5,"./lib/buffer-to-hex-dump":6}],3:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const types = require('./types')
const bufferToHexDump = require('../buffer-to-hex-dump')

/**
 * Given a buffer of ASN.1 data encoded according to Basic Encoding Rules (BER),
 * the reader provides methods for iterating that data and decoding it into
 * regular JavaScript types.
 */
class BerReader {
  /**
   * The source buffer as it was passed in when creating the instance.
   *
   * @type {Buffer}
   */
  #buffer;

  /**
   * The total bytes in the backing buffer.
   *
   * @type {number}
   */
  #size;

  /**
   * An ASN.1 field consists of a tag, a length, and a value. This property
   * records the length of the current field.
   *
   * @type {number}
   */
  #currentFieldLength = 0;

  /**
   * Records the offset in the buffer where the most recent {@link readSequence}
   * was invoked. This is used to facilitate slicing of whole sequences from
   * the buffer as a new {@link BerReader} instance.
   *
   * @type {number}
   */
  #currentSequenceStart = 0;

  /**
   * As the BER buffer is read, this property records the current position
   * in the buffer.
   *
   * @type {number}
   */
  #offset = 0;

  /**
   * @param {Buffer} buffer
   */
  constructor (buffer) {
    if (Buffer.isBuffer(buffer) === false) {
      throw TypeError('Must supply a Buffer instance to read.')
    }

    this.#buffer = buffer.subarray(0)
    this.#size = this.#buffer.length
  }

  get [Symbol.toStringTag] () { return 'BerReader' }

  /**
   * Get a buffer that represents the underlying data buffer.
   *
   * @type {Buffer}
   */
  get buffer () {
    return this.#buffer.subarray(0)
  }

  /**
   * The length of the current field being read.
   *
   * @type {number}
   */
  get length () {
    return this.#currentFieldLength
  }

  /**
   * Current read position in the underlying data buffer.
   *
   * @type {number}
   */
  get offset () {
    return this.#offset
  }

  /**
   * The number of bytes remaining in the backing buffer that have not
   * been read.
   *
   * @type {number}
   */
  get remain () {
    return this.#size - this.#offset
  }

  /**
   * Read the next byte in the buffer without advancing the offset.
   *
   * @return {number | null} The next byte or null if not enough data.
   */
  peek () {
    return this.readByte(true)
  }

  /**
   * Reads a boolean from the current offset and advances the offset.
   *
   * @param {number} [tag] The tag number that is expected to be read.
   *
   * @returns {boolean} True if the tag value represents `true`, otherwise
   * `false`.
   *
   * @throws When there is an error reading the tag.
   */
  readBoolean (tag = types.Boolean) {
    const intBuffer = this.readTag(tag)
    this.#offset += intBuffer.length
    const int = parseIntegerBuffer(intBuffer)

    return (int !== 0)
  }

  /**
   * Reads a single byte and advances offset; you can pass in `true` to make
   * this a "peek" operation (i.e. get the byte, but don't advance the offset).
   *
   * @param {boolean} [peek=false] `true` means don't move the offset.
   * @returns {number | null} The next byte, `null` if not enough data.
   */
  readByte (peek = false) {
    if (this.#size - this.#offset < 1) {
      return null
    }

    const byte = this.#buffer[this.#offset] & 0xff

    if (peek !== true) {
      this.#offset += 1
    }

    return byte
  }

  /**
   * Reads an enumeration (integer) from the current offset and advances the
   * offset.
   *
   * @returns {number} The integer represented by the next sequence of bytes
   * in the buffer from the current offset. The current offset must be at a
   * byte whose value is equal to the ASN.1 enumeration tag.
   *
   * @throws When there is an error reading the tag.
   */
  readEnumeration () {
    const intBuffer = this.readTag(types.Enumeration)
    this.#offset += intBuffer.length

    return parseIntegerBuffer(intBuffer)
  }

  /**
   * Reads an integer from the current offset and advances the offset.
   *
   * @param {number} [tag] The tag number that is expected to be read.
   *
   * @returns {number} The integer represented by the next sequence of bytes
   * in the buffer from the current offset. The current offset must be at a
   * byte whose value is equal to the ASN.1 integer tag.
   *
   * @throws When there is an error reading the tag.
   */
  readInt (tag = types.Integer) {
    const intBuffer = this.readTag(tag)
    this.#offset += intBuffer.length

    return parseIntegerBuffer(intBuffer)
  }

  /**
   * Reads a length value from the BER buffer at the given offset. This
   * method is not really meant to be called directly, as callers have to
   * manipulate the internal buffer afterwards.
   *
   * This method does not advance the reader offset.
   *
   * As a result of this method, the `.length` property can be read for the
   * current field until another method invokes `readLength`.
   *
   * Note: we only support up to 4 bytes to describe the length of a value.
   *
   * @param {number} [offset] Read a length value starting at the specified
   * position in the underlying buffer.
   *
   * @return {number | null} The position the buffer should be advanced to in
   * order for the reader to be at the start of the value for the field. See
   * {@link setOffset}. If the offset, or length, exceeds the size of the
   * underlying buffer, `null` will be returned.
   *
   * @throws When an unsupported length value is encountered.
   */
  readLength (offset) {
    if (offset === undefined) { offset = this.#offset }

    if (offset >= this.#size) { return null }

    let lengthByte = this.#buffer[offset++] & 0xff
    // TODO: we are commenting this out because it seems to be unreachable.
    // It is not clear to me how we can ever check `lenB === null` as `null`
    // is a primitive type, and seemingly cannot be represented by a byte.
    // If we find that removal of this line does not affect the larger suite
    // of ldapjs tests, we should just completely remove it from the code.
    /* if (lenB === null) { return null } */

    if ((lengthByte & 0x80) === 0x80) {
      lengthByte &= 0x7f

      // https://www.rfc-editor.org/rfc/rfc4511.html#section-5.1 prohibits
      // indefinite form (0x80).
      if (lengthByte === 0) { throw Error('Indefinite length not supported.') }

      // We only support up to 4 bytes to describe encoding length. So the only
      // valid indicators are 0x81, 0x82, 0x83, and 0x84.
      if (lengthByte > 4) { throw Error('Encoding too long.') }

      if (this.#size - offset < lengthByte) { return null }

      this.#currentFieldLength = 0
      for (let i = 0; i < lengthByte; i++) {
        this.#currentFieldLength = (this.#currentFieldLength << 8) +
          (this.#buffer[offset++] & 0xff)
      }
    } else {
    // Wasn't a variable length
      this.#currentFieldLength = lengthByte
    }

    return offset
  }

  /**
   * At the current offset, read the next tag, length, and value as an
   * object identifier (OID) and return the OID string.
   *
   * @param {number} [tag] The tag number that is expected to be read.
   *
   * @returns {string | null} Will return `null` if the buffer is an invalid
   * length. Otherwise, returns the OID as a string.
   */
  readOID (tag = types.OID) {
    // See https://web.archive.org/web/20221008202056/https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN
    const oidBuffer = this.readString(tag, true)
    if (oidBuffer === null) { return null }

    const values = []
    let value = 0

    for (let i = 0; i < oidBuffer.length; i++) {
      const byte = oidBuffer[i] & 0xff

      value <<= 7
      value += byte & 0x7f
      if ((byte & 0x80) === 0) {
        values.push(value)
        value = 0
      }
    }

    value = values.shift()
    values.unshift(value % 40)
    values.unshift((value / 40) >> 0)

    return values.join('.')
  }

  /**
   * Get a new {@link Buffer} instance that represents the full set of bytes
   * for a BER representation of a specified tag. For example, this is useful
   * when construction objects from an incoming LDAP message and the object
   * constructor can read a BER representation of itself to create a new
   * instance, e.g. when reading the filter section of a "search request"
   * message.
   *
   * @param {number} tag The expected tag that starts the TLV series of bytes.
   * @param {boolean} [advanceOffset=true] Indicates if the instance's internal
   * offset should be advanced or not after reading the buffer.
   *
   * @returns {Buffer|null} If there is a problem reading the buffer, e.g.
   * the number of bytes indicated by the length do not exist in the value, then
   * `null` will be returned. Otherwise, a new {@link Buffer} of bytes that
   * represents a full TLV.
   */
  readRawBuffer (tag, advanceOffset = true) {
    if (Number.isInteger(tag) === false) {
      throw Error('must specify an integer tag')
    }

    const foundTag = this.peek()
    if (foundTag !== tag) {
      const expected = tag.toString(16).padStart(2, '0')
      const found = foundTag.toString(16).padStart(2, '0')
      throw Error(`Expected 0x${expected}: got 0x${found}`)
    }

    const currentOffset = this.#offset
    const valueOffset = this.readLength(currentOffset + 1)
    if (valueOffset === null) { return null }
    const valueBytesLength = this.length

    const numTagAndLengthBytes = valueOffset - currentOffset

    // Buffer.subarray is not inclusive. We need to account for the
    // tag and length bytes.
    const endPos = currentOffset + valueBytesLength + numTagAndLengthBytes
    if (endPos > this.buffer.byteLength) {
      return null
    }
    const buffer = this.buffer.subarray(currentOffset, endPos)
    if (advanceOffset === true) {
      this.setOffset(currentOffset + (valueBytesLength + numTagAndLengthBytes))
    }

    return buffer
  }

  /**
   * At the current buffer offset, read the next tag as a sequence tag, and
   * advance the offset to the position of the tag of the first item in the
   * sequence.
   *
   * @param {number} [tag] The tag number that is expected to be read.
   *
   * @returns {number|null} The read sequence tag value. Should match the
   * function input parameter value.
   *
   * @throws If the `tag` does not match or if there is an error reading
   * the length of the sequence.
   */
  readSequence (tag) {
    const foundTag = this.peek()
    if (tag !== undefined && tag !== foundTag) {
      const expected = tag.toString(16).padStart(2, '0')
      const found = foundTag.toString(16).padStart(2, '0')
      throw Error(`Expected 0x${expected}: got 0x${found}`)
    }

    this.#currentSequenceStart = this.#offset
    const valueOffset = this.readLength(this.#offset + 1) // stored in `length`
    if (valueOffset === null) { return null }

    this.#offset = valueOffset
    return foundTag
  }

  /**
   * At the current buffer offset, read the next value as a string and advance
   * the offset.
   *
   * @param {number} [tag] The tag number that is expected to be read. Should
   * be `ASN1.String`.
   * @param {boolean} [asBuffer=false] When true, the raw buffer will be
   * returned. Otherwise, a native string.
   *
   * @returns {string | Buffer | null} Will return `null` if the buffer is
   * malformed.
   *
   * @throws If there is a problem reading the length.
   */
  readString (tag = types.OctetString, asBuffer = false) {
    const tagByte = this.peek()

    if (tagByte !== tag) {
      const expected = tag.toString(16).padStart(2, '0')
      const found = tagByte.toString(16).padStart(2, '0')
      throw Error(`Expected 0x${expected}: got 0x${found}`)
    }

    const valueOffset = this.readLength(this.#offset + 1) // stored in `length`
    if (valueOffset === null) { return null }
    if (this.length > this.#size - valueOffset) { return null }

    this.#offset = valueOffset

    if (this.length === 0) { return asBuffer ? Buffer.alloc(0) : '' }

    const str = this.#buffer.subarray(this.#offset, this.#offset + this.length)
    this.#offset += this.length

    return asBuffer ? str : str.toString('utf8')
  }

  /**
   * At the current buffer offset, read the next set of bytes represented
   * by the given tag, and return the resulting buffer. For example, if the
   * BER represents a sequence with a string "foo", i.e.
   * `[0x30, 0x05, 0x04, 0x03, 0x66, 0x6f, 0x6f]`, and the current offset is
   * `0`, then the result of `readTag(0x30)` is the buffer
   * `[0x04, 0x03, 0x66, 0x6f, 0x6f]`.
   *
   * @param {number} tag The tag number that is expected to be read.
   *
   * @returns {Buffer | null} The buffer representing the tag value, or null if
   * the buffer is in some way malformed.
   *
   * @throws When there is an error interpreting the buffer, or the buffer
   * is not formed correctly.
   */
  readTag (tag) {
    if (tag == null) {
      throw Error('Must supply an ASN.1 tag to read.')
    }

    const byte = this.peek()
    if (byte !== tag) {
      const tagString = tag.toString(16).padStart(2, '0')
      const byteString = byte.toString(16).padStart(2, '0')
      throw Error(`Expected 0x${tagString}: got 0x${byteString}`)
    }

    const fieldOffset = this.readLength(this.#offset + 1) // stored in `length`
    if (fieldOffset === null) { return null }

    if (this.length > this.#size - fieldOffset) { return null }
    this.#offset = fieldOffset

    return this.#buffer.subarray(this.#offset, this.#offset + this.length)
  }

  /**
   * Returns the current sequence as a new {@link BerReader} instance. This
   * method relies on {@link readSequence} having been invoked first. If it has
   * not been invoked, the returned reader will represent an undefined portion
   * of the underlying buffer.
   *
   * @returns {BerReader}
   */
  sequenceToReader () {
    // Represents the number of bytes that constitute the "length" portion
    // of the TLV tuple.
    const lengthValueLength = this.#offset - this.#currentSequenceStart
    const buffer = this.#buffer.subarray(
      this.#currentSequenceStart,
      this.#currentSequenceStart + (lengthValueLength + this.#currentFieldLength)
    )
    return new BerReader(buffer)
  }

  /**
   * Set the internal offset to a given position in the underlying buffer.
   * This method is to support manual advancement of the reader.
   *
   * @param {number} position
   *
   * @throws If the given `position` is not an integer.
   */
  setOffset (position) {
    if (Number.isInteger(position) === false) {
      throw Error('Must supply an integer position.')
    }
    this.#offset = position
  }

  /**
   * @param {HexDumpParams} params The `buffer` parameter will be ignored.
   *
   * @see bufferToHexDump
   */
  toHexDump (params) {
    bufferToHexDump({
      ...params,
      buffer: this.buffer
    })
  }
}

/**
 * Given a buffer that represents an integer TLV, parse it and return it
 * as a decimal value. This accounts for signedness.
 *
 * @param {Buffer} integerBuffer
 *
 * @returns {number}
 */
function parseIntegerBuffer (integerBuffer) {
  let value = 0
  let i
  for (i = 0; i < integerBuffer.length; i++) {
    value <<= 8
    value |= (integerBuffer[i] & 0xff)
  }

  if ((integerBuffer[0] & 0x80) === 0x80 && i !== 4) { value -= (1 << (i * 8)) }

  return value >> 0
}

module.exports = BerReader

}).call(this)}).call(this,require("buffer").Buffer)
},{"../buffer-to-hex-dump":6,"./types":4,"buffer":110}],4:[function(require,module,exports){
'use strict'

module.exports = {
  EOC: 0x0,
  Boolean: 0x01,
  Integer: 0x02,
  BitString: 0x03,
  OctetString: 0x04,
  Null: 0x05,
  OID: 0x06,
  ObjectDescriptor: 0x07,
  External: 0x08,
  Real: 0x09, // float
  Enumeration: 0x0a,
  PDV: 0x0b,
  Utf8String: 0x0c,
  RelativeOID: 0x0d,
  Sequence: 0x10,
  Set: 0x11,
  NumericString: 0x12,
  PrintableString: 0x13,
  T61String: 0x14,
  VideotexString: 0x15,
  IA5String: 0x16,
  UTCTime: 0x17,
  GeneralizedTime: 0x18,
  GraphicString: 0x19,
  VisibleString: 0x1a,
  GeneralString: 0x1c,
  UniversalString: 0x1d,
  CharacterString: 0x1e,
  BMPString: 0x1f,
  Constructor: 0x20,
  LDAPSequence: 0x30,
  Context: 0x80
}

},{}],5:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const types = require('./types')
const bufferToHexDump = require('../buffer-to-hex-dump')

class BerWriter {
  /**
   * The source buffer as it was passed in when creating the instance.
   *
   * @type {Buffer}
   */
  #buffer;

  /**
   * The total bytes in the backing buffer.
   *
   * @type {number}
   */
  #size;

  /**
   * As the BER buffer is written, this property records the current position
   * in the buffer.
   *
   * @type {number}
   */
  #offset = 0;

  /**
   * A list of offsets in the buffer where we need to insert sequence tag and
   * length pairs.
   */
  #sequenceOffsets = [];

  /**
   * Coeffecient used when increasing the buffer to accomodate writes that
   * exceed the available space left in the buffer.
   *
   * @type {number}
   */
  #growthFactor;

  constructor ({ size = 1024, growthFactor = 8 } = {}) {
    this.#buffer = Buffer.alloc(size)
    this.#size = this.#buffer.length
    this.#offset = 0
    this.#growthFactor = growthFactor
  }

  get [Symbol.toStringTag] () { return 'BerWriter' }

  get buffer () {
    // TODO: handle sequence check

    return this.#buffer.subarray(0, this.#offset)
  }

  /**
   * The size of the backing buffer.
   *
   * @return {number}
   */
  get size () {
    return this.#size
  }

  /**
   * Append a raw buffer to the current writer instance. No validation to
   * determine if the buffer represents a valid BER encoding is performed.
   *
   * @param {Buffer} buffer The buffer to append. If this is not a valid BER
   * sequence of data, it will invalidate the BER represented by the `BerWriter`.
   *
   * @throws If the input is not an instance of Buffer.
   */
  appendBuffer (buffer) {
    if (Buffer.isBuffer(buffer) === false) {
      throw Error('buffer must be an instance of Buffer')
    }
    this.ensureBufferCapacity(buffer.length)
    buffer.copy(this.#buffer, this.#offset, 0, buffer.length)
    this.#offset += buffer.length
  }

  /**
   * Complete a sequence started with {@link startSequence}.
   *
   * @throws When the sequence is too long and would exceed the 4 byte
   * length descriptor limitation.
   */
  endSequence () {
    const sequenceStartOffset = this.#sequenceOffsets.pop()
    const start = sequenceStartOffset + 3
    const length = this.#offset - start

    if (length <= 0x7f) {
      this.shift(start, length, -2)
      this.#buffer[sequenceStartOffset] = length
    } else if (length <= 0xff) {
      this.shift(start, length, -1)
      this.#buffer[sequenceStartOffset] = 0x81
      this.#buffer[sequenceStartOffset + 1] = length
    } else if (length <= 0xffff) {
      this.#buffer[sequenceStartOffset] = 0x82
      this.#buffer[sequenceStartOffset + 1] = length >> 8
      this.#buffer[sequenceStartOffset + 2] = length
    } else if (length <= 0xffffff) {
      this.shift(start, length, 1)
      this.#buffer[sequenceStartOffset] = 0x83
      this.#buffer[sequenceStartOffset + 1] = length >> 16
      this.#buffer[sequenceStartOffset + 2] = length >> 8
      this.#buffer[sequenceStartOffset + 3] = length
    } else {
      throw Error('sequence too long')
    }
  }

  /**
   * Write a sequence tag to the buffer and advance the offset to the starting
   * position of the value. Sequences must be completed with a subsequent
   * invocation of {@link endSequence}.
   *
   * @param {number} [tag=0x30] The tag to use for the sequence.
   *
   * @throws When the tag is not a number.
   */
  startSequence (tag = (types.Sequence | types.Constructor)) {
    if (typeof tag !== 'number') {
      throw TypeError('tag must be a Number')
    }

    this.writeByte(tag)
    this.#sequenceOffsets.push(this.#offset)
    this.ensureBufferCapacity(3)
    this.#offset += 3
  }

  /**
   * @param {HexDumpParams} params The `buffer` parameter will be ignored.
   *
   * @see bufferToHexDump
   */
  toHexDump (params) {
    bufferToHexDump({
      ...params,
      buffer: this.buffer
    })
  }

  /**
   * Write a boolean TLV to the buffer.
   *
   * @param {boolean} boolValue
   * @param {tag} [number=0x01] A custom tag for the boolean.
   *
   * @throws When a parameter is of the wrong type.
   */
  writeBoolean (boolValue, tag = types.Boolean) {
    if (typeof boolValue !== 'boolean') {
      throw TypeError('boolValue must be a Boolean')
    }
    if (typeof tag !== 'number') {
      throw TypeError('tag must be a Number')
    }

    this.ensureBufferCapacity(3)
    this.#buffer[this.#offset++] = tag
    this.#buffer[this.#offset++] = 0x01
    this.#buffer[this.#offset++] = boolValue === true ? 0xff : 0x00
  }

  /**
   * Write an arbitrary buffer of data to the backing buffer using the given
   * tag.
   *
   * @param {Buffer} buffer
   * @param {number} tag The tag to use for the ASN.1 TLV sequence.
   *
   * @throws When either input parameter is of the wrong type.
   */
  writeBuffer (buffer, tag) {
    if (typeof tag !== 'number') {
      throw TypeError('tag must be a Number')
    }
    if (Buffer.isBuffer(buffer) === false) {
      throw TypeError('buffer must be an instance of Buffer')
    }

    this.writeByte(tag)
    this.writeLength(buffer.length)
    this.ensureBufferCapacity(buffer.length)
    buffer.copy(this.#buffer, this.#offset, 0, buffer.length)
    this.#offset += buffer.length
  }

  /**
   * Write a single byte to the backing buffer and advance the offset. The
   * backing buffer will be automatically expanded to accomodate the new byte
   * if no room in the buffer remains.
   *
   * @param {number} byte The byte to be written.
   *
   * @throws When the passed in parameter is not a `Number` (aka a byte).
   */
  writeByte (byte) {
    if (typeof byte !== 'number') {
      throw TypeError('argument must be a Number')
    }

    this.ensureBufferCapacity(1)
    this.#buffer[this.#offset++] = byte
  }

  /**
   * Write an enumeration TLV to the buffer.
   *
   * @param {number} value
   * @param {number} [tag=0x0a] A custom tag for the enumeration.
   *
   * @throws When a passed in parameter is not of the correct type, or the
   * value requires too many bytes (must be <= 4).
   */
  writeEnumeration (value, tag = types.Enumeration) {
    if (typeof value !== 'number') {
      throw TypeError('value must be a Number')
    }
    if (typeof tag !== 'number') {
      throw TypeError('tag must be a Number')
    }
    this.writeInt(value, tag)
  }

  /**
   * Write an, up to 4 byte, integer TLV to the buffer.
   *
   * @param {number} intToWrite
   * @param {number} [tag=0x02]
   *
   * @throws When either parameter is not of the write type, or if the
   * integer consists of too many bytes.
   */
  writeInt (intToWrite, tag = types.Integer) {
    if (typeof intToWrite !== 'number') {
      throw TypeError('intToWrite must be a Number')
    }
    if (typeof tag !== 'number') {
      throw TypeError('tag must be a Number')
    }

    let intSize = 4
    while (
      (
        ((intToWrite & 0xff800000) === 0) ||
        ((intToWrite & 0xff800000) === (0xff800000 >> 0))
      ) && (intSize > 1)
    ) {
      intSize--
      intToWrite <<= 8
    }

    // TODO: figure out how to cover this in a test.
    /* istanbul ignore if: needs test */
    if (intSize > 4) {
      throw Error('BER ints cannot be > 0xffffffff')
    }

    this.ensureBufferCapacity(2 + intSize)
    this.#buffer[this.#offset++] = tag
    this.#buffer[this.#offset++] = intSize

    while (intSize-- > 0) {
      this.#buffer[this.#offset++] = ((intToWrite & 0xff000000) >>> 24)
      intToWrite <<= 8
    }
  }

  /**
   * Write a set of length bytes to the backing buffer. Per
   * https://www.rfc-editor.org/rfc/rfc4511.html#section-5.1, LDAP message
   * BERs prohibit greater than 4 byte lengths. Given we are supporing
   * the `ldapjs` module, we limit ourselves to 4 byte lengths.
   *
   * @param {number} len The length value to write to the buffer.
   *
   * @throws When the length is not a number or requires too many bytes.
   */
  writeLength (len) {
    if (typeof len !== 'number') {
      throw TypeError('argument must be a Number')
    }

    this.ensureBufferCapacity(4)

    if (len <= 0x7f) {
      this.#buffer[this.#offset++] = len
    } else if (len <= 0xff) {
      this.#buffer[this.#offset++] = 0x81
      this.#buffer[this.#offset++] = len
    } else if (len <= 0xffff) {
      this.#buffer[this.#offset++] = 0x82
      this.#buffer[this.#offset++] = len >> 8
      this.#buffer[this.#offset++] = len
    } else if (len <= 0xffffff) {
      this.#buffer[this.#offset++] = 0x83
      this.#buffer[this.#offset++] = len >> 16
      this.#buffer[this.#offset++] = len >> 8
      this.#buffer[this.#offset++] = len
    } else {
      throw Error('length too long (> 4 bytes)')
    }
  }

  /**
   * Write a NULL tag and value to the buffer.
   */
  writeNull () {
    this.writeByte(types.Null)
    this.writeByte(0x00)
  }

  /**
   * Given an OID string, e.g. `1.2.840.113549.1.1.1`, split it into
   * octets, encode the octets, and write it to the backing buffer.
   *
   * @param {string} oidString
   * @param {number} [tag=0x06] A custom tag to use for the OID.
   *
   * @throws When the parameters are not of the correct types, or if the
   * OID is not in the correct format.
   */
  writeOID (oidString, tag = types.OID) {
    if (typeof oidString !== 'string') {
      throw TypeError('oidString must be a string')
    }
    if (typeof tag !== 'number') {
      throw TypeError('tag must be a Number')
    }

    if (/^([0-9]+\.){3,}[0-9]+$/.test(oidString) === false) {
      throw Error('oidString is not a valid OID string')
    }

    const parts = oidString.split('.')
    const bytes = []
    bytes.push(parseInt(parts[0], 10) * 40 + parseInt(parts[1], 10))
    for (const part of parts.slice(2)) {
      encodeOctet(bytes, parseInt(part, 10))
    }

    this.ensureBufferCapacity(2 + bytes.length)
    this.writeByte(tag)
    this.writeLength(bytes.length)
    this.appendBuffer(Buffer.from(bytes))

    function encodeOctet (bytes, octet) {
      if (octet < 128) {
        bytes.push(octet)
      } else if (octet < 16_384) {
        bytes.push((octet >>> 7) | 0x80)
        bytes.push(octet & 0x7F)
      } else if (octet < 2_097_152) {
        bytes.push((octet >>> 14) | 0x80)
        bytes.push(((octet >>> 7) | 0x80) & 0xFF)
        bytes.push(octet & 0x7F)
      } else if (octet < 268_435_456) {
        bytes.push((octet >>> 21) | 0x80)
        bytes.push(((octet >>> 14) | 0x80) & 0xFF)
        bytes.push(((octet >>> 7) | 0x80) & 0xFF)
        bytes.push(octet & 0x7F)
      } else {
        bytes.push(((octet >>> 28) | 0x80) & 0xFF)
        bytes.push(((octet >>> 21) | 0x80) & 0xFF)
        bytes.push(((octet >>> 14) | 0x80) & 0xFF)
        bytes.push(((octet >>> 7) | 0x80) & 0xFF)
        bytes.push(octet & 0x7F)
      }
    }
  }

  /**
   * Write a string TLV to the buffer.
   *
   * @param {string} stringToWrite
   * @param {number} [tag=0x04] The tag to use.
   *
   * @throws When either input parameter is of the wrong type.
   */
  writeString (stringToWrite, tag = types.OctetString) {
    if (typeof stringToWrite !== 'string') {
      throw TypeError('stringToWrite must be a string')
    }
    if (typeof tag !== 'number') {
      throw TypeError('tag must be a number')
    }

    const toWriteLength = Buffer.byteLength(stringToWrite)
    this.writeByte(tag)
    this.writeLength(toWriteLength)
    if (toWriteLength > 0) {
      this.ensureBufferCapacity(toWriteLength)
      this.#buffer.write(stringToWrite, this.#offset)
      this.#offset += toWriteLength
    }
  }

  /**
   * Given a set of strings, write each as a string TLV to the buffer.
   *
   * @param {string[]} strings
   *
   * @throws When the input is not an array.
   */
  writeStringArray (strings) {
    if (Array.isArray(strings) === false) {
      throw TypeError('strings must be an instance of Array')
    }
    for (const string of strings) {
      this.writeString(string)
    }
  }

  /**
   * Given a number of bytes to be written into the buffer, verify the buffer
   * has enough free space. If not, allocate a new buffer, copy the current
   * backing buffer into the new buffer, and promote the new buffer to be the
   * current backing buffer.
   *
   * @param {number} numberOfBytesToWrite How many bytes are required to be
   * available for writing in the backing buffer.
   */
  ensureBufferCapacity (numberOfBytesToWrite) {
    if (this.#size - this.#offset < numberOfBytesToWrite) {
      let newSize = this.#size * this.#growthFactor
      if (newSize - this.#offset < numberOfBytesToWrite) {
        newSize += numberOfBytesToWrite
      }

      const newBuffer = Buffer.alloc(newSize)

      this.#buffer.copy(newBuffer, 0, 0, this.#offset)
      this.#buffer = newBuffer
      this.#size = newSize
    }
  }

  /**
   * Shift a region of the buffer indicated by `start` and `length` a number
   * of bytes indicated by `shiftAmount`.
   *
   * @param {number} start The starting position in the buffer for the region
   * of bytes to be shifted.
   * @param {number} length The number of bytes that constitutes the region
   * of the buffer to be shifted.
   * @param {number} shiftAmount The number of bytes to shift the region by.
   * This may be negative.
   */
  shift (start, length, shiftAmount) {
    // TODO: this leaves garbage behind. We should either zero out the bytes
    // left behind, or device a better algorightm that generates a clean
    // buffer.
    this.#buffer.copy(this.#buffer, start + shiftAmount, start, start + length)
    this.#offset += shiftAmount
  }
}

module.exports = BerWriter

}).call(this)}).call(this,require("buffer").Buffer)
},{"../buffer-to-hex-dump":6,"./types":4,"buffer":110}],6:[function(require,module,exports){
(function (process){(function (){
'use strict'

const { createWriteStream } = require('fs')

/**
 * @typedef {object} HexDumpParams
 * @property {Buffer} buffer The buffer instance to serialize into a hex dump.
 * @property {string} [prefix=''] A string to prefix each byte with, e.g.
 * `0x`.
 * @property {string} [separator=''] A string to separate each byte with, e.g.
 * `, '.
 * @property {string[]} [wrapCharacters=[]] A set of characters to wrap the
 * output with. For example, `wrapCharacters=['[', ']']` will start the hex
 * dump with `[` and end it with `]`.
 * @property {number} [width=10] How many bytes to write per line.
 * @property {WriteStream | string} [destination=process.stdout] Where to
 * write the serialized data. If a string is provided, it is assumed to be
 * the path to a file. This file will be completely overwritten.
 * @property {boolean} [closeDestination=false] Indicates whether the
 * `destination` should be closed when done. This _should_ be `true` when the
 * passed in `destination` is a stream that you control. If a string path is
 * supplied for the `destination`, this will automatically be handled.
 */

// We'd like to put this coverage directive after the doc block,
// but that confuses doc tooling (e.g. WebStorm).
/* istanbul ignore next: defaults don't need 100% coverage */
/**
 * Given a buffer of bytes, generate a hex dump that can be loaded later
 * or viewed in a hex editor (e.g. [Hex Fiend](https://hexfiend.com)).
 *
 * @param {HexDumpParams} params
 *
 * @throws When the destination cannot be accessed.
 */
module.exports = function bufferToHexDump ({
  buffer,
  prefix = '',
  separator = '',
  wrapCharacters = [],
  width = 10,
  destination = process.stdout,
  closeDestination = false
}) {
  let closeStream = closeDestination
  if (typeof destination === 'string') {
    destination = createWriteStream(destination)
    closeStream = true
  }

  if (wrapCharacters[0]) {
    destination.write(wrapCharacters[0])
  }

  for (const [i, byte] of buffer.entries()) {
    const outByte = Number(byte).toString(16).padStart(2, '0')
    destination.write(prefix + outByte)
    if (i !== buffer.byteLength - 1) {
      destination.write(separator)
    }
    if ((i + 1) % width === 0) {
      destination.write('\n')
    }
  }

  if (wrapCharacters[1]) {
    destination.write(wrapCharacters[1])
  }

  /* istanbul ignore else */
  if (closeStream === true) {
    destination.end()
  }
}

}).call(this)}).call(this,require('_process'))
},{"_process":162,"fs":109}],7:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { core: { LBER_SET } } = require('@ldapjs/protocol')
const {
  BerTypes,
  BerReader,
  BerWriter
} = require('@ldapjs/asn1')
const warning = require('./lib/deprecations')

/**
 * Represents an LDAP attribute and its associated values as defined by
 * https://www.rfc-editor.org/rfc/rfc4512#section-2.5.
 */
class Attribute {
  #buffers = []
  #type

  /**
   * @param {object} options
   * @param {string} [options.type=''] The name of the attribute, e.g. "cn" for
   * the common name attribute. For binary attributes, include the `;binary`
   * option, e.g. `foo;binary`.
   * @param {string|string[]} [options.values] Either a single value for the
   * attribute, or a set of values for the attribute.
   */
  constructor (options = {}) {
    if (options.type && typeof (options.type) !== 'string') {
      throw TypeError('options.type must be a string')
    }
    this.type = options.type || ''

    const values = options.values || options.vals || []
    if (options.vals) {
      warning.emit('LDAP_ATTRIBUTE_DEP_001')
    }
    this.values = values
  }

  get [Symbol.toStringTag] () {
    return 'LdapAttribute'
  }

  /**
   * A copy of the buffers that represent the values for the attribute.
   *
   * @returns {Buffer[]}
   */
  get buffers () {
    return this.#buffers.slice(0)
  }

  /**
   * Serializes the attribute to a plain JavaScript object representation.
   *
   * @returns {object}
   */
  get pojo () {
    return {
      type: this.type,
      values: this.values
    }
  }

  /**
   * The attribute name as provided during construction.
   *
   * @returns {string}
   */
  get type () {
    return this.#type
  }

  /**
   * Set the attribute name.
   *
   * @param {string} name
   */
  set type (name) {
    this.#type = name
  }

  /**
   * The set of attribute values as strings.
   *
   * @returns {string[]}
   */
  get values () {
    const encoding = _bufferEncoding(this.#type)
    return this.#buffers.map(function (v) {
      return v.toString(encoding)
    })
  }

  /**
   * Set the attribute's associated values. This will replace any values set
   * at construction time.
   *
   * @param {string|string[]} vals
   */
  set values (vals) {
    if (Array.isArray(vals) === false) {
      return this.addValue(vals)
    }
    for (const value of vals) {
      this.addValue(value)
    }
  }

  /**
   * Use {@link values} instead.
   *
   * @deprecated
   * @returns {string[]}
   */
  get vals () {
    warning.emit('LDAP_ATTRIBUTE_DEP_003')
    return this.values
  }

  /**
   * Use {@link values} instead.
   *
   * @deprecated
   * @param {string|string[]} values
   */
  set vals (values) {
    warning.emit('LDAP_ATTRIBUTE_DEP_003')
    this.values = values
  }

  /**
   * Append a new value, or set of values, to the current set of values
   * associated with the attributes.
   *
   * @param {string|string[]} value
   */
  addValue (value) {
    if (Buffer.isBuffer(value)) {
      this.#buffers.push(value)
    } else {
      this.#buffers.push(
        Buffer.from(value + '', _bufferEncoding(this.#type))
      )
    }
  }

  /**
   * Replaces instance properties with those found in a given BER.
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @deprecated Use {@link fromBer} instead.
   */
  parse (ber) {
    const attr = Attribute.fromBer(ber)
    this.#type = attr.type
    this.values = attr.values
  }

  /**
   * Convert the {@link Attribute} instance to a {@link BerReader} capable of
   * being used in an LDAP message.
   *
   * @returns {BerReader}
   */
  toBer () {
    const ber = new BerWriter()

    ber.startSequence()
    ber.writeString(this.type)
    ber.startSequence(LBER_SET)

    if (this.#buffers.length > 0) {
      for (const buffer of this.#buffers) {
        ber.writeByte(BerTypes.OctetString)
        ber.writeLength(buffer.length)
        ber.appendBuffer(buffer)
      }
    } else {
      ber.writeStringArray([])
    }
    ber.endSequence()
    ber.endSequence()

    return new BerReader(ber.buffer)
  }

  toJSON () {
    return this.pojo
  }

  /**
   * Given two {@link Attribute} instances, determine if they are equal or
   * different.
   *
   * @param {Attribute} attr1 The first object to compare.
   * @param {Attribute} attr2 The second object to compare.
   *
   * @returns {number} `0` if the attributes are equal in value, `-1` if
   * `attr1` should come before `attr2` when sorted, and `1` if `attr2` should
   * come before `attr1` when sorted.
   *
   * @throws When either input object is not an {@link Attribute}.
   */
  static compare (attr1, attr2) {
    if (Attribute.isAttribute(attr1) === false || Attribute.isAttribute(attr2) === false) {
      throw TypeError('can only compare Attribute instances')
    }

    if (attr1.type < attr2.type) return -1
    if (attr1.type > attr2.type) return 1

    const aValues = attr1.values
    const bValues = attr2.values
    if (aValues.length < bValues.length) return -1
    if (aValues.length > bValues.length) return 1

    for (let i = 0; i < aValues.length; i++) {
      if (aValues[i] < bValues[i]) return -1
      if (aValues[i] > bValues[i]) return 1
    }

    return 0
  }

  /**
   * Read a BER representation of an attribute, and its values, and
   * create a new {@link Attribute} instance. The BER must start
   * at the beginning of a sequence.
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {Attribute}
   */
  static fromBer (ber) {
    ber.readSequence()

    const type = ber.readString()
    const values = []

    // If the next byte represents a BER "SET" sequence...
    if (ber.peek() === LBER_SET) {
      // .. read that sequence ...
      /* istanbul ignore else */
      if (ber.readSequence(LBER_SET)) {
        const end = ber.offset + ber.length
        // ... and read all values in that set.
        while (ber.offset < end) {
          values.push(
            ber.readString(BerTypes.OctetString, true)
          )
        }
      }
    }

    const result = new Attribute({
      type,
      values
    })
    return result
  }

  /**
   * Given an object of attribute types mapping to attribute values, construct
   * a set of Attributes.
   *
   * @param {object} obj Each key is an attribute type, and each value is an
   * attribute value or set of values.
   *
   * @returns {Attribute[]}
   *
   * @throws If an attribute cannot be constructed correctly.
   */
  static fromObject (obj) {
    const attributes = []
    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value) === true) {
        attributes.push(new Attribute({
          type: key,
          values: value
        }))
      } else {
        attributes.push(new Attribute({
          type: key,
          values: [value]
        }))
      }
    }
    return attributes
  }

  /**
   * Determine if an object represents an {@link Attribute}.
   *
   * @param {object} attr The object to check. It can be an instance of
   * {@link Attribute} or a plain JavaScript object that looks like an
   * {@link Attribute} and can be passed to the constructor to create one.
   *
   * @returns {boolean}
   */
  static isAttribute (attr) {
    if (typeof attr !== 'object') {
      return false
    }

    if (Object.prototype.toString.call(attr) === '[object LdapAttribute]') {
      return true
    }

    const typeOk = typeof attr.type === 'string'
    let valuesOk = Array.isArray(attr.values)
    if (valuesOk === true) {
      for (const val of attr.values) {
        if (typeof val !== 'string' && Buffer.isBuffer(val) === false) {
          valuesOk = false
          break
        }
      }
    }
    if (typeOk === true && valuesOk === true) {
      return true
    }

    return false
  }
}

module.exports = Attribute

/**
 * Determine the encoding for values based upon whether the binary
 * option is set on the attribute.
 *
 * @param {string} type
 *
 * @returns {string} Either "utf8" for a plain string value, or "base64" for
 * a binary attribute.
 *
 * @private
 */
function _bufferEncoding (type) {
  return /;binary$/.test(type) ? 'base64' : 'utf8'
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"./lib/deprecations":8,"@ldapjs/asn1":2,"@ldapjs/protocol":93,"buffer":110}],8:[function(require,module,exports){
'use strict'

const warning = require('process-warning')()
const clazz = 'LdapjsAttributeWarning'

warning.create(clazz, 'LDAP_ATTRIBUTE_DEP_001', 'options.vals is deprecated. Use options.values instead.')
warning.create(clazz, 'LDAP_ATTRIBUTE_DEP_002', 'Instance method .parse is deprecated. Use static .fromBer instead.')
warning.create(clazz, 'LDAP_ATTRIBUTE_DEP_003', 'Instance property .vals is deprecated. Use property .values instead.')

module.exports = warning

},{"process-warning":161}],9:[function(require,module,exports){
'use strict'

const { BerReader, BerWriter } = require('@ldapjs/asn1')
const Attribute = require('@ldapjs/attribute')

/**
 * Implements an LDAP CHANGE sequence as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6.
 */
class Change {
  #operation;
  #modification;

  /**
   * @typedef {object} ChangeParameters
   * @property {string | number} operation One of `add` (0), `delete` (1), or
   * `replace` (2). Default: `add`.
   * @property {object | import('@ldapjs/attribute')} modification An attribute
   * instance or an object that is shaped like an attribute.
   */

  /**
   * @param {ChangeParameters} input
   *
   * @throws When the `modification` parameter is invalid.
   */
  constructor ({ operation = 'add', modification }) {
    this.operation = operation
    this.modification = modification
  }

  get [Symbol.toStringTag] () {
    return 'LdapChange'
  }

  /**
   * The attribute that will be modified by the {@link Change}.
   *
   * @returns {import('@ldapjs/attribute')}
   */
  get modification () {
    return this.#modification
  }

  /**
   * Define the attribute to be modified by the {@link Change}.
   *
   * @param {object|import('@ldapjs/attribute')} mod
   *
   * @throws When `mod` is not an instance of `Attribute` or is not an
   * `Attribute` shaped object.
   */
  set modification (mod) {
    if (Attribute.isAttribute(mod) === false) {
      throw Error('modification must be an Attribute')
    }
    if (Object.prototype.toString.call(mod) !== '[object LdapAttribute]') {
      mod = new Attribute(mod)
    }
    this.#modification = mod
  }

  /**
   * Get a plain JavaScript object representation of the change.
   *
   * @returns {object}
   */
  get pojo () {
    return {
      operation: this.operation,
      modification: this.modification.pojo
    }
  }

  /**
   * The string name of the operation that will be performed.
   *
   * @returns {string} One of `add`, `delete`, or `replace`.
   */
  get operation () {
    switch (this.#operation) {
      case 0x00: {
        return 'add'
      }

      case 0x01: {
        return 'delete'
      }

      case 0x02: {
        return 'replace'
      }
    }
  }

  /**
   * Define the operation that the {@link Change} represents.
   *
   * @param {string|number} op May be one of `add` (0), `delete` (1),
   * or `replace` (2).
   *
   * @throws When the `op` is not recognized.
   */
  set operation (op) {
    if (typeof op === 'string') {
      op = op.toLowerCase()
    }

    switch (op) {
      case 0x00:
      case 'add': {
        this.#operation = 0x00
        break
      }

      case 0x01:
      case 'delete': {
        this.#operation = 0x01
        break
      }

      case 0x02:
      case 'replace': {
        this.#operation = 0x02
        break
      }

      default: {
        const type = Number.isInteger(op)
          ? '0x' + Number(op).toString(16)
          : op
        throw Error(`invalid operation type: ${type}`)
      }
    }
  }

  /**
   * Serialize the instance to a BER.
   *
   * @returns {import('@ldapjs/asn1').BerReader}
   */
  toBer () {
    const writer = new BerWriter()
    writer.startSequence()
    writer.writeEnumeration(this.#operation)

    const attrBer = this.#modification.toBer()
    writer.appendBuffer(attrBer.buffer)
    writer.endSequence()

    return new BerReader(writer.buffer)
  }

  /**
   * See {@link pojo}.
   *
   * @returns {object}
   */
  toJSON () {
    return this.pojo
  }

  /**
   * Applies a {@link Change} to a `target` object.
   *
   * @example
   * const change = new Change({
   *   operation: 'add',
   *   modification: {
   *     type: 'cn',
   *     values: ['new']
   *   }
   * })
   * const target = {
   *   cn: ['old']
   * }
   * Change.apply(change, target)
   * // target = { cn: ['old', 'new'] }
   *
   * @param {Change} change The change to apply.
   * @param {object} target The object to modify. This object will be mutated
   * by the function. It should have properties that match the `modification`
   * of the change.
   * @param {boolean} scalar When `true`, will convert single-item arrays
   * to scalar values. Default: `false`.
   *
   * @returns {object} The mutated `target`.
   *
   * @throws When the `change` is not an instance of {@link Change}.
   */
  static apply (change, target, scalar = false) {
    if (Change.isChange(change) === false) {
      throw Error('change must be an instance of Change')
    }

    const type = change.modification.type
    const values = change.modification.values

    let data = target[type]
    if (data === undefined) {
      data = []
    } else if (Array.isArray(data) === false) {
      data = [data]
    }

    switch (change.operation) {
      case 'add': {
        // Add only new unique entries.
        const newValues = values.filter(v => data.indexOf(v) === -1)
        Array.prototype.push.apply(data, newValues)
        break
      }

      case 'delete': {
        data = data.filter(v => values.indexOf(v) === -1)
        if (data.length === 0) {
          // An empty list indicates the attribute should be removed
          // completely.
          delete target[type]
          return target
        }
        break
      }

      case 'replace': {
        if (values.length === 0) {
          // A new value set that is empty is a delete.
          delete target[type]
          return target
        }
        data = values
        break
      }
    }

    if (scalar === true && data.length === 1) {
      // Replace array value with a scalar value if the modified set is
      // single valued and the operation calls for a scalar.
      target[type] = data[0]
    } else {
      target[type] = data
    }

    return target
  }

  /**
   * Determines if an object is an instance of {@link Change}, or at least
   * resembles the shape of a {@link Change} object. A plain object will match
   * if it has a `modification` property that matches an `Attribute`,
   * an `operation` property that is a string or number, and has a `toBer`
   * method. An object that resembles a {@link Change} does not guarantee
   * compatibility. A `toString` check is much more accurate.
   *
   * @param {Change|object} change
   *
   * @returns {boolean}
   */
  static isChange (change) {
    if (Object.prototype.toString.call(change) === '[object LdapChange]') {
      return true
    }
    if (Object.prototype.toString.call(change) !== '[object Object]') {
      return false
    }
    if (
      Attribute.isAttribute(change.modification) === true &&
      (typeof change.operation === 'string' || typeof change.operation === 'number')
    ) {
      return true
    }
    return false
  }

  /**
   * Compares two {@link Change} instance to determine the priority of the
   * changes relative to each other.
   *
   * @param {Change} change1
   * @param {Change} change2
   *
   * @returns {number} -1 for lower priority, 1 for higher priority, and 0
   * for equal priority in relation to `change1`, e.g. -1 would mean `change`
   * has lower priority than `change2`.
   *
   * @throws When neither parameter resembles a {@link Change} object.
   */
  static compare (change1, change2) {
    if (Change.isChange(change1) === false || Change.isChange(change2) === false) {
      throw Error('can only compare Change instances')
    }
    if (change1.operation < change2.operation) {
      return -1
    }
    if (change1.operation > change2.operation) {
      return 1
    }
    return Attribute.compare(change1.modification, change2.modification)
  }

  /**
   * Parse a BER into a new {@link Change} object.
   *
   * @param {import('@ldapjs/asn1').BerReader} ber The BER to process. It must
   * be at an offset that starts a new change sequence. The reader will be
   * advanced to the end of the change sequence by this method.
   *
   * @returns {Change}
   *
   * @throws When there is an error processing the BER.
   */
  static fromBer (ber) {
    ber.readSequence()
    const operation = ber.readEnumeration()
    const modification = Attribute.fromBer(ber)
    return new Change({ operation, modification })
  }
}

module.exports = Change

},{"@ldapjs/asn1":2,"@ldapjs/attribute":7}],10:[function(require,module,exports){
'use strict'

const { Ber } = require('@ldapjs/asn1')

const Control = require('./lib/control')
const EntryChangeNotificationControl = require('./lib/controls/entry-change-notification-control')
const PagedResultsControl = require('./lib/controls/paged-results-control')
const PersistentSearchControl = require('./lib/controls/persistent-search-control')
const ServerSideSortingRequestControl = require('./lib/controls/server-side-sorting-request-control')
const ServerSideSortingResponseControl = require('./lib/controls/server-side-sorting-response-control')
const VirtualListViewRequestControl = require('./lib/controls/virtual-list-view-request-control')
const VirtualListViewResponseControl = require('./lib/controls/virtual-list-view-response-control')

module.exports = {

  getControl: function getControl (ber) {
    if (!ber) throw TypeError('ber must be provided')

    if (ber.readSequence() === null) { return null }

    let type
    const opts = {
      criticality: false,
      value: null
    }

    /* istanbul ignore else */
    if (ber.length) {
      const end = ber.offset + ber.length

      type = ber.readString()
      /* istanbul ignore else */
      if (ber.offset < end) {
        /* istanbul ignore else */
        if (ber.peek() === Ber.Boolean) { opts.criticality = ber.readBoolean() }
      }

      if (ber.offset < end) { opts.value = ber.readString(Ber.OctetString, true) }
    }

    let control
    switch (type) {
      case EntryChangeNotificationControl.OID: {
        control = new EntryChangeNotificationControl(opts)
        break
      }

      case PagedResultsControl.OID: {
        control = new PagedResultsControl(opts)
        break
      }

      case PersistentSearchControl.OID: {
        control = new PersistentSearchControl(opts)
        break
      }

      case ServerSideSortingRequestControl.OID: {
        control = new ServerSideSortingRequestControl(opts)
        break
      }

      case ServerSideSortingResponseControl.OID: {
        control = new ServerSideSortingResponseControl(opts)
        break
      }

      case VirtualListViewRequestControl.OID: {
        control = new VirtualListViewRequestControl(opts)
        break
      }

      case VirtualListViewResponseControl.OID: {
        control = new VirtualListViewResponseControl(opts)
        break
      }

      default: {
        opts.type = type
        control = new Control(opts)
        break
      }
    }

    return control
  },

  Control,
  EntryChangeNotificationControl,
  PagedResultsControl,
  PersistentSearchControl,
  ServerSideSortingRequestControl,
  ServerSideSortingResponseControl,
  VirtualListViewRequestControl,
  VirtualListViewResponseControl
}

},{"./lib/control":11,"./lib/controls/entry-change-notification-control":12,"./lib/controls/paged-results-control":13,"./lib/controls/persistent-search-control":14,"./lib/controls/server-side-sorting-request-control":15,"./lib/controls/server-side-sorting-response-control":16,"./lib/controls/virtual-list-view-request-control":17,"./lib/controls/virtual-list-view-response-control":18,"@ldapjs/asn1":26}],11:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { BerWriter } = require('@ldapjs/asn1')

/**
 * Baseline LDAP control object. Implements
 * https://tools.ietf.org/html/rfc4511#section-4.1.11
 *
 * @class
 */
class Control {
  /**
   * @typedef {object} ControlParams
   * @property {string} [type=''] The dotted decimal control type value.
   * @property {boolean} [criticality=false] Criticality value for the control.
   * @property {string|Buffer} [value] The value for the control. If this is
   * a `string` then it will be written as-is. If it is an instance of `Buffer`
   * then it will be written by `value.toString()` when generating a BER
   * instance.
   */

  /**
   * Create a new baseline LDAP control.
   *
   * @param {ControlParams} [options]
   */
  constructor (options = {}) {
    const opts = Object.assign({ type: '', criticality: false, value: null }, options)
    this.type = opts.type
    this.criticality = opts.criticality
    this.value = opts.value
  }

  get [Symbol.toStringTag] () {
    return 'LdapControl'
  }

  /**
   * Serializes the control into a plain JavaScript object that can be passed
   * to the constructor as an options object. If an instance has a `_pojo(obj)`
   * method then the built object will be sent to that method and the resulting
   * mutated object returned.
   *
   * @returns {object} A plain JavaScript object that represents an LDAP control.
   */
  get pojo () {
    const obj = {
      type: this.type,
      value: this.value,
      criticality: this.criticality
    }

    if (typeof this._pojo === 'function') {
      this._pojo(obj)
    }

    return obj
  }

  /**
   * Converts the instance into a [BER](http://luca.ntop.org/Teaching/Appunti/asn1.html)
   * representation.
   *
   * @param {BerWriter} [ber] An empty `BerWriter` instance to populate.
   *
   * @returns {object} A BER object.
   */
  toBer (ber = new BerWriter()) {
    ber.startSequence()
    ber.writeString(this.type || '')
    ber.writeBoolean(this.criticality)

    /* istanbul ignore else */
    if (typeof (this._toBer) === 'function') {
      this._toBer(ber)
    } else if (this.value !== undefined) {
      if (typeof this.value === 'string') {
        ber.writeString(this.value)
      } else if (Buffer.isBuffer(this.value)) {
        ber.writeString(this.value.toString())
      }
    }

    ber.endSequence()
    return ber
  }
}
module.exports = Control

}).call(this)}).call(this,{"isBuffer":require("../../../is-buffer/index.js")})
},{"../../../is-buffer/index.js":128,"@ldapjs/asn1":26}],12:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { BerReader, BerWriter } = require('@ldapjs/asn1')
const isObject = require('../is-object')
const hasOwn = require('../has-own')
const Control = require('../control')

/**
 * @typedef {object} EntryChangeNotificationControlValue
 * @property {number} changeType One of 1 (add), 2 (delete), 4 (modify),
 * or 8 (modifyDN).
 * @property {string} previousDN Only set when operation is a modifyDN op.
 * @property {number} changeNumber
 */

/**
 * Implements:
 * https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-psearch-03.txt#section-5
 *
 * @extends Control
 */
class EntryChangeNotificationControl extends Control {
  static OID = '2.16.840.1.113730.3.4.7'

  /**
   * @typedef {ControlParams} EntryChangeNotificationParams
   * @property {EntryChangeNotificationControlValue | Buffer} [value]
   */

  /**
   * Creates a new persistent search control.
   *
   * @param {EntryChangeNotificationParams} [options]
   */
  constructor (options = {}) {
    options.type = EntryChangeNotificationControl.OID
    super(options)

    this._value = {
      changeType: 4
    }

    if (hasOwn(options, 'value') === false) {
      return
    }

    if (Buffer.isBuffer(options.value)) {
      this.parse(options.value)
    } else if (isObject(options.value)) {
      this._value = options.value
    } else {
      throw new TypeError('options.value must be a Buffer or Object')
    }
  }

  get value () {
    return this._value
  }

  set value (obj) {
    this._value = Object.assign({}, this._value, obj)
  }

  /**
   * Given a BER buffer that represents a
   * {@link EntryChangeNotificationControlValue}, read that buffer into the
   * current instance.
   */
  parse (buffer) {
    const ber = new BerReader(buffer)
    /* istanbul ignore else */
    if (ber.readSequence()) {
      this._value = {
        changeType: ber.readInt()
      }

      /* istanbul ignore else */
      if (this._value.changeType === 8) {
        // If the operation was moddn, then parse the optional previousDN attr.
        this._value.previousDN = ber.readString()
      }

      this._value.changeNumber = ber.readInt()
    }
  }

  _toBer (ber) {
    const writer = new BerWriter()
    writer.startSequence()
    writer.writeInt(this._value.changeType)
    if (this._value.previousDN) { writer.writeString(this._value.previousDN) }

    if (Object.prototype.hasOwnProperty.call(this._value, 'changeNumber')) {
      writer.writeInt(parseInt(this._value.changeNumber, 10))
    }
    writer.endSequence()

    ber.writeBuffer(writer.buffer, 0x04)
    return ber
  }

  _updatePlainObject (obj) {
    obj.controlValue = this.value
    return obj
  }
}
module.exports = EntryChangeNotificationControl

}).call(this)}).call(this,{"isBuffer":require("../../../../is-buffer/index.js")})
},{"../../../../is-buffer/index.js":128,"../control":11,"../has-own":19,"../is-object":20,"@ldapjs/asn1":26}],13:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { Ber, BerReader, BerWriter } = require('@ldapjs/asn1')
const isObject = require('../is-object')
const hasOwn = require('../has-own')
const Control = require('../control')

/**
 * @typedef {object} PagedResultsControlValue
 * @property {number} size The requested page size from a client, or the result
 * set size estimate from the server.
 * @property {Buffer} cookie Identifier for the result set.
 */

/**
 * Implements:
 * https://datatracker.ietf.org/doc/html/rfc2696#section-2
 *
 * @extends Control
 */
class PagedResultsControl extends Control {
  static OID = '1.2.840.113556.1.4.319'

  /**
   * @typedef {ControlParams} PagedResultsParams
   * @property {PagedResultsControlValue | Buffer} [value]
   */

  /**
   * Creates a new paged results control.
   *
   * @param {PagedResultsParams} [options]
   */
  constructor (options = {}) {
    options.type = PagedResultsControl.OID
    super(options)

    this._value = {
      size: 0,
      cookie: Buffer.alloc(0)
    }

    if (hasOwn(options, 'value') === false) {
      return
    }

    if (Buffer.isBuffer(options.value)) {
      this.parse(options.value)
    } else if (isObject(options.value)) {
      this.value = options.value
    } else {
      throw new TypeError('options.value must be a Buffer or Object')
    }
  }

  get value () {
    return this._value
  }

  set value (obj) {
    this._value = Object.assign({}, this._value, obj)
    if (typeof this._value.cookie === 'string') {
      this._value.cookie = Buffer.from(this._value.cookie)
    }
  }

  parse (buffer) {
    const ber = new BerReader(buffer)

    /* istanbul ignore else */
    if (ber.readSequence()) {
      this._value = {}
      this._value.size = ber.readInt()
      this._value.cookie = ber.readString(Ber.OctetString, true)
      // readString returns '' instead of a zero-length buffer
      if (!this._value.cookie) {
        this._value.cookie = Buffer.alloc(0)
      }
    }
  }

  _toBer (ber) {
    const writer = new BerWriter()
    writer.startSequence()
    writer.writeInt(this._value.size)
    if (this._value.cookie && this._value.cookie.length > 0) {
      writer.writeBuffer(this._value.cookie, Ber.OctetString)
    } else {
      // writeBuffer rejects zero-length buffers
      writer.writeString('')
    }
    writer.endSequence()

    ber.writeBuffer(writer.buffer, Ber.OctetString)
    return ber
  }

  _updatePlainObject (obj) {
    obj.controlValue = this.value
    return obj
  }
}
module.exports = PagedResultsControl

}).call(this)}).call(this,require("buffer").Buffer)
},{"../control":11,"../has-own":19,"../is-object":20,"@ldapjs/asn1":26,"buffer":110}],14:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { BerReader, BerWriter } = require('@ldapjs/asn1')
const isObject = require('../is-object')
const hasOwn = require('../has-own')
const Control = require('../control')

/**
 * @typedef {object} PersistentSearchControlValue
 * @property {number} changeTypes A bitwise OR of 1 (add), 2 (delete),
 * 4 (modify), and 8 (modifyDN).
 * @property {boolean} changesOnly
 * @property {boolean} returnECs
 */

/**
 * Implements:
 * https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-psearch-03.txt
 *
 * @extends Control
 */
class PersistentSearchControl extends Control {
  static OID = '2.16.840.1.113730.3.4.3'

  /**
   * @typedef {ControlParams} PersistentSearchParams
   * @property {PersistentSearchControlValue | Buffer} [value]
   */

  /**
   * Creates a new persistent search control.
   *
   * @param {PersistentSearchParams} [options]
   */
  constructor (options = {}) {
    options.type = PersistentSearchControl.OID
    super(options)

    this._value = {
      changeTypes: 15,
      changesOnly: true,
      returnECs: true
    }

    if (hasOwn(options, 'value') === false) {
      return
    }

    if (Buffer.isBuffer(options.value)) {
      this.parse(options.value)
    } else if (isObject(options.value)) {
      this._value = options.value
    } else {
      throw new TypeError('options.value must be a Buffer or Object')
    }
  }

  get value () {
    return this._value
  }

  set value (obj) {
    this._value = Object.assign({}, this._value, obj)
  }

  /**
   * Given a BER buffer that represents a {@link PersistentSearchControlValue},
   * read that buffer into the current instance.
   */
  parse (buffer) {
    const ber = new BerReader(buffer)

    /* istanbul ignore else */
    if (ber.readSequence()) {
      this._value = {
        changeTypes: ber.readInt(),
        changesOnly: ber.readBoolean(),
        returnECs: ber.readBoolean()
      }
    }
  }

  _toBer (ber) {
    const writer = new BerWriter()
    writer.startSequence()
    writer.writeInt(this._value.changeTypes)
    writer.writeBoolean(this._value.changesOnly)
    writer.writeBoolean(this._value.returnECs)
    writer.endSequence()

    ber.writeBuffer(writer.buffer, 0x04)
    return ber
  }

  _updatePlainObject (obj) {
    obj.controlValue = this.value
    return obj
  }
}
module.exports = PersistentSearchControl

}).call(this)}).call(this,{"isBuffer":require("../../../../is-buffer/index.js")})
},{"../../../../is-buffer/index.js":128,"../control":11,"../has-own":19,"../is-object":20,"@ldapjs/asn1":26}],15:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { Ber, BerReader, BerWriter } = require('@ldapjs/asn1')
const isObject = require('../is-object')
const hasOwn = require('../has-own')
const Control = require('../control')

/**
 * @typedef {object} SortKeyItem
 * @property {string} attributeType
 * @property {string} orderingRule
 * @property {boolean} reverseOrder
 */

/**
 * @typedef {SortKeyItem[]} ServerSideSortingRequestControlValue
 */

/**
 * Implements:
 * https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-sorting#section-3.1
 *
 * @extends Control
 */
class ServerSideSortingRequestControl extends Control {
  static OID = '1.2.840.113556.1.4.473'

  /**
   * @typedef {ControlParams} ServerSideSortingRequestParams
   * @property {ServerSideSortingRequestControlValue | SortKeyItem | Buffer} [value]
   */

  /**
   * Creates a new server side sorting request control.
   *
   * @param {ServerSideSortingRequestParams} [options]
   */
  constructor (options = { value: [] }) {
    options.type = ServerSideSortingRequestControl.OID
    super(options)

    const inputValue = options.value ?? []
    if (Buffer.isBuffer(inputValue)) {
      this.parse(inputValue)
    } else if (Array.isArray(inputValue)) {
      for (const obj of inputValue) {
        if (isObject(obj) === false) {
          throw new Error('Control value must be an object')
        }
        if (hasOwn(obj, 'attributeType') === false) {
          throw new Error('Missing required key: attributeType')
        }
      }
      this.value = inputValue
    } else if (isObject(inputValue)) {
      if (hasOwn(inputValue, 'attributeType') === false) {
        throw new Error('Missing required key: attributeType')
      }
      this.value = [inputValue]
    } else {
      throw new TypeError('options.value must be a Buffer, Array or Object')
    }
  }

  get value () {
    return this._value
  }

  set value (items) {
    if (Buffer.isBuffer(items) === true) return
    if (Array.isArray(items) === false) {
      this._value = [items]
      return
    }
    this._value = items
  }

  parse (buffer) {
    const ber = new BerReader(buffer)
    let item
    /* istanbul ignore else */
    if (ber.readSequence(0x30)) {
      this.value = []

      while (ber.readSequence(0x30)) {
        item = {}
        item.attributeType = ber.readString(Ber.OctetString)
        /* istanbul ignore else */
        if (ber.peek() === 0x80) {
          item.orderingRule = ber.readString(0x80)
        }
        /* istanbul ignore else */
        if (ber.peek() === 0x81) {
          item.reverseOrder = (ber._readTag(0x81) !== 0)
        }
        this.value.push(item)
      }
    }
  }

  _pojo (obj) {
    obj.value = this.value
    return obj
  }

  _toBer (ber) {
    if (this.value.length === 0) { return }

    const writer = new BerWriter()
    writer.startSequence(0x30)
    for (let i = 0; i < this.value.length; i++) {
      const item = this.value[i]
      writer.startSequence(0x30)
      /* istanbul ignore else */
      if (hasOwn(item, 'attributeType')) {
        writer.writeString(item.attributeType, Ber.OctetString)
      }
      /* istanbul ignore else */
      if (hasOwn(item, 'orderingRule')) {
        writer.writeString(item.orderingRule, 0x80)
      }
      /* istanbul ignore else */
      if (hasOwn(item, 'reverseOrder')) {
        writer.writeBoolean(item.reverseOrder, 0x81)
      }
      writer.endSequence()
    }
    writer.endSequence()
    ber.writeBuffer(writer.buffer, 0x04)
  }
}
module.exports = ServerSideSortingRequestControl

}).call(this)}).call(this,{"isBuffer":require("../../../../is-buffer/index.js")})
},{"../../../../is-buffer/index.js":128,"../control":11,"../has-own":19,"../is-object":20,"@ldapjs/asn1":26}],16:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { BerReader, BerWriter } = require('@ldapjs/asn1')
const Control = require('../control')
const isObject = require('../is-object')
const hasOwn = require('../has-own')
const { resultCodes: RESULT_CODES } = require('@ldapjs/protocol')

const validCodeNames = [
  'SUCCESS',
  'OPERATIONS_ERROR',
  'TIME_LIMIT_EXCEEDED',
  'STRONGER_AUTH_REQUIRED',
  'ADMIN_LIMIT_EXCEEDED',
  'NO_SUCH_ATTRIBUTE',
  'INAPPROPRIATE_MATCHING',
  'INSUFFICIENT_ACCESS_RIGHTS',
  'BUSY',
  'UNWILLING_TO_PERFORM',
  'OTHER'
]

const filteredCodes = Object.entries(RESULT_CODES).filter(([k, v]) => validCodeNames.includes(k))
const VALID_CODES = new Map([
  ...filteredCodes,
  ...filteredCodes.map(([k, v]) => { return [v, k] })
])

/**
 * @typedef {object} ServerSideSortingResponseControlResult
 * @property {number} result
 * @property {string} failedAttribute
 */

/**
 * Implements:
 * https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-sorting#section-3.2
 *
 * @extends Control
 */
class ServerSideSortingResponseControl extends Control {
  static OID = '1.2.840.113556.1.4.474'

  /**
   * A map of possible response codes. Includes `CODE => VALUE` and
   * `VALUE => CODE`. For example, `RESPONSE_CODES.get(0)` returns
   * `LDAP_SUCCESS`, and `RESPONSE_CODES.get('LDAP_SUCCESS')` returns `0`.
   */
  static RESPONSE_CODES = Object.freeze(VALID_CODES)

  /**
   * @typedef {ControlParams} ServerSideSortingResponseParams
   * @property {ServerSideSortingResponseControlResult | Buffer} value
   */

  /**
   * Creates a new server side sorting response control.
   *
   * @param {ServerSideSortingResponseParams} [options]
   */
  constructor (options = {}) {
    options.type = ServerSideSortingResponseControl.OID
    options.criticality = false
    super(options)

    this.value = {}

    if (hasOwn(options, 'value') === false || !options.value) {
      return
    }

    const value = options.value
    if (Buffer.isBuffer(value)) {
      this.parse(value)
    } else if (isObject(value)) {
      if (VALID_CODES.has(value.result) === false) {
        throw new Error('Invalid result code')
      }
      if (hasOwn(value, 'failedAttribute') && (typeof value.failedAttribute) !== 'string') {
        throw new Error('failedAttribute must be String')
      }

      this.value = value
    } else {
      throw new TypeError('options.value must be a Buffer or Object')
    }
  }

  get value () {
    return this._value
  }

  set value (obj) {
    this._value = Object.assign({}, this._value, obj)
  }

  parse (buffer) {
    const ber = new BerReader(buffer)
    /* istanbul ignore else */
    if (ber.readSequence(0x30)) {
      this._value = {}
      this._value.result = ber.readEnumeration()
      /* istanbul ignore else */
      if (ber.peek() === 0x80) {
        this._value.failedAttribute = ber.readString(0x80)
      }
    }
  }

  _pojo (obj) {
    obj.value = this.value
    return obj
  }

  _toBer (ber) {
    if (!this._value || Object.keys(this._value).length === 0) { return }

    const writer = new BerWriter()
    writer.startSequence(0x30)
    writer.writeEnumeration(this.value.result)
    /* istanbul ignore else */
    if (this.value.result !== RESULT_CODES.SUCCESS && this.value.failedAttribute) {
      writer.writeString(this.value.failedAttribute, 0x80)
    }
    writer.endSequence()
    ber.writeBuffer(writer.buffer, 0x04)
  }
}
module.exports = ServerSideSortingResponseControl

}).call(this)}).call(this,{"isBuffer":require("../../../../is-buffer/index.js")})
},{"../../../../is-buffer/index.js":128,"../control":11,"../has-own":19,"../is-object":20,"@ldapjs/asn1":26,"@ldapjs/protocol":93}],17:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { BerReader, BerWriter } = require('@ldapjs/asn1')
const isObject = require('../is-object')
const hasOwn = require('../has-own')
const Control = require('../control')

/**
 * @typedef {object} VirtualListViewControlValue
 * @property {number} beforeCount
 * @property {number} afterCount
 *
 */

/**
 * Implements:
 * https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-ldapv3-vlv-07#section-6.1
 *
 * @extends Control
 */
class VirtualListViewRequestControl extends Control {
  static OID = '2.16.840.1.113730.3.4.9'

  /**
   * @typedef {ControlParams} VirtualListViewRequestParams
   * @property {Buffer|VirtualListViewControlValue} [value]
   */

  /**
   * @param {VirtualListViewRequestParams} [options]
   */
  constructor (options = {}) {
    options.type = VirtualListViewRequestControl.OID
    super(options)

    if (hasOwn(options, 'value') === false) {
      // return
      throw Error('control is not enabled')
    }

    if (Buffer.isBuffer(options.value)) {
      this.parse(options.value)
    } else if (isObject(options.value)) {
      if (Object.prototype.hasOwnProperty.call(options.value, 'beforeCount') === false) {
        throw new Error('Missing required key: beforeCount')
      }
      if (Object.prototype.hasOwnProperty.call(options.value, 'afterCount') === false) {
        throw new Error('Missing required key: afterCount')
      }
      this._value = options.value
    } else {
      throw new TypeError('options.value must be a Buffer or Object')
    }

    throw Error('control is not enabled')
  }

  get value () {
    return this._value
  }

  set value (items) {
    if (Buffer.isBuffer(items) === true) return
    if (Array.isArray(items) === false) {
      this._value = [items]
      return
    }
    this._value = items
  }

  parse (buffer) {
    const ber = new BerReader(buffer)
    if (ber.readSequence()) {
      this._value = {}
      this._value.beforeCount = ber.readInt()
      this._value.afterCount = ber.readInt()
      if (ber.peek() === 0xa0) {
        if (ber.readSequence(0xa0)) {
          this._value.targetOffset = ber.readInt()
          this._value.contentCount = ber.readInt()
        }
      }
      if (ber.peek() === 0x81) {
        this._value.greaterThanOrEqual = ber.readString(0x81)
      }
      return true
    }
    return false
  }

  _pojo (obj) {
    obj.value = this.value
    return obj
  }

  _toBer (ber) {
    if (!this._value || this._value.length === 0) {
      return
    }
    const writer = new BerWriter()
    writer.startSequence(0x30)
    writer.writeInt(this._value.beforeCount)
    writer.writeInt(this._value.afterCount)
    if (this._value.targetOffset !== undefined) {
      writer.startSequence(0xa0)
      writer.writeInt(this._value.targetOffset)
      writer.writeInt(this._value.contentCount)
      writer.endSequence()
    } else if (this._value.greaterThanOrEqual !== undefined) {
      writer.writeString(this._value.greaterThanOrEqual, 0x81)
    }
    writer.endSequence()
    ber.writeBuffer(writer.buffer, 0x04)
  }
}
module.exports = VirtualListViewRequestControl

}).call(this)}).call(this,{"isBuffer":require("../../../../is-buffer/index.js")})
},{"../../../../is-buffer/index.js":128,"../control":11,"../has-own":19,"../is-object":20,"@ldapjs/asn1":26}],18:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { Ber, BerReader, BerWriter } = require('@ldapjs/asn1')
const isObject = require('../is-object')
const hasOwn = require('../has-own')
const Control = require('../control')
const { resultCodes: RESULT_CODES } = require('@ldapjs/protocol')

const validCodeNames = [
  'SUCCESS',
  'OPERATIONS_ERROR',
  'UNWILLING_TO_PERFORM',
  'INSUFFICIENT_ACCESS_RIGHTS',
  'BUSY',
  'TIME_LIMIT_EXCEEDED',
  'STRONGER_AUTH_REQUIRED',
  'ADMIN_LIMIT_EXCEEDED',
  'SORT_CONTROL_MISSING',
  'OFFSET_RANGE_ERROR',
  'CONTROL_ERROR',
  'OTHER'
]

const filteredCodes = Object.entries(RESULT_CODES).filter(([k, v]) => validCodeNames.includes(k))
const VALID_CODES = new Map([
  ...filteredCodes,
  ...filteredCodes.map(([k, v]) => { return [v, k] })
])

// TODO: complete this doc block based on the "implements" spec link
/**
 * @typedef {object} VirtualListViewResponseControlValue
 * @property {number} result A valid LDAP response code for the control.
 */

/**
 * Implements:
 * https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-ldapv3-vlv-07#section-6.2
 *
 * @extends Control
 */
class VirtualListViewResponseControl extends Control {
  static OID = '2.16.840.1.113730.3.4.10'

  /**
   * A map of possible response codes. Includes `CODE => VALUE` and
   * `VALUE => CODE`. For example, `RESPONSE_CODES.get(0)` returns
   * `LDAP_SUCCESS`, and `RESPONSE_CODES.get('LDAP_SUCCESS')` returns `0`.
   */
  static RESPONSE_CODES = Object.freeze(VALID_CODES)

  /**
   * @typedef {ControlParams} VirtualListViewResponseParams
   * @property {Buffer|VirtualListViewResponseControlValue} [value]
   */

  /**
   * @param {VirtualListViewResponseParams} options
   */
  constructor (options = {}) {
    options.type = VirtualListViewResponseControl.OID
    options.criticality = false
    super(options)

    this.value = {}

    if (hasOwn(options, 'value') === false || !options.value) {
      // return
      throw Error('control not enabled')
    }

    const value = options.value
    if (Buffer.isBuffer(value)) {
      this.parse(options.value)
    } else if (isObject(value)) {
      if (VALID_CODES.has(value.result) === false) {
        throw new Error('Invalid result code')
      }
      this.value = options.value
    } else {
      throw new TypeError('options.value must be a Buffer or Object')
    }

    throw Error('control not enabled')
  }

  get value () {
    return this._value
  }

  set value (obj) {
    this._value = Object.assign({}, this._value, obj)
  }

  parse (buffer) {
    const ber = new BerReader(buffer)
    if (ber.readSequence()) {
      this._value = {}

      if (ber.peek(0x02)) {
        this._value.targetPosition = ber.readInt()
      }

      if (ber.peek(0x02)) {
        this._value.contentCount = ber.readInt()
      }

      this._value.result = ber.readEnumeration()
      this._value.cookie = ber.readString(Ber.OctetString, true)

      // readString returns '' instead of a zero-length buffer
      if (!this._value.cookie) {
        this._value.cookie = Buffer.alloc(0)
      }

      return true
    }

    return false
  }

  _pojo (obj) {
    obj.value = this.value
    return obj
  }

  _toBer (ber) {
    if (this.value.length === 0) { return }

    const writer = new BerWriter()
    writer.startSequence()
    if (this.value.targetPosition !== undefined) {
      writer.writeInt(this.value.targetPosition)
    }
    if (this.value.contentCount !== undefined) {
      writer.writeInt(this.value.contentCount)
    }

    writer.writeEnumeration(this.value.result)
    if (this.value.cookie && this.value.cookie.length > 0) {
      writer.writeBuffer(this.value.cookie, Ber.OctetString)
    } else {
      writer.writeString('') // writeBuffer rejects zero-length buffers
    }

    writer.endSequence()
    ber.writeBuffer(writer.buffer, 0x04)
  }
}
module.exports = VirtualListViewResponseControl

}).call(this)}).call(this,require("buffer").Buffer)
},{"../control":11,"../has-own":19,"../is-object":20,"@ldapjs/asn1":26,"@ldapjs/protocol":93,"buffer":110}],19:[function(require,module,exports){
'use strict'

module.exports = function hasOwn (obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop)
}

},{}],20:[function(require,module,exports){
'use strict'

module.exports = function isObject (input) {
  return Object.prototype.toString.call(input) === '[object Object]'
}

},{}],21:[function(require,module,exports){
// Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.

module.exports = {

  newInvalidAsn1Error: function (msg) {
    const e = new Error()
    e.name = 'InvalidAsn1Error'
    e.message = msg || ''
    return e
  }

}

},{}],22:[function(require,module,exports){
// Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.

const errors = require('./errors')
const types = require('./types')

const Reader = require('./reader')
const Writer = require('./writer')

// --- Exports

module.exports = {

  Reader: Reader,

  Writer: Writer

}

for (const t in types) {
  if (Object.prototype.hasOwnProperty.call(types, t)) { module.exports[t] = types[t] }
}
for (const e in errors) {
  if (Object.prototype.hasOwnProperty.call(errors, e)) { module.exports[e] = errors[e] }
}

},{"./errors":21,"./reader":23,"./types":24,"./writer":25}],23:[function(require,module,exports){
(function (Buffer){(function (){
// Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.

const assert = require('assert')
const ASN1 = require('./types')
const errors = require('./errors')

// --- Globals

const newInvalidAsn1Error = errors.newInvalidAsn1Error

// --- API

function Reader (data) {
  if (!data || !Buffer.isBuffer(data)) { throw new TypeError('data must be a node Buffer') }

  this._buf = data
  this._size = data.length

  // These hold the "current" state
  this._len = 0
  this._offset = 0
}

Object.defineProperty(Reader.prototype, Symbol.toStringTag, { value: 'BerReader' })

Object.defineProperty(Reader.prototype, 'length', {
  enumerable: true,
  get: function () { return (this._len) }
})

Object.defineProperty(Reader.prototype, 'offset', {
  enumerable: true,
  get: function () { return (this._offset) }
})

Object.defineProperty(Reader.prototype, 'remain', {
  get: function () { return (this._size - this._offset) }
})

Object.defineProperty(Reader.prototype, 'buffer', {
  get: function () { return (this._buf.slice(this._offset)) }
})

/**
 * Reads a single byte and advances offset; you can pass in `true` to make this
 * a "peek" operation (i.e., get the byte, but don't advance the offset).
 *
 * @param {Boolean} peek true means don't move offset.
 * @return {Number} the next byte, null if not enough data.
 */
Reader.prototype.readByte = function (peek) {
  if (this._size - this._offset < 1) { return null }

  const b = this._buf[this._offset] & 0xff

  if (!peek) { this._offset += 1 }

  return b
}

Reader.prototype.peek = function () {
  return this.readByte(true)
}

/**
 * Reads a (potentially) variable length off the BER buffer.  This call is
 * not really meant to be called directly, as callers have to manipulate
 * the internal buffer afterwards.
 *
 * As a result of this call, you can call `Reader.length`, until the
 * next thing called that does a readLength.
 *
 * @return {Number} the amount of offset to advance the buffer.
 * @throws {InvalidAsn1Error} on bad ASN.1
 */
Reader.prototype.readLength = function (offset) {
  if (offset === undefined) { offset = this._offset }

  if (offset >= this._size) { return null }

  let lenB = this._buf[offset++] & 0xff
  if (lenB === null) { return null }

  if ((lenB & 0x80) === 0x80) {
    lenB &= 0x7f

    if (lenB === 0) { throw newInvalidAsn1Error('Indefinite length not supported') }

    if (lenB > 4) { throw newInvalidAsn1Error('encoding too long') }

    if (this._size - offset < lenB) { return null }

    this._len = 0
    for (let i = 0; i < lenB; i++) { this._len = (this._len << 8) + (this._buf[offset++] & 0xff) }
  } else {
    // Wasn't a variable length
    this._len = lenB
  }

  return offset
}

/**
 * Parses the next sequence in this BER buffer.
 *
 * To get the length of the sequence, call `Reader.length`.
 *
 * @return {Number} the sequence's tag.
 */
Reader.prototype.readSequence = function (tag) {
  const seq = this.peek()
  if (seq === null) { return null }
  if (tag !== undefined && tag !== seq) {
    throw newInvalidAsn1Error('Expected 0x' + tag.toString(16) +
                              ': got 0x' + seq.toString(16))
  }

  const o = this.readLength(this._offset + 1) // stored in `length`
  if (o === null) { return null }

  this._offset = o
  return seq
}

Reader.prototype.readInt = function () {
  return this._readTag(ASN1.Integer)
}

Reader.prototype.readBoolean = function (tag) {
  return (this._readTag(tag || ASN1.Boolean) !== 0)
}

Reader.prototype.readEnumeration = function () {
  return this._readTag(ASN1.Enumeration)
}

Reader.prototype.readString = function (tag, retbuf) {
  if (!tag) { tag = ASN1.OctetString }

  const b = this.peek()
  if (b === null) { return null }

  if (b !== tag) {
    throw newInvalidAsn1Error('Expected 0x' + tag.toString(16) +
                              ': got 0x' + b.toString(16))
  }

  const o = this.readLength(this._offset + 1) // stored in `length`

  if (o === null) { return null }

  if (this.length > this._size - o) { return null }

  this._offset = o

  if (this.length === 0) { return retbuf ? Buffer.alloc(0) : '' }

  const str = this._buf.slice(this._offset, this._offset + this.length)
  this._offset += this.length

  return retbuf ? str : str.toString('utf8')
}

Reader.prototype.readOID = function (tag) {
  if (!tag) { tag = ASN1.OID }

  const b = this.readString(tag, true)
  if (b === null) { return null }

  const values = []
  let value = 0

  for (let i = 0; i < b.length; i++) {
    const byte = b[i] & 0xff

    value <<= 7
    value += byte & 0x7f
    if ((byte & 0x80) === 0) {
      values.push(value)
      value = 0
    }
  }

  value = values.shift()
  values.unshift(value % 40)
  values.unshift((value / 40) >> 0)

  return values.join('.')
}

Reader.prototype._readTag = function (tag) {
  assert.ok(tag !== undefined)

  const b = this.peek()

  if (b === null) { return null }

  if (b !== tag) {
    throw newInvalidAsn1Error('Expected 0x' + tag.toString(16) +
                              ': got 0x' + b.toString(16))
  }

  const o = this.readLength(this._offset + 1) // stored in `length`
  if (o === null) { return null }

  if (this.length > 4) { throw newInvalidAsn1Error('Integer too long: ' + this.length) }

  if (this.length > this._size - o) { return null }
  this._offset = o

  const fb = this._buf[this._offset]
  let value = 0

  let i
  for (i = 0; i < this.length; i++) {
    value <<= 8
    value |= (this._buf[this._offset++] & 0xff)
  }

  if ((fb & 0x80) === 0x80 && i !== 4) { value -= (1 << (i * 8)) }

  return value >> 0
}

// --- Exported API

module.exports = Reader

}).call(this)}).call(this,require("buffer").Buffer)
},{"./errors":21,"./types":24,"assert":96,"buffer":110}],24:[function(require,module,exports){
// Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.

module.exports = {
  EOC: 0,
  Boolean: 1,
  Integer: 2,
  BitString: 3,
  OctetString: 4,
  Null: 5,
  OID: 6,
  ObjectDescriptor: 7,
  External: 8,
  Real: 9, // float
  Enumeration: 10,
  PDV: 11,
  Utf8String: 12,
  RelativeOID: 13,
  Sequence: 16,
  Set: 17,
  NumericString: 18,
  PrintableString: 19,
  T61String: 20,
  VideotexString: 21,
  IA5String: 22,
  UTCTime: 23,
  GeneralizedTime: 24,
  GraphicString: 25,
  VisibleString: 26,
  GeneralString: 28,
  UniversalString: 29,
  CharacterString: 30,
  BMPString: 31,
  Constructor: 32,
  Context: 128
}

},{}],25:[function(require,module,exports){
(function (Buffer){(function (){
// Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.

const assert = require('assert')
const ASN1 = require('./types')
const errors = require('./errors')

// --- Globals

const newInvalidAsn1Error = errors.newInvalidAsn1Error

const DEFAULT_OPTS = {
  size: 1024,
  growthFactor: 8
}

// --- Helpers

function merge (from, to) {
  assert.ok(from)
  assert.equal(typeof (from), 'object')
  assert.ok(to)
  assert.equal(typeof (to), 'object')

  const keys = Object.getOwnPropertyNames(from)
  keys.forEach(function (key) {
    if (to[key]) { return }

    const value = Object.getOwnPropertyDescriptor(from, key)
    Object.defineProperty(to, key, value)
  })

  return to
}

// --- API

function Writer (options) {
  options = merge(DEFAULT_OPTS, options || {})

  this._buf = Buffer.alloc(options.size || 1024)
  this._size = this._buf.length
  this._offset = 0
  this._options = options

  // A list of offsets in the buffer where we need to insert
  // sequence tag/len pairs.
  this._seq = []
}

Object.defineProperty(Writer.prototype, Symbol.toStringTag, { value: 'BerWriter' })

Object.defineProperty(Writer.prototype, 'buffer', {
  get: function () {
    if (this._seq.length) { throw newInvalidAsn1Error(this._seq.length + ' unended sequence(s)') }

    return (this._buf.slice(0, this._offset))
  }
})

/**
 * Append a raw buffer to the current writer instance. No validation to
 * determine if the buffer represents a valid BER encoding is performed.
 *
 * @param {Buffer} buffer The buffer to append. If this is not a valid BER
 * sequence of data, it will invalidate the BER represented by the `BerWriter`.
 *
 * @throws If the input is not an instance of Buffer.
 */
Writer.prototype.appendBuffer = function appendBuffer (buffer) {
  if (Buffer.isBuffer(buffer) === false) {
    throw Error('buffer must be an instance of Buffer')
  }
  for (const b of buffer.values()) {
    this.writeByte(b)
  }
}

Writer.prototype.writeByte = function (b) {
  if (typeof (b) !== 'number') { throw new TypeError('argument must be a Number') }

  this._ensure(1)
  this._buf[this._offset++] = b
}

Writer.prototype.writeInt = function (i, tag) {
  if (typeof (i) !== 'number') { throw new TypeError('argument must be a Number') }
  if (typeof (tag) !== 'number') { tag = ASN1.Integer }

  let sz = 4

  while ((((i & 0xff800000) === 0) || ((i & 0xff800000) === 0xff800000 >> 0)) &&
        (sz > 1)) {
    sz--
    i <<= 8
  }

  if (sz > 4) { throw newInvalidAsn1Error('BER ints cannot be > 0xffffffff') }

  this._ensure(2 + sz)
  this._buf[this._offset++] = tag
  this._buf[this._offset++] = sz

  while (sz-- > 0) {
    this._buf[this._offset++] = ((i & 0xff000000) >>> 24)
    i <<= 8
  }
}

Writer.prototype.writeNull = function () {
  this.writeByte(ASN1.Null)
  this.writeByte(0x00)
}

Writer.prototype.writeEnumeration = function (i, tag) {
  if (typeof (i) !== 'number') { throw new TypeError('argument must be a Number') }
  if (typeof (tag) !== 'number') { tag = ASN1.Enumeration }

  return this.writeInt(i, tag)
}

Writer.prototype.writeBoolean = function (b, tag) {
  if (typeof (b) !== 'boolean') { throw new TypeError('argument must be a Boolean') }
  if (typeof (tag) !== 'number') { tag = ASN1.Boolean }

  this._ensure(3)
  this._buf[this._offset++] = tag
  this._buf[this._offset++] = 0x01
  this._buf[this._offset++] = b ? 0xff : 0x00
}

Writer.prototype.writeString = function (s, tag) {
  if (typeof (s) !== 'string') { throw new TypeError('argument must be a string (was: ' + typeof (s) + ')') }
  if (typeof (tag) !== 'number') { tag = ASN1.OctetString }

  const len = Buffer.byteLength(s)
  this.writeByte(tag)
  this.writeLength(len)
  if (len) {
    this._ensure(len)
    this._buf.write(s, this._offset)
    this._offset += len
  }
}

Writer.prototype.writeBuffer = function (buf, tag) {
  if (typeof (tag) !== 'number') { throw new TypeError('tag must be a number') }
  if (!Buffer.isBuffer(buf)) { throw new TypeError('argument must be a buffer') }

  this.writeByte(tag)
  this.writeLength(buf.length)
  this._ensure(buf.length)
  buf.copy(this._buf, this._offset, 0, buf.length)
  this._offset += buf.length
}

Writer.prototype.writeStringArray = function (strings) {
  if (Array.isArray(strings) === false) { throw new TypeError('argument must be an Array[String]') }

  const self = this
  strings.forEach(function (s) {
    self.writeString(s)
  })
}

// This is really to solve DER cases, but whatever for now
Writer.prototype.writeOID = function (s, tag) {
  if (typeof (s) !== 'string') { throw new TypeError('argument must be a string') }
  if (typeof (tag) !== 'number') { tag = ASN1.OID }

  if (!/^([0-9]+\.){3,}[0-9]+$/.test(s)) { throw new Error('argument is not a valid OID string') }

  function encodeOctet (bytes, octet) {
    if (octet < 128) {
      bytes.push(octet)
    } else if (octet < 16384) {
      bytes.push((octet >>> 7) | 0x80)
      bytes.push(octet & 0x7F)
    } else if (octet < 2097152) {
      bytes.push((octet >>> 14) | 0x80)
      bytes.push(((octet >>> 7) | 0x80) & 0xFF)
      bytes.push(octet & 0x7F)
    } else if (octet < 268435456) {
      bytes.push((octet >>> 21) | 0x80)
      bytes.push(((octet >>> 14) | 0x80) & 0xFF)
      bytes.push(((octet >>> 7) | 0x80) & 0xFF)
      bytes.push(octet & 0x7F)
    } else {
      bytes.push(((octet >>> 28) | 0x80) & 0xFF)
      bytes.push(((octet >>> 21) | 0x80) & 0xFF)
      bytes.push(((octet >>> 14) | 0x80) & 0xFF)
      bytes.push(((octet >>> 7) | 0x80) & 0xFF)
      bytes.push(octet & 0x7F)
    }
  }

  const tmp = s.split('.')
  const bytes = []
  bytes.push(parseInt(tmp[0], 10) * 40 + parseInt(tmp[1], 10))
  tmp.slice(2).forEach(function (b) {
    encodeOctet(bytes, parseInt(b, 10))
  })

  const self = this
  this._ensure(2 + bytes.length)
  this.writeByte(tag)
  this.writeLength(bytes.length)
  bytes.forEach(function (b) {
    self.writeByte(b)
  })
}

Writer.prototype.writeLength = function (len) {
  if (typeof (len) !== 'number') { throw new TypeError('argument must be a Number') }

  this._ensure(4)

  if (len <= 0x7f) {
    this._buf[this._offset++] = len
  } else if (len <= 0xff) {
    this._buf[this._offset++] = 0x81
    this._buf[this._offset++] = len
  } else if (len <= 0xffff) {
    this._buf[this._offset++] = 0x82
    this._buf[this._offset++] = len >> 8
    this._buf[this._offset++] = len
  } else if (len <= 0xffffff) {
    this._buf[this._offset++] = 0x83
    this._buf[this._offset++] = len >> 16
    this._buf[this._offset++] = len >> 8
    this._buf[this._offset++] = len
  } else {
    throw newInvalidAsn1Error('Length too long (> 4 bytes)')
  }
}

Writer.prototype.startSequence = function (tag) {
  if (typeof (tag) !== 'number') { tag = ASN1.Sequence | ASN1.Constructor }

  this.writeByte(tag)
  this._seq.push(this._offset)
  this._ensure(3)
  this._offset += 3
}

Writer.prototype.endSequence = function () {
  const seq = this._seq.pop()
  const start = seq + 3
  const len = this._offset - start

  if (len <= 0x7f) {
    this._shift(start, len, -2)
    this._buf[seq] = len
  } else if (len <= 0xff) {
    this._shift(start, len, -1)
    this._buf[seq] = 0x81
    this._buf[seq + 1] = len
  } else if (len <= 0xffff) {
    this._buf[seq] = 0x82
    this._buf[seq + 1] = len >> 8
    this._buf[seq + 2] = len
  } else if (len <= 0xffffff) {
    this._shift(start, len, 1)
    this._buf[seq] = 0x83
    this._buf[seq + 1] = len >> 16
    this._buf[seq + 2] = len >> 8
    this._buf[seq + 3] = len
  } else {
    throw newInvalidAsn1Error('Sequence too long')
  }
}

Writer.prototype._shift = function (start, len, shift) {
  assert.ok(start !== undefined)
  assert.ok(len !== undefined)
  assert.ok(shift)

  this._buf.copy(this._buf, start + shift, start, start + len)
  this._offset += shift
}

Writer.prototype._ensure = function (len) {
  assert.ok(len)

  if (this._size - this._offset < len) {
    let sz = this._size * this._options.growthFactor
    if (sz - this._offset < len) { sz += len }

    const buf = Buffer.alloc(sz)

    this._buf.copy(buf, 0, 0, this._offset)
    this._buf = buf
    this._size = sz
  }
}

// --- Exported API

module.exports = Writer

}).call(this)}).call(this,require("buffer").Buffer)
},{"./errors":21,"./types":24,"assert":96,"buffer":110}],26:[function(require,module,exports){
// Copyright 2011 Mark Cavage <mcavage@gmail.com> All rights reserved.

// If you have no idea what ASN.1 or BER is, see this:
// https://web.archive.org/web/20220314051854/http://luca.ntop.org/Teaching/Appunti/asn1.html

const Ber = require('./ber/index')

// --- Exported API

module.exports = {

  Ber: Ber,

  BerReader: Ber.Reader,

  BerWriter: Ber.Writer

}

},{"./ber/index":22}],27:[function(require,module,exports){
'use strict'

module.exports = {
  DN: require('./lib/dn'),
  RDN: require('./lib/rdn')
}

},{"./lib/dn":29,"./lib/rdn":30}],28:[function(require,module,exports){
'use strict'

const warning = require('process-warning')()
const clazz = 'LdapjsDnWarning'

warning.create(clazz, 'LDAP_DN_DEP_001', 'attribute options is deprecated and are ignored')
warning.create(clazz, 'LDAP_DN_DEP_002', '.format() is deprecated. Use .toString() instead')
warning.create(clazz, 'LDAP_DN_DEP_003', '.set() is deprecated. Use .setAttribute() instead')
warning.create(clazz, 'LDAP_DN_DEP_004', '.setFormat() is deprecated. Options will be ignored')

module.exports = warning

},{"process-warning":161}],29:[function(require,module,exports){
'use strict'

const warning = require('./deprecations')
const RDN = require('./rdn')
const parseString = require('./utils/parse-string')

/**
 * Implements distinguished name strings as described in
 * https://www.rfc-editor.org/rfc/rfc4514 as an object.
 * This is the primary implementation for parsing and generating DN strings.
 *
 * @example
 * const dn = new DN({rdns: [{cn: 'jdoe', givenName: 'John'}] })
 * dn.toString() // 'cn=jdoe+givenName=John'
 */
class DN {
  #rdns = []

  /**
   * @param {object} input
   * @param {RDN[]} [input.rdns=[]] A set of RDN objects that define the DN.
   * Remember that DNs are in reverse domain order. Thus, the target RDN must
   * be the first item and the top-level RDN the last item.
   *
   * @throws When the provided `rdns` array is invalid.
   */
  constructor ({ rdns = [] } = {}) {
    if (Array.isArray(rdns) === false) {
      throw Error('rdns must be an array')
    }

    const hasNonRdn = rdns.some(
      r => RDN.isRdn(r) === false
    )
    if (hasNonRdn === true) {
      throw Error('rdns must be an array of RDN objects')
    }

    Array.prototype.push.apply(
      this.#rdns,
      rdns.map(r => {
        if (Object.prototype.toString.call(r) === '[object LdapRdn]') {
          return r
        }
        return new RDN(r)
      })
    )
  }

  get [Symbol.toStringTag] () {
    return 'LdapDn'
  }

  /**
   * The number of RDNs that make up the DN.
   *
   * @returns {number}
   */
  get length () {
    return this.#rdns.length
  }

  /**
   * Determine if the current instance is the child of another DN instance or
   * DN string.
   *
   * @param {DN|string} dn
   *
   * @returns {boolean}
   */
  childOf (dn) {
    if (typeof dn === 'string') {
      const parsedDn = DN.fromString(dn)
      return parsedDn.parentOf(this)
    }
    return dn.parentOf(this)
  }

  /**
   * Get a new instance that is a replica of the current instance.
   *
   * @returns {DN}
   */
  clone () {
    return new DN({ rdns: this.#rdns })
  }

  /**
   * Determine if the instance is equal to another DN.
   *
   * @param {DN|string} dn
   *
   * @returns {boolean}
   */
  equals (dn) {
    if (typeof dn === 'string') {
      const parsedDn = DN.fromString(dn)
      return parsedDn.equals(this)
    }

    if (this.length !== dn.length) return false

    for (let i = 0; i < this.length; i += 1) {
      if (this.#rdns[i].equals(dn.rdnAt(i)) === false) {
        return false
      }
    }

    return true
  }

  /**
   * @deprecated Use .toString() instead.
   *
   * @returns {string}
   */
  format () {
    warning.emit('LDAP_DN_DEP_002')
    return this.toString()
  }

  /**
   * Determine if the instance has any RDNs defined.
   *
   * @returns {boolean}
   */
  isEmpty () {
    return this.#rdns.length === 0
  }

  /**
   * Get a DN representation of the parent of this instance.
   *
   * @returns {DN|undefined}
   */
  parent () {
    if (this.length === 0) return undefined
    const save = this.shift()
    const dn = new DN({ rdns: this.#rdns })
    this.unshift(save)
    return dn
  }

  /**
   * Determine if the instance is the parent of a given DN instance or DN
   * string.
   *
   * @param {DN|string} dn
   *
   * @returns {boolean}
   */
  parentOf (dn) {
    if (typeof dn === 'string') {
      const parsedDn = DN.fromString(dn)
      return this.parentOf(parsedDn)
    }

    if (this.length >= dn.length) {
      // If we have more RDNs in our set then we must be a descendent at least.
      return false
    }

    const numberOfElementsDifferent = dn.length - this.length
    for (let i = this.length - 1; i >= 0; i -= 1) {
      const myRdn = this.#rdns[i]
      const theirRdn = dn.rdnAt(i + numberOfElementsDifferent)
      if (myRdn.equals(theirRdn) === false) {
        return false
      }
    }

    return true
  }

  /**
   * Removes the last RDN from the list and returns it. This alters the
   * instance.
   *
   * @returns {RDN}
   */
  pop () {
    return this.#rdns.pop()
  }

  /**
   * Adds a new RDN to the end of the list (i.e. the "top most" RDN in the
   * directory path) and returns the new RDN count.
   *
   * @param {RDN} rdn
   *
   * @returns {number}
   *
   * @throws When the input is not a valid RDN.
   */
  push (rdn) {
    if (Object.prototype.toString.call(rdn) !== '[object LdapRdn]') {
      throw Error('rdn must be a RDN instance')
    }
    return this.#rdns.push(rdn)
  }

  /**
   * Return the RDN at the provided index in the list of RDNs associated with
   * this instance.
   *
   * @param {number} index
   *
   * @returns {RDN}
   */
  rdnAt (index) {
    return this.#rdns[index]
  }

  /**
   * Reverse the RDNs list such that the first element becomes the last, and
   * the last becomes the first. This is useful when the RDNs were added in the
   * opposite order of how they should have been.
   *
   * This is an in-place operation. The instance is changed as a result of
   * this operation.
   *
   * @returns {DN} The current instance (i.e. this method is chainable).
   */
  reverse () {
    this.#rdns.reverse()
    return this
  }

  /**
   * @deprecated Formatting options are not supported.
   */
  setFormat () {
    warning.emit('LDAP_DN_DEP_004')
  }

  /**
   * Remove the first RDN from the set of RDNs and return it.
   *
   * @returns {RDN}
   */
  shift () {
    return this.#rdns.shift()
  }

  /**
   * Render the DN instance as a spec compliant DN string.
   *
   * @returns {string}
   */
  toString () {
    let result = ''
    for (const rdn of this.#rdns) {
      const rdnString = rdn.toString()
      result += `,${rdnString}`
    }
    return result.substring(1)
  }

  /**
   * Adds an RDN to the beginning of the RDN list and returns the new length.
   *
   * @param {RDN} rdn
   *
   * @returns {number}
   *
   * @throws When the RDN is invalid.
   */
  unshift (rdn) {
    if (Object.prototype.toString.call(rdn) !== '[object LdapRdn]') {
      throw Error('rdn must be a RDN instance')
    }
    return this.#rdns.unshift(rdn)
  }

  /**
   * Determine if an object is an instance of {@link DN} or is at least
   * a DN-like object. It is safer to perform a `toString` check.
   *
   * @example Valid Instance
   * const dn = new DN()
   * DN.isDn(dn) // true
   *
   * @example DN-like Instance
   * let dn = { rdns: [{name: 'cn', value: 'foo'}] }
   * DN.isDn(dn) // true
   *
   * dn = { rdns: [{cn: 'foo', sn: 'bar'}, {dc: 'example'}, {dc: 'com'}]}
   * DN.isDn(dn) // true
   *
   * @example Preferred Check
   * let dn = new DN()
   * Object.prototype.toString.call(dn) === '[object LdapDn]' // true
   *
   * dn = { rdns: [{name: 'cn', value: 'foo'}] }
   * Object.prototype.toString.call(dn) === '[object LdapDn]' // false
   *
   * @param {object} dn
   * @returns {boolean}
   */
  static isDn (dn) {
    if (Object.prototype.toString.call(dn) === '[object LdapDn]') {
      return true
    }
    if (
      Object.prototype.toString.call(dn) !== '[object Object]' ||
      Array.isArray(dn.rdns) === false
    ) {
      return false
    }
    if (dn.rdns.some(dn => RDN.isRdn(dn) === false) === true) {
      return false
    }

    return true
  }

  /**
   * Parses a DN string and returns a new {@link DN} instance.
   *
   * @example
   * const dn = DN.fromString('cn=foo,dc=example,dc=com')
   * DN.isDn(dn) // true
   *
   * @param {string} dnString
   *
   * @returns {DN}
   *
   * @throws If the string is not parseable.
   */
  static fromString (dnString) {
    const rdns = parseString(dnString)
    return new DN({ rdns })
  }
}

module.exports = DN

},{"./deprecations":28,"./rdn":30,"./utils/parse-string":35}],30:[function(require,module,exports){
'use strict'

const warning = require('./deprecations')
const escapeValue = require('./utils/escape-value')
const isDottedDecimal = require('./utils/is-dotted-decimal')

/**
 * Implements a relative distinguished name as described in
 * https://www.rfc-editor.org/rfc/rfc4514.
 *
 * @example
 * const rdn = new RDN({cn: 'jdoe', givenName: 'John'})
 * rdn.toString() // 'cn=jdoe+givenName=John'
 */
class RDN {
  #attributes = new Map()

  /**
   * @param {object} rdn An object of key-values to use as RDN attribute
   * types and attribute values. Attribute values should be strings.
   */
  constructor (rdn = {}) {
    for (const [key, val] of Object.entries(rdn)) {
      this.setAttribute({ name: key, value: val })
    }
  }

  get [Symbol.toStringTag] () {
    return 'LdapRdn'
  }

  /**
   * The number attributes associated with the RDN.
   *
   * @returns {number}
   */
  get size () {
    return this.#attributes.size
  }

  /**
   * Very naive equality check against another RDN instance. In short, if they
   * do not have the exact same key names with the exact same values, then
   * this check will return `false`.
   *
   * @param {RDN} rdn
   *
   * @returns {boolean}
   *
   * @todo Should implement support for the attribute types listed in https://www.rfc-editor.org/rfc/rfc4514#section-3
   */
  equals (rdn) {
    if (Object.prototype.toString.call(rdn) !== '[object LdapRdn]') {
      return false
    }
    if (this.size !== rdn.size) {
      return false
    }

    for (const key of this.keys()) {
      if (rdn.has(key) === false) return false
      if (this.getValue(key) !== rdn.getValue(key)) return false
    }

    return true
  }

  /**
   * The value associated with the given attribute name.
   *
   * @param {string} name An attribute name associated with the RDN.
   *
   * @returns {*}
   */
  getValue (name) {
    return this.#attributes.get(name)?.value
  }

  /**
   * Determine if the RDN has a specific attribute assigned.
   *
   * @param {string} name The name of the attribute.
   *
   * @returns {boolean}
   */
  has (name) {
    return this.#attributes.has(name)
  }

  /**
   * All attribute names associated with the RDN.
   *
   * @returns {IterableIterator<string>}
   */
  keys () {
    return this.#attributes.keys()
  }

  /**
   * Define an attribute type and value on the RDN.
   *
   * @param {string} name
   * @param {string | import('@ldapjs/asn1').BerReader} value
   * @param {object} options Deprecated. All options will be ignored.
   *
   * @throws If any parameter is invalid.
   */
  setAttribute ({ name, value, options = {} }) {
    if (typeof name !== 'string') {
      throw Error('name must be a string')
    }

    const valType = Object.prototype.toString.call(value)
    if (typeof value !== 'string' && valType !== '[object BerReader]') {
      throw Error('value must be a string or BerReader')
    }
    if (Object.prototype.toString.call(options) !== '[object Object]') {
      throw Error('options must be an object')
    }

    const startsWithAlpha = str => /^[a-zA-Z]/.test(str) === true
    if (startsWithAlpha(name) === false && isDottedDecimal(name) === false) {
      throw Error('attribute name must start with an ASCII alpha character or be a numeric OID')
    }

    const attr = { value, name }
    for (const [key, val] of Object.entries(options)) {
      warning.emit('LDAP_DN_DEP_001')
      if (key === 'value') continue
      attr[key] = val
    }

    this.#attributes.set(name, attr)
  }

  /**
   * Convert the RDN to a string representation. If an attribute value is
   * an instance of `BerReader`, the value will be encoded appropriately.
   *
   * @example Dotted Decimal Type
   * const rdn = new RDN({
   *   cn: '#foo',
   *   '1.3.6.1.4.1.1466.0': '#04024869'
   * })
   * rnd.toString()
   * // => 'cn=\23foo+1.3.6.1.4.1.1466.0=#04024869'
   *
   * @returns {string}
   */
  toString () {
    let result = ''
    const isHexEncodedValue = val => /^#([0-9a-fA-F]{2})+$/.test(val) === true

    for (const entry of this.#attributes.values()) {
      result += entry.name + '='

      if (isHexEncodedValue(entry.value)) {
        result += entry.value
      } else if (Object.prototype.toString.call(entry.value) === '[object BerReader]') {
        let encoded = '#'
        for (const byte of entry.value.buffer) {
          encoded += Number(byte).toString(16).padStart(2, '0')
        }
        result += encoded
      } else {
        result += escapeValue(entry.value)
      }

      result += '+'
    }

    return result.substring(0, result.length - 1)
  }

  /**
   * @returns {string}
   *
   * @deprecated Use {@link toString}.
   */
  format () {
    // If we decide to add back support for this, we should do it as
    // `.toStringWithFormatting(options)`.
    warning.emit('LDAP_DN_DEP_002')
    return this.toString()
  }

  /**
   * @param {string} name
   * @param {string} value
   * @param {object} options
   *
   * @deprecated Use {@link setAttribute}.
   */
  set (name, value, options) {
    warning.emit('LDAP_DN_DEP_003')
    this.setAttribute({ name, value, options })
  }

  /**
   * Determine if an object is an instance of {@link RDN} or is at least
   * a RDN-like object. It is safer to perform a `toString` check.
   *
   * @example Valid Instance
   * const Rdn = new RDN()
   * RDN.isRdn(rdn) // true
   *
   * @example RDN-like Instance
   * const rdn = { name: 'cn', value: 'foo' }
   * RDN.isRdn(rdn) // true
   *
   * @example Preferred Check
   * let rdn = new RDN()
   * Object.prototype.toString.call(rdn) === '[object LdapRdn]' // true
   *
   * dn = { name: 'cn', value: 'foo' }
   * Object.prototype.toString.call(dn) === '[object LdapRdn]' // false
   *
   * @param {object} rdn
   * @returns {boolean}
   */
  static isRdn (rdn) {
    if (Object.prototype.toString.call(rdn) === '[object LdapRdn]') {
      return true
    }

    const isObject = Object.prototype.toString.call(rdn) === '[object Object]'
    if (isObject === false) {
      return false
    }

    if (typeof rdn.name === 'string' && typeof rdn.value === 'string') {
      return true
    }

    for (const value of Object.values(rdn)) {
      if (
        typeof value !== 'string' &&
        Object.prototype.toString.call(value) !== '[object BerReader]'
      ) return false
    }

    return true
  }
}

module.exports = RDN

},{"./deprecations":28,"./utils/escape-value":31,"./utils/is-dotted-decimal":32}],31:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

/**
 * Converts an attribute value into an escaped string as described in
 * https://www.rfc-editor.org/rfc/rfc4514#section-2.4.
 *
 * This function supports up to 4 byte unicode characters.
 *
 * @param {string} value
 * @returns {string} The escaped string.
 */
module.exports = function escapeValue (value) {
  if (typeof value !== 'string') {
    throw Error('value must be a string')
  }

  const toEscape = Buffer.from(value, 'utf8')
  const escaped = []

  // We will handle the reverse solidus ('\') on its own.
  const embeddedReservedChars = [
    0x22, // '"'
    0x2b, // '+'
    0x2c, // ','
    0x3b, // ';'
    0x3c, // '<'
    0x3e // '>'
  ]
  for (let i = 0; i < toEscape.byteLength;) {
    const charHex = toEscape[i]

    // Handle leading space or #.
    if (i === 0 && (charHex === 0x20 || charHex === 0x23)) {
      escaped.push(toEscapedHexString(charHex))
      i += 1
      continue
    }
    // Handle trailing space.
    if (i === toEscape.byteLength - 1 && charHex === 0x20) {
      escaped.push(toEscapedHexString(charHex))
      i += 1
      continue
    }

    if (embeddedReservedChars.includes(charHex) === true) {
      escaped.push(toEscapedHexString(charHex))
      i += 1
      continue
    }

    if (charHex >= 0xc0 && charHex <= 0xdf) {
      // Represents the first byte in a 2-byte UTF-8 character.
      escaped.push(toEscapedHexString(charHex))
      escaped.push(toEscapedHexString(toEscape[i + 1]))
      i += 2
      continue
    }

    if (charHex >= 0xe0 && charHex <= 0xef) {
      // Represents the first byte in a 3-byte UTF-8 character.
      escaped.push(toEscapedHexString(charHex))
      escaped.push(toEscapedHexString(toEscape[i + 1]))
      escaped.push(toEscapedHexString(toEscape[i + 2]))
      i += 3
      continue
    }

    if (charHex >= 0xf0 && charHex <= 0xf7) {
      // Represents the first byte in a 4-byte UTF-8 character.
      escaped.push(toEscapedHexString(charHex))
      escaped.push(toEscapedHexString(toEscape[i + 1]))
      escaped.push(toEscapedHexString(toEscape[i + 2]))
      escaped.push(toEscapedHexString(toEscape[i + 3]))
      i += 4
      continue
    }

    if (charHex <= 31) {
      // Represents an ASCII control character.
      escaped.push(toEscapedHexString(charHex))
      i += 1
      continue
    }

    escaped.push(String.fromCharCode(charHex))
    i += 1
    continue
  }

  return escaped.join('')
}

/**
 * Given a byte, convert it to an escaped hex string.
 *
 * @example
 * toEscapedHexString(0x20) // '\20'
 *
 * @param {number} char
 * @returns {string}
 */
function toEscapedHexString (char) {
  return '\\' + char.toString(16).padStart(2, '0')
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":110}],32:[function(require,module,exports){
'use strict'

const partIsNotNumeric = part => /^\d+$/.test(part) === false

/**
 * Determines if a passed in string is a dotted decimal string.
 *
 * @param {string} value
 *
 * @returns {boolean}
 */
module.exports = function isDottedDecimal (value) {
  if (typeof value !== 'string') return false

  const parts = value.split('.')
  const nonNumericParts = parts.filter(partIsNotNumeric)

  return nonNumericParts.length === 0
}

},{}],33:[function(require,module,exports){
'use strict'

/**
 * Find the ending position of the attribute type name portion of an RDN.
 * This function does not verify if the name is a valid description string
 * or numeric OID. It merely reads a string from the given starting position
 * to the spec defined end of an attribute type string.
 *
 * @param {Buffer} searchBuffer A buffer representing the RDN.
 * @param {number} startPos The position in the `searchBuffer` to start
 * searching from.
 *
 * @returns {number} The position of the end of the RDN's attribute type name,
 * or `-1` if an invalid character has been encountered.
 */
module.exports = function findNameEnd ({ searchBuffer, startPos }) {
  let pos = startPos

  while (pos < searchBuffer.byteLength) {
    const char = searchBuffer[pos]
    if (char === 0x20 || char === 0x3d) {
      // Name ends with a space or an '=' character.
      break
    }
    if (isValidNameChar(char) === true) {
      pos += 1
      continue
    }
    return -1
  }

  return pos
}

/**
 * Determine if a character is a valid `attributeType` character as defined
 * in RFC 4514 §3.
 *
 * @param {number} c The character to verify. Should be the byte representation
 * of the character from a {@link Buffer} instance.
 *
 * @returns {boolean}
 */
function isValidNameChar (c) {
  if (c >= 0x41 && c <= 0x5a) { // A - Z
    return true
  }
  if (c >= 0x61 && c <= 0x7a) { // a - z
    return true
  }
  if (c >= 0x30 && c <= 0x39) { // 0 - 9
    return true
  }
  if (c === 0x2d || c === 0x2e) { // - or .
    return true
  }
  return false
}

},{}],34:[function(require,module,exports){
'use strict'

// Attribute types must start with an ASCII alphanum character.
// https://www.rfc-editor.org/rfc/rfc4514#section-3
// https://www.rfc-editor.org/rfc/rfc4512#section-1.4
const isLeadChar = (c) => /[a-zA-Z0-9]/.test(c) === true

/**
 * Find the starting position of an attribute type (name). Leading spaces and
 * commas are ignored. If an invalid leading character is encountered, an
 * invalid position will be returned.
 *
 * @param {Buffer} searchBuffer
 * @param {number} startPos
 *
 * @returns {number} The position in the buffer where the name starts, or `-1`
 * if an invalid name starting character is encountered.
 */
module.exports = function findNameStart ({ searchBuffer, startPos }) {
  let pos = startPos
  while (pos < searchBuffer.byteLength) {
    if (searchBuffer[pos] === 0x20 || searchBuffer[pos] === 0x2c) {
      // Skip leading space and comma.
      pos += 1
      continue
    }
    const char = String.fromCharCode(searchBuffer[pos])
    if (isLeadChar(char) === true) {
      return pos
    }
    break
  }
  return -1
}

},{}],35:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const readAttributePair = require('./read-attribute-pair')

/**
 * @typedef {object} ParsedPojoRdn
 * @property {string} name Either the name of an RDN attribute, or the
 * equivalent numeric OID.
 * @property {string | import('@ldapjs/asn1').BerReader} value The attribute
 * value as a plain string, or a `BerReader` if the string value was an encoded
 * hex string.
 */

/**
 * Parse a string into a set of plain JavaScript object representations of
 * RDNs.
 *
 * @example A plain string with multiple RDNs and multiple attribute assertions.
 * const input = 'cn=foo+sn=bar,dc=example,dc=com
 * const result = parseString(input)
 * // [
 * //   { cn: 'foo', sn: 'bar' },
 * //   { dc: 'example' }
 * //   { dc: 'com' }
 * // ]
 *
 * @param {string} input The RDN string to parse.
 *
 * @returns {ParsedPojoRdn[]}
 *
 * @throws When there is some problem parsing the RDN string.
 */
module.exports = function parseString (input) {
  if (typeof input !== 'string') {
    throw Error('input must be a string')
  }
  if (input.length === 0) {
    // Short circuit because the input is an empty DN (i.e. "root DSE").
    return []
  }

  const searchBuffer = Buffer.from(input, 'utf8')
  const length = searchBuffer.byteLength
  const rdns = []

  let pos = 0
  let rdn = {}

  readRdnLoop:
  while (pos <= length) {
    if (pos === length) {
      const char = searchBuffer[pos - 1]

      /* istanbul ignore else */
      if (char === 0x2b || char === 0x2c || char === 0x3b) {
        throw Error('rdn string ends abruptly with character: ' + String.fromCharCode(char))
      }
    }

    // Find the start of significant characters by skipping over any leading
    // whitespace.
    while (pos < length && searchBuffer[pos] === 0x20) {
      pos += 1
    }

    const readAttrPairResult = readAttributePair({ searchBuffer, startPos: pos })
    pos = readAttrPairResult.endPos
    rdn = { ...rdn, ...readAttrPairResult.pair }

    if (pos >= length) {
      // We've reached the end of the string. So push the current RDN and stop.
      rdns.push(rdn)
      break
    }

    // Next, we need to determine if the next set of significant characters
    // denotes another attribute pair for the current RDN, or is the indication
    // of another RDN.
    while (pos < length) {
      const char = searchBuffer[pos]

      // We don't need to skip whitespace before the separator because the
      // attribute pair function has already advanced us past any such
      // whitespace.

      if (char === 0x2b) { // +
        // We need to continue adding attribute pairs to the current RDN.
        pos += 1
        continue readRdnLoop
      }

      /* istanbul ignore else */
      if (char === 0x2c || char === 0x3b) { // , or ;
        // The current RDN has been fully parsed, so push it to the list,
        // reset the collector, and start parsing the next RDN.
        rdns.push(rdn)
        rdn = {}
        pos += 1
        continue readRdnLoop
      }
    }
  }

  return rdns
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"./read-attribute-pair":37,"buffer":110}],36:[function(require,module,exports){
'use strict'

const isDigit = c => /[0-9]/.test(c) === true
const hasKeyChars = input => /[a-zA-Z-]/.test(input) === true
const isValidLeadChar = c => /[a-zA-Z]/.test(c) === true
const hasInvalidChars = input => /[^a-zA-Z0-9-]/.test(input) === true

/**
 * An attribute type name is defined by RFC 4514 §3 as a "descr" or
 * "numericoid". These are defined by RFC 4512 §1.4. This function validates
 * the given name as matching the spec.
 *
 * @param {string} name
 *
 * @returns {boolean}
 */
module.exports = function isValidAttributeTypeName (name) {
  if (isDigit(name[0]) === true) {
    // A leading digit indicates that the name should be a numericoid.
    return hasKeyChars(name) === false
  }

  if (isValidLeadChar(name[0]) === false) {
    return false
  }

  return hasInvalidChars(name) === false
}

},{}],37:[function(require,module,exports){
'use strict'

const findNameStart = require('./find-name-start')
const findNameEnd = require('./find-name-end')
const isValidAttributeTypeName = require('./is-valid-attribute-type-name')
const readAttributeValue = require('./read-attribute-value')

/**
 * @typedef {object} AttributePair
 * @property {string | import('@ldapjs/asn1').BerReader} name Property name is
 * actually the property name of the attribute pair. The value will be a string,
 * or, in the case of the value being a hex encoded string, an instance of
 * `BerReader`.
 *
 * @example
 * const input = 'foo=bar'
 * const pair = { foo: 'bar' }
 */

/**
 * @typedef {object} ReadAttributePairResult
 * @property {number} endPos The ending position in the input search buffer that
 * is the end of the read attribute pair.
 * @property {AttributePair} pair The parsed attribute pair.
 */

/**
 * Read an RDN attribute type and attribute value pair from the provided
 * search buffer at the given starting position.
 *
 * @param {Buffer} searchBuffer
 * @param {number} startPos
 *
 * @returns {ReadAttributePairResult}
 *
 * @throws When there is some problem with the input string.
 */
module.exports = function readAttributePair ({ searchBuffer, startPos }) {
  let pos = startPos

  const nameStartPos = findNameStart({
    searchBuffer,
    startPos: pos
  })
  if (nameStartPos < 0) {
    throw Error('invalid attribute name leading character encountered')
  }

  const nameEndPos = findNameEnd({
    searchBuffer,
    startPos: nameStartPos
  })
  if (nameStartPos < 0) {
    throw Error('invalid character in attribute name encountered')
  }

  const attributeName = searchBuffer.subarray(nameStartPos, nameEndPos).toString('utf8')
  if (isValidAttributeTypeName(attributeName) === false) {
    throw Error('invalid attribute type name: ' + attributeName)
  }

  const valueReadResult = readAttributeValue({
    searchBuffer,
    startPos: nameEndPos
  })
  pos = valueReadResult.endPos
  const attributeValue = valueReadResult.value

  return {
    endPos: pos,
    pair: { [attributeName]: attributeValue }
  }
}

},{"./find-name-end":33,"./find-name-start":34,"./is-valid-attribute-type-name":36,"./read-attribute-value":38}],38:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const readHexString = require('./read-hex-string')
const readEscapeSequence = require('./read-escape-sequence')

/**
 * @typedef {object} ReadAttributeValueResult
 * @property {number} endPos The position in the buffer that marks the end of
 * the value.
 * @property {string | import('@ldapjs/asn1').BerReader} value
 */

/**
 * Read an attribute value string from a given {@link Buffer} and return it.
 * If the value is an encoded octet string, it will be decoded and returned
 * as a {@link Buffer}.
 *
 * @param {Buffer} searchBuffer
 * @param {number} startPos
 *
 * @returns {ReadAttributeValueResult}
 *
 * @throws When there is a syntax error in the attribute value string.
 */
module.exports = function readAttributeValue ({ searchBuffer, startPos }) {
  let pos = startPos

  while (pos < searchBuffer.byteLength && searchBuffer[pos] === 0x20) {
    // Skip over any leading whitespace before the '='.
    pos += 1
  }

  if (pos >= searchBuffer.byteLength || searchBuffer[pos] !== 0x3d) {
    throw Error('attribute value does not start with equals sign')
  }

  // Advance past the equals sign.
  pos += 1
  while (pos <= searchBuffer.byteLength && searchBuffer[pos] === 0x20) {
    // Advance past any leading whitespace.
    pos += 1
  }

  if (pos >= searchBuffer.byteLength) {
    return { endPos: pos, value: '' }
  }

  if (searchBuffer[pos] === 0x23) {
    const result = readHexString({ searchBuffer, startPos: pos + 1 })
    pos = result.endPos
    return { endPos: pos, value: result.berReader }
  }

  const readValueResult = readValueString({ searchBuffer, startPos: pos })
  pos = readValueResult.endPos
  return {
    endPos: pos,
    value: readValueResult.value.toString('utf8').trim()
  }
}

/**
 * @typedef {object} ReadValueStringResult
 * @property {number} endPos
 * @property {Buffer} value
 * @private
 */

/**
 * Read a series of bytes from the buffer as a plain string.
 *
 * @param {Buffer} searchBuffer
 * @param {number} startPos
 *
 * @returns {ReadValueStringResult}
 *
 * @throws When the attribute value is malformed.
 *
 * @private
 */
function readValueString ({ searchBuffer, startPos }) {
  let pos = startPos
  let inQuotes = false
  let endQuotePresent = false

  const bytes = []
  while (pos <= searchBuffer.byteLength) {
    const char = searchBuffer[pos]

    if (pos === searchBuffer.byteLength) {
      if (inQuotes === true && endQuotePresent === false) {
        throw Error('missing ending double quote for attribute value')
      }
      break
    }

    if (char === 0x22) {
      // Handle the double quote (") character.
      // RFC 2253 §4 allows for attribute values to be wrapped in double
      // quotes in order to allow certain characters to be unescaped.
      // We are not enforcing escaping of characters in this parser, so we only
      // need to recognize that the quotes are present. Our RDN string encoder
      // will escape characters as necessary.
      if (inQuotes === true) {
        pos += 1
        endQuotePresent = true

        // We should be at the end of the value.
        while (pos < searchBuffer.byteLength) {
          const nextChar = searchBuffer[pos]
          if (isEndChar(nextChar) === true) {
            break
          }
          if (nextChar !== 0x20) {
            throw Error('significant rdn character found outside of quotes at position ' + pos)
          }
          pos += 1
        }

        break
      }

      if (pos !== startPos) {
        throw Error('unexpected quote (") in rdn string at position ' + pos)
      }
      inQuotes = true
      pos += 1
      continue
    }

    if (isEndChar(char) === true && inQuotes === false) {
      break
    }

    if (char === 0x5c) {
      // We have encountered the start of an escape sequence.
      const seqResult = readEscapeSequence({
        searchBuffer,
        startPos: pos
      })
      pos = seqResult.endPos
      Array.prototype.push.apply(bytes, seqResult.parsed)
      continue
    }

    bytes.push(char)
    pos += 1
  }

  return {
    endPos: pos,
    value: Buffer.from(bytes)
  }
}

function isEndChar (c) {
  switch (c) {
    case 0x2b: // +
    case 0x2c: // ,
    case 0x3b: // ; -- Allowed by RFC 2253 §4 in place of a comma.
      return true
    default:
      return false
  }
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"./read-escape-sequence":39,"./read-hex-string":40,"buffer":110}],39:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

/**
 * @typedef ReadEscapeSequenceResult
 * @property {number} endPos The position in the buffer that marks the end of
 * the escape sequence.
 * @property {Buffer} parsed The parsed escape sequence as a buffer of bytes.
 */

/**
 * Read an escape sequence from a buffer. It reads until no escape sequences
 * are found. Thus, a sequence of escape sequences will all be parsed at once
 * and returned as a single result.
 *
 * @example A Single ASCII Sequence
 * const toParse = Buffer.from('foo\\#bar', 'utf8')
 * const {parsed, endPos} = readEscapeSequence({
 *   searchBuffer: toParse,
 *   startPos: 3
 * })
 * // => parsed = '#', endPos = 5
 *
 * @example Multiple ASCII Sequences In Succession
 * const toParse = Buffer.from('foo\\#\\!bar', 'utf8')
 * const {parsed, endPos} = readEscapeSequence({
 *   searchBuffer: toParse,
 *   startPos: 3
 * })
 * // => parsed = '#!', endPos = 7
 *
 * @param searchBuffer
 * @param startPos
 *
 * @returns {ReadEscapeSequenceResult}
 *
 * @throws When an escaped sequence is not a valid hexadecimal value.
 */
module.exports = function readEscapeSequence ({ searchBuffer, startPos }) {
  // This is very similar to the `readEscapedCharacters` algorithm in
  // the `utils/escape-filter-value` in `@ldapjs/filter`. The difference being
  // that here we want to interpret the escape sequence instead of return it
  // as a string to be embedded in an "escaped" string.
  // https://github.com/ldapjs/filter/blob/1423612/lib/utils/escape-filter-value.js

  let pos = startPos
  const buf = []

  while (pos < searchBuffer.byteLength) {
    const char = searchBuffer[pos]
    const nextChar = searchBuffer[pos + 1]

    if (char !== 0x5c) {
      // End of sequence reached.
      break
    }

    const strHexCode = String.fromCharCode(nextChar) +
      String.fromCharCode(searchBuffer[pos + 2])
    const hexCode = parseInt(strHexCode, 16)
    if (Number.isNaN(hexCode) === true) {
      if (nextChar >= 0x00 && nextChar <= 0x7f) {
        // Sequence is a single escaped ASCII character
        buf.push(nextChar)
        pos += 2
        continue
      } else {
        throw Error('invalid hex code in escape sequence')
      }
    }

    if (hexCode >= 0xc0 && hexCode <= 0xdf) {
      // Sequence is a 2-byte utf-8 character.
      const secondByte = parseInt(
        String.fromCharCode(searchBuffer[pos + 4]) +
        String.fromCharCode(searchBuffer[pos + 5]),
        16
      )
      buf.push(hexCode)
      buf.push(secondByte)
      pos += 6
      continue
    }

    if (hexCode >= 0xe0 && hexCode <= 0xef) {
      // Sequence is a 3-byte utf-8 character.
      const secondByte = parseInt(
        String.fromCharCode(searchBuffer[pos + 4]) +
        String.fromCharCode(searchBuffer[pos + 5]),
        16
      )
      const thirdByte = parseInt(
        String.fromCharCode(searchBuffer[pos + 7]) +
        String.fromCharCode(searchBuffer[pos + 8]),
        16
      )
      buf.push(hexCode)
      buf.push(secondByte)
      buf.push(thirdByte)
      pos += 9
      continue
    }

    if (hexCode >= 0xf0 && hexCode <= 0xf7) {
      // Sequence is a 4-byte utf-8 character.
      const secondByte = parseInt(
        String.fromCharCode(searchBuffer[pos + 4]) +
        String.fromCharCode(searchBuffer[pos + 5]),
        16
      )
      const thirdByte = parseInt(
        String.fromCharCode(searchBuffer[pos + 7]) +
        String.fromCharCode(searchBuffer[pos + 8]),
        16
      )
      const fourthByte = parseInt(
        String.fromCharCode(searchBuffer[pos + 10]) +
        String.fromCharCode(searchBuffer[pos + 11]),
        16
      )
      buf.push(hexCode)
      buf.push(secondByte)
      buf.push(thirdByte)
      buf.push(fourthByte)
      pos += 12
      continue
    }

    // The escaped character should be a single hex value.
    buf.push(hexCode)
    pos += 3
  }

  return {
    endPos: pos,
    parsed: Buffer.from(buf)
  }
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":110}],40:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { BerReader } = require('@ldapjs/asn1')

const isValidHexCode = code => /[0-9a-fA-F]{2}/.test(code) === true

/**
 * @typedef {object} ReadHexStringResult
 * @property {number} endPos The position in the buffer where the end of the
 * hex string was encountered.
 * @property {import('@ldapjs/asn1').BerReader} berReader The parsed hex string
 * as an BER object.
 */

/**
 * Read a sequence of bytes as a hex encoded octet string. The sequence is
 * assumed to be a spec compliant encoded BER object.
 *
 * @param {Buffer} searchBuffer The buffer to read.
 * @param {number} startPos The position in the buffer to start reading from.
 *
 * @returns {ReadHexStringResult}
 *
 * @throws When an invalid hex pair has been encountered.
 */
module.exports = function readHexString ({ searchBuffer, startPos }) {
  const bytes = []

  let pos = startPos
  while (pos < searchBuffer.byteLength) {
    if (isEndChar(searchBuffer[pos])) {
      break
    }

    const hexPair = String.fromCharCode(searchBuffer[pos]) +
      String.fromCharCode(searchBuffer[pos + 1])
    if (isValidHexCode(hexPair) === false) {
      throw Error('invalid hex pair encountered: 0x' + hexPair)
    }

    bytes.push(parseInt(hexPair, 16))
    pos += 2
  }

  return {
    endPos: pos,
    berReader: new BerReader(Buffer.from(bytes))
  }
}

function isEndChar (c) {
  switch (c) {
    case 0x20: // space
    case 0x2b: // +
    case 0x2c: // ,
    case 0x3b: // ;
      return true
    default:
      return false
  }
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"@ldapjs/asn1":2,"buffer":110}],41:[function(require,module,exports){
'use strict'

const { search } = require('@ldapjs/protocol')

const FILTERS = {
  [search.FILTER_AND]: require('../filters/and'),
  [search.FILTER_APPROX]: require('../filters/approximate'),
  [search.FILTER_EQUALITY]: require('../filters/equality'),
  [search.FILTER_EXT]: require('../filters/extensible'),
  [search.FILTER_GE]: require('../filters/greater-than-equals'),
  [search.FILTER_LE]: require('../filters/less-than-equals'),
  [search.FILTER_NOT]: require('../filters/not'),
  [search.FILTER_OR]: require('../filters/or'),
  [search.FILTER_PRESENT]: require('../filters/presence'),
  [search.FILTER_SUBSTRINGS]: require('../filters/substring')
}

/**
 * Reads a buffer that is encoded BER data and returns the appropriate
 * filter that it represents.
 *
 * @param {BerReader} ber The BER buffer to parse.
 *
 * @returns {FilterString}
 *
 * @throws If input is not of correct type or there is an error is parsing.
 */
module.exports = function parseBer (ber) {
  if (Object.prototype.toString.call(ber) !== '[object BerReader]') {
    throw new TypeError('ber (BerReader) required')
  }

  return _parse(ber)
}

function _parse (ber) {
  let f

  const filterStartOffset = ber.offset
  const type = ber.readSequence()
  switch (type) {
    case search.FILTER_AND:
    case search.FILTER_OR: {
      f = new FILTERS[type]()
      parseSet(f)
      break
    }

    case search.FILTER_NOT: {
      const innerFilter = _parse(ber)
      f = new FILTERS[type]({ filter: innerFilter })
      break
    }

    case search.FILTER_APPROX:
    case search.FILTER_EQUALITY:
    case search.FILTER_EXT:
    case search.FILTER_GE:
    case search.FILTER_LE:
    case search.FILTER_PRESENT:
    case search.FILTER_SUBSTRINGS: {
      f = FILTERS[type].parse(getBerBuffer(ber))
      break
    }

    default: {
      throw Error(
        'invalid search filter type: 0x' + type.toString(16).padStart(2, '0')
      )
    }
  }

  return f

  function parseSet (f) {
    const end = ber.offset + ber.length
    while (ber.offset < end) {
      const parsed = _parse(ber)
      f.addClause(parsed)
    }
  }

  function getBerBuffer (inputBer) {
    // Since our new filter code does not allow "empty" constructors,
    // we need to pass a BER into the filter's `.parse` method in order
    // to get a new instance. In order to do that, we need to read the
    // full BER section of the buffer for the filter. When we enter this
    // function, the tag and length has already been read in order to determine
    // what type of filter is being constructed. Since need those bytes to
    // construct a valid TLV buffer, we must rewind the offset by 2 bytes.
    ber.setOffset(filterStartOffset)

    // Next, we need the tag so that we can supply it to the raw buffer read
    // method.
    const tag = inputBer.peek()

    // We must advance the internal offset of the passed in BER here.
    // Again, this is due to the original side effect reliant nature of
    // ldapjs.
    return inputBer.readRawBuffer(tag)
  }
}

},{"../filters/and":44,"../filters/approximate":45,"../filters/equality":46,"../filters/extensible":47,"../filters/greater-than-equals":48,"../filters/less-than-equals":49,"../filters/not":50,"../filters/or":51,"../filters/presence":52,"../filters/substring":53,"@ldapjs/protocol":93}],42:[function(require,module,exports){
'use strict'

const warning = require('process-warning')()

warning.create('LdapjsFilterWarning', 'LDAP_FILTER_DEP_001', 'parse is deprecated. Use the parseString function instead.')

module.exports = warning

},{"process-warning":161}],43:[function(require,module,exports){
'use strict'

const { BerReader, BerWriter } = require('@ldapjs/asn1')

/**
 * Baseline LDAP filter object. This exists solely to define the interface
 * and basline properties and methods for actual LDAP filters.
 */
class FilterString {
  /**
   * The BER tag for the filter as defined in
   * https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.
   */
  TAG = 0x30
  // For this base `FilterString` we repurpose the sequence start tag. We
  // represent it as a sequence that contains a null value.
  // So we do this because it is nonsense to have an empty filter string.

  /**
   * Local name of the filter.
   */
  type = 'FilterString'

  /**
   * String value denoting which LDAP attribute the filter tagets. For example,
   * in the filter `(&(cn=Foo Bar))`, the value would be "cn".
   */
  attribute = ''

  #value;

  #clauses = [];

  /**
   * @typedef {object} FilterStringParams
   * @property {string} attribute The name of the attribute the filter
   * will target.
   * @property {*} value The right hand side of the filter.
   */

  /**
   * Creates a new filter object and sets the `attrbitute`.
   *
   * @param {FilterStringParams} input
   *
   * @returns {FilterString}
   */
  constructor ({ attribute = '', value, clauses = [] } = {}) {
    this.attribute = attribute
    this.#value = value

    if (Array.isArray(clauses) === false) {
      throw Error('clauses must be an array')
    }
    Array.prototype.push.apply(this.#clauses, clauses)
  }

  get [Symbol.toStringTag] () {
    return 'FilterString'
  }

  /**
   * String or Buffer representing the righthand side of the filter string.
   *
   * @property {string|Buffer} value
   */
  get value () {
    return this.#value
  }

  set value (val) {
    this.#value = val
  }

  /**
   * Determines if a filter instance meets specific criteria.
   * Each type of filter provides its own logic for this method.
   * Thus, the documentation for the method should be consulted on each
   * specific filter. This baseline implementation always returns `false`.
   *
   * @returns {boolean} Always `false`.
   */
  matches () {
    return false
  }

  /**
   * Generate a string representation of the filter.
   *
   * @returns {string}
   */
  toString () {
    return '()'
  }

  /**
   * Returns a BER instance of the filter. This is typically used when
   * constructing search messages to send to an LDAP server.
   *
   * @returns {object} A `BerReader` instance from `@ldapjs/asn1`.
   */
  toBer () {
    const ber = new BerWriter()

    ber.startSequence(this.TAG)
    this._toBer(ber)
    ber.endSequence()

    return new BerReader(ber.buffer)
  }

  _toBer (ber) {
    ber.writeNull()
  }

  /**
   * Get a "JSON" (plain JavaScript object) representation of the filter.
   * Do not rely on this property to exist.
   *
   * @deprecated 2022-06-12
   * @property {object}
   */
  get json () {
    return {
      type: this.type,
      attribute: this.attribute,
      value: this.#value
    }
  }

  /**
   * Alias for the filter itself. This is added for backward compatibility.
   * Do not rely on this property.
   *
   * @deprecated 2022-06-12
   * @property {FilterString}
   */
  get filter () {
    return this
  }

  /**
   * Alias for accessing the filter clauses. This is added for backward
   * compatibility. Do not rely on this property.
   *
   * @deprecated 2022-06-12
   * @property {FilterString[]}
   */
  get filters () {
    return this.#clauses
  }

  /**
   * Most filters, e.g. "and" and "not" filters, can have multiple filter
   * clauses. For example, the filter `(&(foo=a)(bar=b))` is an "and" filter
   * with two clauses: `(foo=a)` and `(bar=b)`. This property provides access
   * to the sibling clauses, which are themselves `FilterString` instances.
   *
   * @property {FilterString[]}
   */
  get clauses () {
    return this.#clauses
  }

  /**
   * @callback filterForEachCallback
   * @param {FilterString}
   */
  /**
   * For every filter clause in the filter, apply a callback function.
   * This includes the root filter.
   *
   * @param {filterForEachCallback} callback
   */
  forEach (callback) {
    this.#clauses.forEach(clause => clause.forEach(callback))
    callback(this) // eslint-disable-line
  }

  /**
   * @callback filterMapCallback
   * @param {FilterString}
   */
  /**
   * For every filter clause in the filter, including the root filter,
   * apply a mutation callback.
   *
   * @param {filterMapCallback} callback
   * @returns {FilterString|*} The result of applying the callback to the
   * root filter.
   */
  map (callback) {
    if (this.#clauses.length === 0) {
      return callback(this) // eslint-disable-line
    }

    const child = this.#clauses
      .map(clause => clause.map(callback))
      .filter(clause => clause !== null)
    if (child.length === 0) {
      return null
    }
    this.#clauses = child
    return callback(this) // eslint-disable-line
  }

  /**
   * Alias for `.addClause`. This is added for backward compatibility.
   * Do not rely on this.
   *
   * @deprecated 2022-06-12
   * @param {FilterString} filter
   */
  addFilter (filter) {
    this.addClause(filter)
  }

  /**
   * Adds a new filter clause to the filter.
   *
   * @see clauses
   * @param {FilterString} clause
   */
  addClause (clause) {
    if (clause instanceof FilterString === false) {
      throw Error('clause must be an instance of FilterString')
    }
    this.#clauses.push(clause)
  }

  /**
   * Parses a `Buffer` instance and returns a new `FilterString` representation.
   * Each `FilterString` implementation must implement this method.
   *
   * @param {Buffer} buffer
   *
   * @throws When the input `buffer` does not match the expected format.
   *
   * @returns {FilterString}
   */
  static parse (buffer) {
    // It is actually nonsense to implement this method for the base
    // `FilteSring`, but we do it any way for completeness sake. We effectively
    // just validate that the input buffer is the one we expect for our made up
    // "empty" filter string and return a new instance if the buffer validates.

    if (buffer.length !== 4) {
      throw Error(`expected buffer length 4, got ${buffer.length}`)
    }

    const reader = new BerReader(buffer)
    let seq = reader.readSequence()
    if (seq !== 0x30) {
      throw Error(`expected sequence start, got 0x${seq.toString(16).padStart(2, '0')}`)
    }

    seq = reader.readSequence()
    if (seq !== 0x05) {
      throw Error(`expected null sequence start, got 0x${seq.toString(16).padStart(2, '0')}`)
    }

    return new FilterString()
  }
}

module.exports = FilterString

},{"@ldapjs/asn1":2}],44:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { search } = require('@ldapjs/protocol')

/**
 * Represents a set of filters that must all match for the filter to
 * match, e.g. `(&(cn=foo)(sn=bar))`.
 */
class AndFilter extends FilterString {
  /**
   * @typedef {FilterStringParams} AndFilterParams
   * @property {FilterString[]} [filters=[]] A set of filters which comprise
   * the clauses of the `AND` filter.
   */

  /**
   * @param {AndFilterParams} input
   *
   * @throws When a filter is not an instance of {@link FilterString}.
   */
  constructor ({ filters = [] } = {}) {
    super({})

    // AND filters do not have an `attribute` property.
    this.attribute = undefined

    for (const filter of filters) {
      this.addClause(filter)
    }

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_AND },
      type: { value: 'AndFilter' }
    })
  }

  get json () {
    return {
      type: this.type,
      filters: this.clauses.map(clause => clause.json)
    }
  }

  toString () {
    let result = '(&'
    for (const clause of this.clauses) {
      result += clause.toString()
    }
    result += ')'
    return result
  }

  /**
   * Determines if an object represents an equivalent filter instance.
   * Both the filter attribute and filter value must match the comparison
   * object. All clauses of the `AND` filter, that is all "sub filters", must
   * match for the result to be `true`.
   *
   * @example
   * const eqFilter = new EqualityFilter({ attribute: 'foo', value: 'bar' })
   * const filter = new AndFilter({ filters: [eqFilter] })
   * assert.equal(filter.matches({ foo: 'bar' }), true)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttrCase=true] If `false`, "fOo" will match
   * "foo" in the attribute position (left hand side).
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttrCase = true) {
    if (this.clauses.length === 0) {
      // https://datatracker.ietf.org/doc/html/rfc4526#section-2
      return true
    }

    for (const clause of this.clauses) {
      if (Array.isArray(obj) === true) {
        for (const attr of obj) {
          // For each passed in attribute, we need to determine if the current
          // clause matches the attribute name. If it does, we need to
          // determine if the values match.
          if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
            throw Error('array element must be an instance of LdapAttribute')
          }
          if (attr.type !== clause.attribute) {
            continue
          }
          if (clause.matches(attr, strictAttrCase) === false) {
            return false
          }
        }
      } else {
        if (clause.matches(obj, strictAttrCase) === false) {
          return false
        }
      }
    }

    return true
  }

  _toBer (ber) {
    for (const clause of this.clauses) {
      const filterBer = clause.toBer()
      ber.appendBuffer(filterBer.buffer)
    }
    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {AndFilter}
   */
  static parse (buffer) {
    const parseNestedFilter = require('./utils/parse-nested-filter')
    return parseNestedFilter({
      buffer,
      constructor: AndFilter,
      startTag: search.FILTER_AND
    })
  }
}

module.exports = AndFilter

},{"../filter-string":43,"./utils/parse-nested-filter":54,"@ldapjs/protocol":93}],45:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { BerReader } = require('@ldapjs/asn1')
const { search } = require('@ldapjs/protocol')
const escapeFilterValue = require('../utils/escape-filter-value')

/**
 * Represents a basic filter for determining if an LDAP entry contains a
 * specified attribute that is approximately equal a given value,
 * e.g. `(cn~=foo)`.
 */
class ApproximateFilter extends FilterString {
  /**
   * @typedef {FilterStringParams} AttributeParams
   */

  /**
   * @param {AttributeParams} input
   *
   * @throws When either `attribute` or `value` is not a string of at least
   * one character.
   */
  constructor ({ attribute, value } = {}) {
    if (typeof attribute !== 'string' || attribute.length < 1) {
      throw Error('attribute must be a string of at least one character')
    }
    if (typeof value !== 'string' || value.length < 1) {
      throw Error('value must be a string of at least one character')
    }

    super({ attribute, value })

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_APPROX },
      type: { value: 'ApproximateFilter' }
    })
  }

  /**
   * Not implemented.
   *
   * @throws In all cases.
   */
  matches () {
    throw Error('not implemented')
  }

  toString () {
    return ('(' + escapeFilterValue(this.attribute) +
          '~=' + escapeFilterValue(this.value) + ')')
  }

  _toBer (ber) {
    ber.writeString(this.attribute)
    ber.writeString(this.value)
    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {ApproximateFilter}
   */
  static parse (buffer) {
    const reader = new BerReader(buffer)

    const seq = reader.readSequence()
    if (seq !== search.FILTER_APPROX) {
      const expected = '0x' + search.FILTER_APPROX.toString(16).padStart(2, '0')
      const found = '0x' + seq.toString(16).padStart(2, '0')
      throw Error(`expected approximate filter sequence ${expected}, got ${found}`)
    }

    const attribute = reader.readString()
    const value = reader.readString()

    return new ApproximateFilter({ attribute, value })
  }
}

module.exports = ApproximateFilter

},{"../filter-string":43,"../utils/escape-filter-value":61,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],46:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const FilterString = require('../filter-string')
const { BerReader, BerTypes } = require('@ldapjs/asn1')
const { search } = require('@ldapjs/protocol')
const escapeFilterValue = require('../utils/escape-filter-value')
const testValues = require('../utils/test-values')
const getAttributeValue = require('../utils/get-attribute-value')

/**
 * Represents a basic filter for determining if an LDAP entry contains a
 * specified attribute that equals a given value, e.g. `(cn=foo)`.
 */
class EqualityFilter extends FilterString {
  #raw

  /**
   * @typedef {FilterStringParams} EqualityParams
   * @property {string} attribute The name of the LDAP addtribute this
   * filter will target.
   * @property {string|Buffer} [value] A string or buffer value as the
   * test for this filter. Required if `raw` is not provided.
   * @property {Buffer} [raw] A buffer to use as the test for this filter.
   * Required if `value` is not provided.
   */

  /**
   * @param {EqualityParams} input
   *
   * @throws When no value, either through `value` or `raw`, is provided.
   * Also throws when `attribute` is not a string.
   */
  constructor ({ attribute, raw, value } = {}) {
    if (typeof attribute !== 'string' || attribute.length < 1) {
      throw Error('attribute must be a string of at least one character')
    }

    super({ attribute, value })

    if (raw) {
      this.#raw = raw
    } else {
      if (!value) {
        throw Error('must either provide a buffer via `raw` or some `value`')
      }
      this.#raw = Buffer.from(value)
    }

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_EQUALITY },
      type: { value: 'EqualityFilter' }
    })
  }

  get value () {
    return Buffer.isBuffer(this.#raw) ? this.#raw.toString() : this.#raw
  }

  set value (val) {
    if (typeof val === 'string') {
      this.#raw = Buffer.from(val)
    } else if (Buffer.isBuffer(val)) {
      this.#raw = Buffer.alloc(val.length)
      val.copy(this.#raw)
    } else {
      this.#raw = val
    }
  }

  /**
   * Determines if an object represents an equivalent filter instance.
   * Both the filter attribute and filter value must match the comparison
   * object.
   *
   * @example
   * const filter = new EqualityFilter({ attribute: 'foo', value: 'bar' })
   * assert.equal(filter.matches({ foo: 'bar' }), true)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttrCase=true] If `false`, "fOo" will match
   * "foo" in the attribute position (left hand side).
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttrCase = true) {
    if (Array.isArray(obj) === true) {
      for (const attr of obj) {
        if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
          throw Error('array element must be an instance of LdapAttribute')
        }
        if (this.matches(attr, strictAttrCase) === true) {
          return true
        }
      }
      return false
    }

    let testValue = this.value

    if (this.attribute.toLowerCase() === 'objectclass') {
      // Perform a case-insensitive match for `objectClass` as most LDAP
      // implementations behave in this manner.
      const targetAttribute = getAttributeValue({
        sourceObject: obj,
        attributeName: this.attribute,
        strictCase: false
      })
      testValue = testValue.toLowerCase()
      return testValues({
        rule: v => testValue === v.toLowerCase(),
        value: targetAttribute
      })
    }

    const targetAttribute = getAttributeValue({
      sourceObject: obj,
      attributeName: this.attribute,
      strictCase: strictAttrCase
    })
    return testValues({
      rule: v => testValue === v,
      value: targetAttribute
    })
  }

  /**
   * @throws When `value` is not a string or a buffer.
   */
  toString () {
    let value
    if (Buffer.isBuffer(this.#raw)) {
      value = this.#raw
      const decoded = this.#raw.toString('utf8')
      const validate = Buffer.from(decoded, 'utf8')

      // Use the decoded UTF-8 if it is valid, otherwise fall back to bytes.
      // Since Buffer.compare is missing in older versions of node, a simple
      // length comparison is used as a heuristic.  This can be updated later to
      // a full compare if it is found lacking.
      if (validate.length === this.#raw.length) {
        value = decoded
      }
    } else if (typeof (this.#raw) === 'string') {
      value = this.#raw
    } else {
      throw new Error('invalid value type')
    }
    return ('(' + escapeFilterValue(this.attribute) +
          '=' + escapeFilterValue(value) + ')')
  }

  _toBer (ber) {
    ber.writeString(this.attribute)
    ber.writeBuffer(this.#raw, BerTypes.OctetString)
    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {EqualityFilter}
   */
  static parse (buffer) {
    const reader = new BerReader(buffer)

    const tag = reader.readSequence()
    if (tag !== search.FILTER_EQUALITY) {
      const expected = '0x' + search.FILTER_EQUALITY.toString(16).padStart(2, '0')
      const found = '0x' + tag.toString(16).padStart(2, '0')
      throw Error(`expected equality filter sequence ${expected}, got ${found}`)
    }

    const attribute = reader.readString()
    const value = reader.readString(BerTypes.OctetString, true)

    return new EqualityFilter({ attribute, value })
  }
}

module.exports = EqualityFilter

}).call(this)}).call(this,require("buffer").Buffer)
},{"../filter-string":43,"../utils/escape-filter-value":61,"../utils/get-attribute-value":62,"../utils/test-values":63,"@ldapjs/asn1":2,"@ldapjs/protocol":93,"buffer":110}],47:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { search } = require('@ldapjs/protocol')
const { BerReader } = require('@ldapjs/asn1')

/**
 * Represents an extensible LDAP filter as defined in
 * https://www.rfc-editor.org/rfc/rfc2251.html#section-4.5.1.
 */
class ExtensibleFilter extends FilterString {
  #dnAttributes;
  #rule;

  /**
   * @typedef {FilterStringParams} ExtensibleParams
   * @property {string|undefined} [attribute=''] Name of the attribute to
   * match against, if any.
   * @property {*} [value=''] Value to test for.
   * @property {string} [rule] A matching rule OID if a speficic matching
   * rule is to be used.
   * @property {string|undefined} [matchType=''] An alias for `attribute`.
   * This parameter is provided for backward compatibility. Use `attribute`
   * instead.
   * @property {boolean} [dnAttributes=false] Indicates if all attributes
   * of a matching distinguished name should be tested.
   */

  /**
   * @param {ExtensibleParams} input
   *
   * @throws When `dnAttbributes` or `rule` are not valid.
   */
  constructor ({ attribute, value, rule, matchType, dnAttributes = false } = {}) {
    // `attribute` and `matchType` are allowed to be `undefined` per the
    // RFC. When either is not provided, an empty string will be used.
    // This is covered in the `toString` and `toBer` methods.

    if (typeof dnAttributes !== 'boolean') {
      throw Error('dnAttributes must be a boolean value')
    }
    if (rule && typeof rule !== 'string') {
      throw Error('rule must be a string')
    }

    super({ attribute, value })

    if (matchType !== undefined) {
      this.attribute = matchType
    }

    this.#dnAttributes = dnAttributes
    this.#rule = rule
    this.value = value ?? ''

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_EXT },
      type: { value: 'ExtensibleFilter' }
    })
  }

  get json () {
    return {
      type: this.type,
      matchRule: this.#rule,
      matchType: this.attribute,
      matchValue: this.value,
      dnAttributes: this.#dnAttributes
    }
  }

  get dnAttributes () {
    return this.#dnAttributes
  }

  get matchingRule () {
    return this.#rule
  }

  get matchValue () {
    return this.value
  }

  get matchType () {
    return this.attribute
  }

  toString () {
    let result = '('

    if (this.attribute) {
      result += this.attribute
    }

    result += ':'

    if (this.#dnAttributes === true) {
      result += 'dn:'
    }

    if (this.#rule) {
      result += this.#rule + ':'
    }

    result += '=' + this.value + ')'
    return result
  }

  /**
   * Not implemented.
   *
   * @throws In all cases.
   */
  matches () {
    throw Error('not implemented')
  }

  _toBer (ber) {
    if (this.#rule) { ber.writeString(this.#rule, 0x81) }
    if (this.attribute) { ber.writeString(this.attribute, 0x82) }

    ber.writeString(this.value, 0x83)
    if (this.#dnAttributes === true) {
      ber.writeBoolean(this.#dnAttributes, 0x84)
    }

    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag, or an
   * invalid context specific tag is encountered.
   *
   * @returns {ExtensibleFilter}
   */
  static parse (buffer) {
    const reader = new BerReader(buffer)

    const seq = reader.readSequence()
    if (seq !== search.FILTER_EXT) {
      const expected = '0x' + search.FILTER_EXT.toString(16).padStart(2, '0')
      const found = '0x' + seq.toString(16).padStart(2, '0')
      throw Error(`expected extensible filter sequence ${expected}, got ${found}`)
    }

    let rule
    let attribute
    let value
    let dnAttributes

    // Must set end outside of loop as the reader will update the
    // length property as the buffer is read.
    const end = reader.buffer.length
    while (reader.offset < end) {
      // Read the context specific tag and act accordingly.
      const tag = reader.peek()
      switch (tag) {
        case 0x81: {
          rule = reader.readString(tag)
          break
        }
        case 0x82: {
          attribute = reader.readString(tag)
          break
        }
        case 0x83: {
          value = reader.readString(tag)
          break
        }
        case 0x84: {
          dnAttributes = reader.readBoolean(tag)
          break
        }
        default: {
          throw Error('invalid extensible filter type: 0x' + tag.toString(16).padStart(2, '0'))
        }
      }
    }

    return new ExtensibleFilter({ attribute, value, rule, dnAttributes })
  }
}

module.exports = ExtensibleFilter

},{"../filter-string":43,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],48:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { BerReader } = require('@ldapjs/asn1')
const { search } = require('@ldapjs/protocol')
const escapeFilterValue = require('../utils/escape-filter-value')
const testValues = require('../utils/test-values')
const getAttributeValue = require('../utils/get-attribute-value')

/**
 * Represents a basic filter for determining if an LDAP entry contains a
 * specified attribute that is greater than or equal to a given value,
 * e.g. `(cn>=foo)`.
 */
class GreaterThanEqualsFilter extends FilterString {
  /**
   * @typedef {FilterStringParams} GreaterThanEqualsParams
   * @property {string} attribute
   * @property {string} value
   */

  /**
   * @param {GreaterThanEqualsParams} input
   *
   * @throws When `attribute` or `value` is not a string.
   */
  constructor ({ attribute, value } = {}) {
    if (typeof attribute !== 'string' || attribute.length < 1) {
      throw Error('attribute must be a string of at least one character')
    }
    if (typeof value !== 'string' || value.length < 1) {
      throw Error('value must be a string of at least one character')
    }

    super({ attribute, value })

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_GE },
      type: { value: 'GreaterThanEqualsFilter' }
    })
  }

  /**
   * Determines if an object represents a greater-than-equals filter instance.
   * Both the filter attribute and filter value must match the comparison
   * object.
   *
   * @example
   * const filter = new GreaterThanEqualsFilter({ attribute: 'foo', value: 'bar' })
   * assert.equal(filter.matches({ foo: 'bar' }), true)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttrCase=true] If `false`, "fOo" will match
   * "foo" in the attribute position (left hand side).
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttrCase = true) {
    if (Array.isArray(obj) === true) {
      for (const attr of obj) {
        if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
          throw Error('array element must be an instance of LdapAttribute')
        }
        if (this.matches(attr, strictAttrCase) === true) {
          return true
        }
      }
      return false
    }

    const testValue = this.value
    const targetAttribute = getAttributeValue({ sourceObject: obj, attributeName: this.attribute, strictCase: strictAttrCase })

    return testValues({
      rule: v => testValue <= v,
      value: targetAttribute
    })
  }

  toString () {
    return ('(' + escapeFilterValue(this.attribute) +
          '>=' + escapeFilterValue(this.value) + ')')
  }

  _toBer (ber) {
    ber.writeString(this.attribute)
    ber.writeString(this.value)
    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {GreaterThanEqualsFilter}
   */
  static parse (buffer) {
    const reader = new BerReader(buffer)

    const seq = reader.readSequence()
    if (seq !== search.FILTER_GE) {
      const expected = '0x' + search.FILTER_GE.toString(16).padStart(2, '0')
      const found = '0x' + seq.toString(16).padStart(2, '0')
      throw Error(`expected greater-than-equals filter sequence ${expected}, got ${found}`)
    }

    const attribute = reader.readString()
    const value = reader.readString()

    return new GreaterThanEqualsFilter({ attribute, value })
  }
}

module.exports = GreaterThanEqualsFilter

},{"../filter-string":43,"../utils/escape-filter-value":61,"../utils/get-attribute-value":62,"../utils/test-values":63,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],49:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { BerReader } = require('@ldapjs/asn1')
const { search } = require('@ldapjs/protocol')

const escapeFilterValue = require('../utils/escape-filter-value')
const testValues = require('../utils/test-values')
const getAttributeValue = require('../utils/get-attribute-value')

/**
 * Represents a basic filter for determining if an LDAP entry contains a
 * specified attribute that is less than or equal to a given value,
 * e.g. `(cn<=foo)`.
 */
class LessThanEqualsFilter extends FilterString {
  /**
   * @typedef {FilterStringParams} LessThanEqualsParams
   * @property {string} attribute
   * @property {string} value
   */

  /**
   * @param {LessThanEqualsParams} input
   *
   * @throws When `attribute` or `value` is not a string.
   */
  constructor ({ attribute, value } = {}) {
    if (typeof attribute !== 'string' || attribute.length < 1) {
      throw Error('attribute must be a string of at least one character')
    }
    if (typeof value !== 'string' || value.length < 1) {
      throw Error('value must be a string of at least one character')
    }

    super({ attribute, value })

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_LE },
      type: { value: 'LessThanEqualsFilter' }
    })
  }

  toString () {
    return ('(' + escapeFilterValue(this.attribute) +
          '<=' + escapeFilterValue(this.value) + ')')
  }

  /**
   * Determines if an object represents a less-than-equals filter instance.
   * Both the filter attribute and filter value must match the comparison
   * object.
   *
   * @example
   * const filter = new LessThanEqualsFilter({ attribute: 'foo', value: 'bar' })
   * assert.equal(filter.matches({ foo: 'bar' }), true)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttrCase=true] If `false`, "fOo" will match
   * "foo" in the attribute position (left hand side).
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttrCase = true) {
    if (Array.isArray(obj) === true) {
      for (const attr of obj) {
        if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
          throw Error('array element must be an instance of LdapAttribute')
        }
        if (this.matches(attr, strictAttrCase) === true) {
          return true
        }
      }
      return false
    }

    const testValue = this.value
    const targetAttribute = getAttributeValue({ sourceObject: obj, attributeName: this.attribute, strictCase: strictAttrCase })

    return testValues({
      rule: v => v <= testValue,
      value: targetAttribute
    })
  }

  _toBer (ber) {
    ber.writeString(this.attribute)
    ber.writeString(this.value)
    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {LessThanEqualsFilter}
   */
  static parse (buffer) {
    const reader = new BerReader(buffer)

    const seq = reader.readSequence()
    if (seq !== search.FILTER_LE) {
      const expected = '0x' + search.FILTER_LE.toString(16).padStart(2, '0')
      const found = '0x' + seq.toString(16).padStart(2, '0')
      throw Error(`expected less-than-equals filter sequence ${expected}, got ${found}`)
    }

    const attribute = reader.readString()
    const value = reader.readString()

    return new LessThanEqualsFilter({ attribute, value })
  }
}

module.exports = LessThanEqualsFilter

},{"../filter-string":43,"../utils/escape-filter-value":61,"../utils/get-attribute-value":62,"../utils/test-values":63,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],50:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { search } = require('@ldapjs/protocol')

/**
 * Represents a basic filter that negates other filters, e.g.
 * `(!(cn=foo))`. A `NotFilter` may only have one direct negated
 * filter, but that filter may represent a multiple clause filter
 * such as an `AndFilter`.
 */
class NotFilter extends FilterString {
  /**
   * @typedef {FilterStringParams} NotParams
   * @property {FilterString} filter The filter to negate.
   */

  /**
   * @param {NotParams} input
   *
   * @throws If not filter is provided.
   */
  constructor ({ filter } = {}) {
    if (filter instanceof FilterString === false) {
      throw Error('filter is required and must be a filter instance')
    }

    super()

    // We set `attribute` to `undefined` because the NOT filter is a specal
    // case: it must not have an attribute or an value. It must have an inner
    // filter.
    this.attribute = undefined
    this.filter = filter

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_NOT },
      type: { value: 'NotFilter' }
    })
  }

  get json () {
    return {
      type: this.type,
      filter: this.filter.json
    }
  }

  get filter () {
    return this.clauses[0]
  }

  set filter (filter) {
    if (filter instanceof FilterString === false) {
      throw Error('filter must be a filter instance')
    }
    this.clauses[0] = filter
  }

  setFilter (filter) {
    this.clauses[0] = filter
  }

  toString () {
    return '(!' + this.filter.toString() + ')'
  }

  /**
   * Invokes the direct filter's `matches` routine and inverts the result.
   *
   * @example
   * const eqFilter = new EqualityFilter({ attribute: 'foo', value: 'bar' })
   * const filter = new NotFilter({ filter: eqFilter })
   * assert.equal(filter.matches({ foo: 'bar' }), false)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttrCase=true] If `false`, "fOo" will match
   * "foo" in the attribute position (left hand side).
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttrCase = true) {
    return !this.filter.matches(obj, strictAttrCase)
  }

  _toBer (ber) {
    const innerBer = this.filter.toBer(ber)
    ber.appendBuffer(innerBer.buffer)
    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {NotFilter}
   */
  static parse (buffer) {
    const parseNestedFilter = require('./utils/parse-nested-filter')
    return parseNestedFilter({
      buffer,
      constructor: NotFilter,
      startTag: search.FILTER_NOT
    })
  }
}

module.exports = NotFilter

},{"../filter-string":43,"./utils/parse-nested-filter":54,"@ldapjs/protocol":93}],51:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { search } = require('@ldapjs/protocol')

/**
 * Represents a set of filters that must all match for the filter to
 * match, e.g. `(|(cn=foo)(sn=bar))`.
 */
class OrFilter extends FilterString {
  /**
   * @typedef {FilterStringParams} OrParams
   * @property {FilterString[]} [filters=[]] A set of filters which comprise
   * the clauses of the `OR` filter.
   */

  /**
   * @param {OrParams} input
   *
   * @throws When a filter is not an instance of {@link FilterString}.
   */
  constructor ({ filters = [] } = {}) {
    super({})

    // OR filters do not have an `attribute` property.
    this.attribute = undefined

    for (const filter of filters) {
      this.addClause(filter)
    }

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_OR },
      type: { value: 'OrFilter' }
    })
  }

  get json () {
    return {
      type: this.type,
      filters: this.clauses.map(clause => clause.json)
    }
  }

  toString () {
    let result = '(|'
    for (const clause of this.clauses) {
      result += clause.toString()
    }
    result += ')'
    return result
  }

  /**
   * Determines if an object represents an equivalent filter instance.
   * Both the filter attribute and filter value must match the comparison
   * object. Any clause of the `OR` filter, that is all "sub filters", may
   * match for the result to be `true`.
   *
   * @example
   * const eqFilter = new EqualityFilter({ attribute: 'foo', value: 'bar' })
   * const filter = new OrFilter({ filters: [eqFilter] })
   * assert.equal(filter.matches({ foo: 'bar' }), true)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttrCase=true] If `false`, "fOo" will match
   * "foo" in the attribute position (left hand side).
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttrCase = true) {
    if (this.clauses.length === 0) {
      // https://datatracker.ietf.org/doc/html/rfc4526#section-2
      return false
    }

    for (const clause of this.clauses) {
      if (Array.isArray(obj) === true) {
        for (const attr of obj) {
          // For each passed in attribute, we need to determine if the current
          // clause matches the attribute name. If it does, we need to
          // determine if the values match.
          if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
            throw Error('array element must be an instance of LdapAttribute')
          }
          if (attr.type !== clause.attribute) {
            continue
          }
          if (clause.matches(attr, strictAttrCase) === true) {
            return true
          }
        }
      } else {
        if (clause.matches(obj, strictAttrCase) === true) {
          return true
        }
      }
    }

    return false
  }

  _toBer (ber) {
    for (const clause of this.clauses) {
      const filterBer = clause.toBer()
      ber.appendBuffer(filterBer.buffer)
    }
    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {OrFilter}
   */
  static parse (buffer) {
    const parseNestedFilter = require('./utils/parse-nested-filter')
    return parseNestedFilter({
      buffer,
      constructor: OrFilter,
      startTag: search.FILTER_OR
    })
  }
}

module.exports = OrFilter

},{"../filter-string":43,"./utils/parse-nested-filter":54,"@ldapjs/protocol":93}],52:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { BerReader } = require('@ldapjs/asn1')
const { search } = require('@ldapjs/protocol')
const escapeFilterValue = require('../utils/escape-filter-value')
const getAttributeValue = require('../utils/get-attribute-value')

/**
 * Represents a basic filter for determining if an LDAP entry contains a
 * specified attribute, e.g. `(cn=*)`.
 */
class PresenceFilter extends FilterString {
  /**
   * @typedef {FilterStringParams} PresenceParams
   * @property {string} attribute The name of the attribute this filter targets.
   */

  /**
   * @param {PresenceParams} input
   *
   * @throws If no attribute name is given.
   */
  constructor ({ attribute } = {}) {
    if (typeof attribute !== 'string' || attribute.length < 1) {
      throw Error('attribute must be a string of at least one character')
    }

    super({ attribute })

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_PRESENT },
      type: { value: 'PresenceFilter' }
    })
  }

  /**
   * Determine if a given object matches the filter instance.
   *
   * @example
   * const filter = new PresenceFilter({ attribute: 'foo' })
   * assert.equal(filter.matches({ foo: "bar" }), true)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttributeCase=true] If `false`, "fOo" will match
   * "foo".
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttributeCase = true) {
    if (Array.isArray(obj) === true) {
      for (const attr of obj) {
        if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
          throw Error('array element must be an instance of LdapAttribute')
        }
        if (this.matches(attr, strictAttributeCase) === true) {
          return true
        }
      }
      return false
    }

    return getAttributeValue({
      sourceObject: obj,
      attributeName: this.attribute,
      strictCase: strictAttributeCase
    }) !== undefined
  }

  toString () {
    return `(${escapeFilterValue(this.attribute)}=*)`
  }

  _toBer (ber) {
    for (let i = 0; i < this.attribute.length; i++) {
      ber.writeByte(this.attribute.charCodeAt(i))
    }
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {PresenceFilter}
   */
  static parse (buffer) {
    const reader = new BerReader(buffer)

    const tag = reader.peek()
    if (tag !== search.FILTER_PRESENT) {
      const expected = '0x' + search.FILTER_PRESENT.toString(16).padStart(2, '0')
      const found = '0x' + tag.toString(16).padStart(2, '0')
      throw Error(`expected presence filter sequence ${expected}, got ${found}`)
    }

    const attribute = reader.readString(tag)
    return new PresenceFilter({ attribute })
  }
}

module.exports = PresenceFilter

},{"../filter-string":43,"../utils/escape-filter-value":61,"../utils/get-attribute-value":62,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],53:[function(require,module,exports){
'use strict'

const FilterString = require('../filter-string')
const { BerReader } = require('@ldapjs/asn1')
const { search } = require('@ldapjs/protocol')
const escapeFilterValue = require('../utils/escape-filter-value')
const testValues = require('../utils/test-values')
const getAttributeValue = require('../utils/get-attribute-value')

/**
 * Represents a filter that matches substrings withing LDAP entry attribute
 * values, e.g. `(cn=*f*o*o)`.
 */
class SubstringFilter extends FilterString {
  #subInitial;
  #subAny = [];
  #subFinal;

  /**
   * @typedef {FilterStringParams} SubstringParams
   * @property {string} input.attribute The attribute to test against.
   * @property {string} [subInitial] Text that must appear at the start
   * of a value and may not overlap any value of `subAny` or `subFinal`.
   * @property {string[]} [subAny] Text items that must appear in the
   * attribute value that do not overlap with `subInitial`, `subFinal`, or
   * any other `subAny` item.
   * @property {string} [subFinal] Text that must appear at the end of
   * the attribute value. May not overlap with `subInitial` or any `subAny`
   * item.
   */

  /**
   * @param {SubstringParams} input
   *
   * @throws When any input parameter is of an incorrect type.
   */
  constructor ({ attribute, subInitial, subAny = [], subFinal } = {}) {
    if (typeof attribute !== 'string' || attribute.length < 1) {
      throw Error('attribute must be a string of at least one character')
    }
    if (Array.isArray(subAny) === false) {
      throw Error('subAny must be an array of items')
    }
    if (subFinal && typeof subFinal !== 'string') {
      throw Error('subFinal must be a string')
    }

    super({ attribute })

    this.#subInitial = subInitial
    Array.prototype.push.apply(this.#subAny, subAny)
    this.#subFinal = subFinal

    Object.defineProperties(this, {
      TAG: { value: search.FILTER_SUBSTRINGS },
      type: { value: 'SubstringFilter' }
    })
  }

  get subInitial () {
    return this.#subInitial
  }

  get subAny () {
    return this.#subAny
  }

  get subFinal () {
    return this.#subFinal
  }

  get json () {
    return {
      type: this.type,
      subInitial: this.#subInitial,
      subAny: this.#subAny,
      subFinal: this.#subFinal
    }
  }

  toString () {
    let result = '(' + escapeFilterValue(this.attribute) + '='

    if (this.#subInitial) {
      result += escapeFilterValue(this.#subInitial)
    }

    result += '*'

    for (const any of this.#subAny) {
      result += escapeFilterValue(any) + '*'
    }

    if (this.#subFinal) {
      result += escapeFilterValue(this.#subFinal)
    }

    result += ')'
    return result
  }

  /**
   * Determines if an object represents an equivalent filter instance.
   * Both the filter attribute and filter value must match the comparison
   * object.
   *
   * @example
   * const filter = new EqualityFilter({ attribute: 'foo', subInitial: 'bar' })
   * assert.equal(filter.matches({ foo: 'bar' }), true)
   *
   * @param {object} obj An object to check for match.
   * @param {boolean} [strictAttrCase=true] If `false`, "fOo" will match
   * "foo" in the attribute position (left hand side).
   *
   * @throws When input types are not correct.
   *
   * @returns {boolean}
   */
  matches (obj, strictAttrCase) {
    if (Array.isArray(obj) === true) {
      for (const attr of obj) {
        if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
          throw Error('array element must be an instance of LdapAttribute')
        }
        if (this.matches(attr, strictAttrCase) === true) {
          return true
        }
      }
      return false
    }

    const targetValue = getAttributeValue({ sourceObject: obj, attributeName: this.attribute, strictCase: strictAttrCase })

    if (targetValue === undefined || targetValue === null) {
      return false
    }

    let re = ''

    if (this.#subInitial) { re += '^' + escapeRegExp(this.#subInitial) + '.*' }
    this.#subAny.forEach(function (s) {
      re += escapeRegExp(s) + '.*'
    })
    if (this.#subFinal) { re += escapeRegExp(this.#subFinal) + '$' }

    const matcher = new RegExp(re)
    return testValues({
      rule: v => matcher.test(v),
      value: targetValue
    })
  }

  _toBer (ber) {
    // Tag sequence as already been started via FilterString.toBer, so
    // start by writing the "type" field.
    ber.writeString(this.attribute)
    ber.startSequence()

    if (this.#subInitial) { ber.writeString(this.#subInitial, 0x80) }

    if (this.#subAny.length > 0) {
      for (const sub of this.#subAny) {
        ber.writeString(sub, 0x81)
      }
    }

    if (this.#subFinal) { ber.writeString(this.#subFinal, 0x82) }

    ber.endSequence()

    return ber
  }

  /**
   * Parses a BER encoded `Buffer` and returns a new filter.
   *
   * @param {Buffer} buffer BER encoded buffer.
   *
   * @throws When the buffer does not start with the proper BER tag.
   *
   * @returns {AndFilter}
   */
  static parse (buffer) {
    const reader = new BerReader(buffer)

    const seq = reader.readSequence()
    if (seq !== search.FILTER_SUBSTRINGS) {
      const expected = '0x' + search.FILTER_SUBSTRINGS.toString(16).padStart(2, '0')
      const found = '0x' + seq.toString(16).padStart(2, '0')
      throw Error(`expected substring filter sequence ${expected}, got ${found}`)
    }

    let subInitial
    const subAny = []
    let subFinal

    const attribute = reader.readString()
    reader.readSequence()

    // Must set end outside of loop as the reader will update the
    // length property as the buffer is read.
    const end = reader.offset + reader.length
    while (reader.offset < end) {
      const tag = reader.peek()
      switch (tag) {
        case 0x80: { // Initial
          subInitial = reader.readString(tag)
          break
        }

        case 0x81: { // Any
          const anyVal = reader.readString(tag)
          subAny.push(anyVal)
          break
        }

        case 0x82: { // Final
          subFinal = reader.readString(tag)
          break
        }

        default: {
          throw new Error('Invalid substrings filter type: 0x' + tag.toString(16))
        }
      }
    }

    return new SubstringFilter({ attribute, subInitial, subAny, subFinal })
  }
}

function escapeRegExp (str) {
  return str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&') // eslint-disable-line
}

module.exports = SubstringFilter

},{"../filter-string":43,"../utils/escape-filter-value":61,"../utils/get-attribute-value":62,"../utils/test-values":63,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],54:[function(require,module,exports){
'use strict'

const { search } = require('@ldapjs/protocol')
const { BerReader } = require('@ldapjs/asn1')

module.exports = function parseNestedFilter ({ startTag, buffer, constructor }) {
  // We need to import all of the filter objects within the function
  // because this function is meant to be used within each of the objects's
  // `parse` methods. If we import outside of this function, we will get
  // circular import errors.
  const FILTERS = {
    [search.FILTER_AND]: require('../and'),
    [search.FILTER_APPROX]: require('../approximate'),
    [search.FILTER_EQUALITY]: require('../equality'),
    [search.FILTER_EXT]: require('../extensible'),
    [search.FILTER_GE]: require('../greater-than-equals'),
    [search.FILTER_LE]: require('../less-than-equals'),
    [search.FILTER_NOT]: require('../not'),
    [search.FILTER_OR]: require('../or'),
    [search.FILTER_PRESENT]: require('../presence'),
    [search.FILTER_SUBSTRINGS]: require('../substring')
  }

  const reader = new BerReader(buffer)

  const seq = reader.readSequence()
  if (seq !== startTag) {
    const expected = '0x' + startTag.toString(16).padStart(2, '0')
    const found = '0x' + seq.toString(16).padStart(2, '0')
    throw Error(`expected filter tag ${expected}, got ${found}`)
  }

  const filters = []
  const currentFilterLength = reader.length
  while (reader.offset < currentFilterLength) {
    const tag = reader.peek()
    const tagBuffer = reader.readRawBuffer(tag)
    const filter = FILTERS[tag].parse(tagBuffer)
    filters.push(filter)
  }

  if (constructor === FILTERS[search.FILTER_NOT]) {
    return new constructor({ filter: filters[0] })
  }

  return new constructor({ filters })
}

},{"../and":44,"../approximate":45,"../equality":46,"../extensible":47,"../greater-than-equals":48,"../less-than-equals":49,"../not":50,"../or":51,"../presence":52,"../substring":53,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],55:[function(require,module,exports){
'use strict'

const testValues = require('./utils/test-values')
const getAttributeValue = require('./utils/get-attribute-value')

const FilterString = require('./filter-string')
const AndFilter = require('./filters/and')
const ApproximateFilter = require('./filters/approximate')
const EqualityFilter = require('./filters/equality')
const ExtensibleFilter = require('./filters/extensible')
const GreaterThanEqualsFilter = require('./filters/greater-than-equals')
const LessThanEqualsFilter = require('./filters/less-than-equals')
const NotFilter = require('./filters/not')
const OrFilter = require('./filters/or')
const PresenceFilter = require('./filters/presence')
const SubstringFilter = require('./filters/substring')

const deprecations = require('./deprecations')
const parseString = require('./string-parsing/parse-string')

module.exports = {
  parseBer: require('./ber-parsing'),

  /**
   * @deprecated 2022-06-26 Use `parseString` instead.
   */
  parse: (string) => {
    deprecations.emit('LDAP_FILTER_DEP_001')
    return parseString(string)
  },
  parseString,

  // Helper utilties for writing custom matchers
  testValues,
  getAttrValue: getAttributeValue,
  getAttributeValue,

  // Filter definitions
  FilterString,
  AndFilter,
  ApproximateFilter,
  EqualityFilter,
  ExtensibleFilter,
  GreaterThanEqualsFilter,
  LessThanEqualsFilter,
  NotFilter,
  OrFilter,
  PresenceFilter,
  SubstringFilter
}

},{"./ber-parsing":41,"./deprecations":42,"./filter-string":43,"./filters/and":44,"./filters/approximate":45,"./filters/equality":46,"./filters/extensible":47,"./filters/greater-than-equals":48,"./filters/less-than-equals":49,"./filters/not":50,"./filters/or":51,"./filters/presence":52,"./filters/substring":53,"./string-parsing/parse-string":60,"./utils/get-attribute-value":62,"./utils/test-values":63}],56:[function(require,module,exports){
'use strict'

const escapeFilterValue = require('../utils/escape-filter-value')

/**
 * In an extensible filter, the righthand size of the filter can have
 * substrings delimeted by `*` characters, e.g. `foo=*foo*bar*baz*`. This
 * function is used to encode those substrings.
 *
 * @param {string} str In `*foo*bar*baz*` it would be `foo*bar*baz`.
 *
 * @returns {object} An object with extensible filter properties.
 *
 * @throws When the separator is missing from the input string.
 */
module.exports = function escapeSubstring (str) {
  const fields = str.split('*')
  const out = {
    initial: '',
    final: '',
    any: []
  }

  if (fields.length <= 1) {
    throw Error('extensible filter delimiter missing')
  }

  out.initial = escapeFilterValue(fields.shift())
  out.final = escapeFilterValue(fields.pop())
  Array.prototype.push.apply(out.any, fields.map(escapeFilterValue))

  return out
}

},{"../utils/escape-filter-value":61}],57:[function(require,module,exports){
'use strict'

const ApproximateFilter = require('../filters/approximate')
const EqualityFilter = require('../filters/equality')
const GreaterThanEqualsFilter = require('../filters/greater-than-equals')
const LessThanEqualsFilter = require('../filters/less-than-equals')
const PresenceFilter = require('../filters/presence')
const SubstringFilter = require('../filters/substring')
const escapeSubstring = require('./escape-substring')
const escapeFilterValue = require('../utils/escape-filter-value')
const parseExtensibleFilterString = require('./parse-extensible-filter-string')

const attrRegex = /^[-_a-zA-Z0-9]+/

/**
 * Given the expression part of a filter string, e.g. `cn=foo` in `(cn=foo)`,
 * parse it into the corresponding filter instance(s).
 *
 * @param {string} inputString The filter expression to parse.
 *
 * @returns {FilterString}
 *
 * @throws When some parsing error occurs.
 */
module.exports = function parseExpr (inputString) {
  let attribute
  let match
  let remainder

  if (inputString[0] === ':' || inputString.indexOf(':=') > 0) {
    // An extensible filter can have no attribute name.
    return parseExtensibleFilterString(inputString)
  } else if ((match = inputString.match(attrRegex)) !== null) {
    attribute = match[0]
    remainder = inputString.substring(attribute.length)
  } else {
    throw new Error('invalid attribute name')
  }

  if (remainder === '=*') {
    return new PresenceFilter({ attribute })
  } else if (remainder[0] === '=') {
    remainder = remainder.substring(1)
    if (remainder.indexOf('*') !== -1) {
      const val = escapeSubstring(remainder)
      return new SubstringFilter({
        attribute,
        subInitial: val.initial,
        subAny: val.any,
        subFinal: val.final
      })
    } else {
      return new EqualityFilter({
        attribute,
        value: escapeFilterValue(remainder)
      })
    }
  } else if (remainder[0] === '>' && remainder[1] === '=') {
    return new GreaterThanEqualsFilter({
      attribute,
      value: escapeFilterValue(remainder.substring(2))
    })
  } else if (remainder[0] === '<' && remainder[1] === '=') {
    return new LessThanEqualsFilter({
      attribute,
      value: escapeFilterValue(remainder.substring(2))
    })
  } else if (remainder[0] === '~' && remainder[1] === '=') {
    return new ApproximateFilter({
      attribute,
      value: escapeFilterValue(remainder.substring(2))
    })
  }

  throw new Error('invalid expression')
}

},{"../filters/approximate":45,"../filters/equality":46,"../filters/greater-than-equals":48,"../filters/less-than-equals":49,"../filters/presence":52,"../filters/substring":53,"../utils/escape-filter-value":61,"./escape-substring":56,"./parse-extensible-filter-string":58}],58:[function(require,module,exports){
'use strict'

const ExtensibleFilter = require('../filters/extensible')
const escapeFilterValue = require('../utils/escape-filter-value')

/**
 * Parses the string representation of an extensible filter into an
 * {@link ExtensibleFilter} instance. Note, the opening and closing
 * parentheticals should not be present in the string.
 *
 * @param {string} filterString Extensible filter string without parentheticals.
 *
 * @returns {ExtensibleFilter}
 *
 * @throws When the filter string is missing a `:=`.
 */
module.exports = function parseExtensibleFilterString (filterString) {
  const fields = filterString.split(':')
  const attribute = escapeFilterValue(fields.shift())

  const params = {
    attribute,
    dnAttributes: false,
    rule: undefined,
    value: undefined
  }

  if (fields[0].toLowerCase() === 'dn') {
    params.dnAttributes = true
    fields.shift()
  }
  if (fields.length !== 0 && fields[0][0] !== '=') {
    params.rule = fields.shift()
  }
  if (fields.length === 0 || fields[0][0] !== '=') {
    // With matchType, dnAttribute, and rule consumed, the := must be next.
    throw new Error('missing := in extensible filter string')
  }

  // Trim the leading = (from the :=)  and reinsert any extra ':' charachters
  // which may have been present in the value field.
  filterString = fields.join(':').substr(1)
  params.value = escapeFilterValue(filterString)

  return new ExtensibleFilter(params)
}

},{"../filters/extensible":47,"../utils/escape-filter-value":61}],59:[function(require,module,exports){
'use strict'

const AndFilter = require('../filters/and')
const OrFilter = require('../filters/or')
const NotFilter = require('../filters/not')
const parseExpression = require('./parse-expression')

const unbalancedError = Error('unbalanced parentheses')

/**
 * @type {object} ParseFilterResult
 * @property {number} end The ending position of the most recent iteration
 * of the function.
 * @property {FilterString} filter The parsed filter instance.
 */

/**
 * Recursively parse an LDAP filter string into a set of {@link FilterString}
 * instances. For example, the filter `(&(cn=foo)(sn=bar))` will return an
 * {@link AndFilter} instance that has two {@link EqualityFilter} clauses.
 *
 * @param {string} inputString The filter string, including starting and ending
 * parentheticals, to parse.
 * @param {number} [start=0] The starting position in the string to start the
 * parsing from. Used during recursion when a new sub-expression is encounterd.
 *
 * @returns {ParseFilterResult}
 *
 * @throws When any error occurs during parsing.
 */
module.exports = function parseFilter (inputString, start = 0) {
  let cur = start
  const len = inputString.length
  let res
  let end
  let output
  const children = []

  if (inputString[cur++] !== '(') {
    throw Error('missing opening parentheses')
  }

  if (inputString[cur] === '&') {
    cur++
    if (inputString[cur] === ')') {
      output = new AndFilter({})
    } else {
      do {
        res = parseFilter(inputString, cur)
        children.push(res.filter)
        cur = res.end + 1
      } while (cur < len && inputString[cur] !== ')')

      output = new AndFilter({ filters: children })
    }
  } else if (inputString[cur] === '|') {
    cur++
    do {
      res = parseFilter(inputString, cur)
      children.push(res.filter)
      cur = res.end + 1
    } while (cur < len && inputString[cur] !== ')')

    output = new OrFilter({ filters: children })
  } else if (inputString[cur] === '!') {
    res = parseFilter(inputString, cur + 1)
    output = new NotFilter({ filter: res.filter })
    cur = res.end + 1
    if (inputString[cur] !== ')') {
      throw unbalancedError
    }
  } else {
    end = inputString.indexOf(')', cur)
    if (end === -1) {
      throw unbalancedError
    }

    output = parseExpression(inputString.substring(cur, end))
    cur = end
  }

  return {
    end: cur,
    filter: output
  }
}

},{"../filters/and":44,"../filters/not":50,"../filters/or":51,"./parse-expression":57}],60:[function(require,module,exports){
'use strict'

const parseFilter = require('./parse-filter')

/**
 * Parse and LDAP filter string into a {@link FilterString} instance.
 *
 * @param {string} inputString The LDAP filter string to parse. Can omit the
 * leading and terminating parentheses.
 *
 * @returns {FilterString}
 *
 * @throws For any error while parsing.
 */
module.exports = function parseString (inputString) {
  if (typeof inputString !== 'string') {
    throw Error('input must be a string')
  }
  if (inputString.length < 1) {
    throw Error('input string cannot be empty')
  }

  let normalizedString = inputString
  if (normalizedString.charAt(0) !== '(') {
    // Wrap the filter in parantheticals since it is not already wrapped.
    normalizedString = `(${normalizedString})`
  }

  const parsed = parseFilter(normalizedString)
  if (parsed.end < inputString.length - 1) {
    throw Error('unbalanced parentheses')
  }

  return parsed.filter
}

},{"./parse-filter":59}],61:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

module.exports = escapeFilterValue

/**
 * Escapes LDAP filter attribute values. For example,
 * in the filter `(cn=föo)`, this function would be used
 * to encode `föo` to `f\c3\b6o`. Already encoded values
 * will be left intact.
 *
 * @param {string|Buffer} toEscape
 *
 * @returns {string}
 *
 * @see https://datatracker.ietf.org/doc/html/rfc4515
 */
function escapeFilterValue (toEscape) {
  if (typeof toEscape === 'string') {
    return escapeBuffer(Buffer.from(toEscape))
  }

  if (Buffer.isBuffer(toEscape)) {
    return escapeBuffer(toEscape)
  }

  throw Error('toEscape must be a string or a Buffer')
}

function escapeBuffer (buf) {
  let result = ''
  for (let i = 0; i < buf.length; i += 1) {
    if (buf[i] >= 0xc0 && buf[i] <= 0xdf) {
      // Represents the first byte in a 2-byte UTF-8 character.
      result += '\\' + buf[i].toString(16) + '\\' + buf[i + 1].toString(16)
      i += 1
      continue
    }

    if (buf[i] >= 0xe0 && buf[i] <= 0xef) {
      // Represents the first byte in a 3-byte UTF-8 character.
      result += [
        '\\', buf[i].toString(16),
        '\\', buf[i + 1].toString(16),
        '\\', buf[i + 2].toString(16)
      ].join('')
      i += 2
      continue
    }

    if (buf[i] <= 31) {
      // It's an ASCII control character so we will straight
      // encode it (excluding the "space" character).
      result += '\\' + buf[i].toString(16).padStart(2, '0')
      continue
    }

    const char = String.fromCharCode(buf[i])
    switch (char) {
      case '*': {
        result += '\\2a'
        break
      }

      case '(': {
        result += '\\28'
        break
      }

      case ')': {
        result += '\\29'
        break
      }

      case '\\': {
        // result += '\\5c'
        // It looks like we have encountered an already escaped sequence
        // of characters. So we will attempt to read that sequence as-is.
        const escapedChars = readEscapedCharacters(buf, i)
        i += escapedChars.length
        result += escapedChars.join('')
        break
      }

      default: {
        result += char
        break
      }
    }
  }
  return result
}

/**
 * In a buffer that represents a string with escaped character code
 * sequences, e.g. `'foo\\2a'`, read the escaped character code sequence
 * and return it as a string. If an invalid escape sequence is encountered,
 * it will be assumed that the sequence needs to be escaped and the returned
 * string will include the escaped sequence.
 *
 * @param {Buffer} buf
 * @param {number} start Starting offset of the escaped character sequence
 * in the buffer
 *
 * @returns {string}
 */
function readEscapedCharacters (buf, start) {
  const chars = []

  for (let i = start; ;) {
    if (buf[i] === undefined) {
      // The sequence was a terminating `\`. So we actually want
      // to escape it. Therefore, replace the read `\` with the
      // ecape sequence.
      chars[-1] = '\\5c'
      break
    }

    if (buf[i] === 0x5c) { // read `\` character
      chars.push('\\')
      i += 1
      continue
    }

    const strHexCode = String.fromCharCode(buf[i]) + String.fromCharCode(buf[i + 1])
    const hexCode = parseInt(strHexCode, 16)
    if (Number.isNaN(hexCode)) {
      // The next two bytes do not comprise a hex code. Therefore,
      // we really want to escape the previous `\` character and append
      // the next two characters.
      chars.push('5c' + strHexCode)
      break
    }

    if (hexCode >= 0xc0 && hexCode <= 0xdf) {
      // Handle 2-byte character code.
      chars.push(hexCode.toString(16).padEnd(2, '0'))
      for (let x = i + 2; x < i + 4; x += 1) {
        chars.push(String.fromCharCode(buf[x]))
      }
      break
    }

    if (hexCode >= 0xe0 && hexCode <= 0xef) {
      // Handle 3-byte character code.
      chars.push(hexCode.toString(16).padStart(2, '0'))
      for (let x = i + 2; x < i + 8; x += 1) {
        chars.push(String.fromCharCode(buf[x]))
      }
      break
    }

    // Single byte escaped code.
    chars.push(hexCode.toString(16).padStart(2, '0'))
    break
  }

  return chars
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":110}],62:[function(require,module,exports){
'use strict'

module.exports = getAttributeValue

/**
 * Fetch value for named object attribute.
 *
 * @param {object} input
 * @param {object} input.sourceObject object to fetch value from
 * @param {string} input.attributeName name of attribute to fetch
 * @param {boolean} [input.strictCase=false] attribute name is case-sensitive
 */
function getAttributeValue ({ sourceObject, attributeName, strictCase = false }) {
  if (Object.prototype.toString.call(sourceObject) === '[object LdapAttribute]') {
    sourceObject = {
      [sourceObject.type]: sourceObject.values
    }
  }

  if (Object.prototype.toString.call(sourceObject) !== '[object Object]') {
    throw Error('sourceObject must be an object')
  }
  if (typeof attributeName !== 'string') {
    throw Error('attributeName must be a string')
  }

  // Check for exact case match first
  if (Object.prototype.hasOwnProperty.call(sourceObject, attributeName)) {
    return sourceObject[attributeName]
  } else if (strictCase === true) {
    return undefined
  }

  // Perform case-insensitive enumeration after that
  const lowerName = attributeName.toLowerCase()
  const foundName = Object.getOwnPropertyNames(sourceObject).find((name) =>
    name.toLowerCase() === lowerName
  )
  return foundName && sourceObject[foundName]
}

},{}],63:[function(require,module,exports){
'use strict'

module.exports = testValues

/**
 * Tests if the given input matches some condition.
 *
 * @callback ruleCallback
 * @param {*} input Value to test.
 * @returns {boolean}
 */

/**
 * Check value or array with test function.
 *
 * @param {object} input
 * @param {ruleCallback} input.rule Synchronous function that tests if an input
 * matches some condition. Must return `true` or `false`.
 * @param {*|*[]} input.value An item, or list of items, to verify with the
 * rule function.
 * @param {boolean} [input.requireAllMatch=false] require all array values to match.
 *
 * @returns {boolean}
 */
function testValues ({ rule, value, requireAllMatch = false }) {
  if (Array.isArray(value) === false) {
    return rule(value)
  }

  if (requireAllMatch === true) {
    // Do all entries match rule?
    for (let i = 0; i < value.length; i++) {
      if (rule(value[i]) === false) {
        return false
      }
    }
    return true
  }

  // Do any entries match rule?
  for (let i = 0; i < value.length; i++) {
    if (rule(value[i])) {
      return true
    }
  }
  return false
}

},{}],64:[function(require,module,exports){
'use strict'

module.exports = {
  // Base objects.
  LdapMessage: require('./lib/ldap-message'),
  LdapResult: require('./lib/ldap-result'),

  // Request objects.
  AbandonRequest: require('./lib/messages/abandon-request'),
  AddRequest: require('./lib/messages/add-request'),
  BindRequest: require('./lib/messages/bind-request'),
  CompareRequest: require('./lib/messages/compare-request'),
  DeleteRequest: require('./lib/messages/delete-request'),
  ExtensionRequest: require('./lib/messages/extension-request'),
  ModifyRequest: require('./lib/messages/modify-request'),
  ModifyDnRequest: require('./lib/messages/modifydn-request'),
  SearchRequest: require('./lib/messages/search-request'),
  UnbindRequest: require('./lib/messages/unbind-request'),

  // Response objects.
  AbandonResponse: require('./lib/messages/abandon-response'),
  AddResponse: require('./lib/messages/add-response'),
  BindResponse: require('./lib/messages/bind-response'),
  CompareResponse: require('./lib/messages/compare-response'),
  DeleteResponse: require('./lib/messages/delete-response'),
  ExtensionResponse: require('./lib/messages/extension-response'),
  ModifyResponse: require('./lib/messages/modify-response'),
  ModifyDnResponse: require('./lib/messages/modifydn-response'),

  // Search request messages.
  SearchResultEntry: require('./lib/messages/search-result-entry'),
  SearchResultReference: require('./lib/messages/search-result-reference'),
  SearchResultDone: require('./lib/messages/search-result-done'),

  // Specific extension response implementations.
  PasswordModifyResponse: require('./lib/messages/extension-responses/password-modify'),
  WhoAmIResponse: require('./lib/messages/extension-responses/who-am-i'),

  // Miscellaneous objects.
  IntermediateResponse: require('./lib/messages/intermediate-response')
}

},{"./lib/ldap-message":66,"./lib/ldap-result":67,"./lib/messages/abandon-request":68,"./lib/messages/abandon-response":69,"./lib/messages/add-request":70,"./lib/messages/add-response":71,"./lib/messages/bind-request":72,"./lib/messages/bind-response":73,"./lib/messages/compare-request":74,"./lib/messages/compare-response":75,"./lib/messages/delete-request":76,"./lib/messages/delete-response":77,"./lib/messages/extension-request":78,"./lib/messages/extension-response":79,"./lib/messages/extension-responses/password-modify":80,"./lib/messages/extension-responses/who-am-i":81,"./lib/messages/intermediate-response":83,"./lib/messages/modify-request":84,"./lib/messages/modify-response":85,"./lib/messages/modifydn-request":86,"./lib/messages/modifydn-response":87,"./lib/messages/search-request":88,"./lib/messages/search-result-done":89,"./lib/messages/search-result-entry":90,"./lib/messages/search-result-reference":91,"./lib/messages/unbind-request":92}],65:[function(require,module,exports){
'use strict'

const warning = require('process-warning')()
const clazz = 'LdapjsMessageWarning'

warning.create(clazz, 'LDAP_MESSAGE_DEP_001', 'messageID is deprecated. Use messageId instead.')

warning.create(clazz, 'LDAP_MESSAGE_DEP_002', 'The .json property is deprecated. Use .pojo instead.')

warning.create(clazz, 'LDAP_MESSAGE_DEP_003', 'abandonID is deprecated. Use abandonId instead.')

warning.create(clazz, 'LDAP_MESSAGE_DEP_004', 'errorMessage is deprecated. Use diagnosticMessage instead.')

module.exports = warning

},{"process-warning":161}],66:[function(require,module,exports){
'use strict'

const { BerReader, BerWriter } = require('@ldapjs/asn1')
const warning = require('./deprecations')

const { operations } = require('@ldapjs/protocol')
const { getControl } = require('@ldapjs/controls')

const messageClasses = {
  AbandonRequest: require('./messages/abandon-request'),
  AddRequest: require('./messages/add-request'),
  BindRequest: require('./messages/bind-request'),
  CompareRequest: require('./messages/compare-request'),
  DeleteRequest: require('./messages/delete-request'),
  ExtensionRequest: require('./messages/extension-request'),
  ModifyRequest: require('./messages/modify-request'),
  ModifyDnRequest: require('./messages/modifydn-request'),
  SearchRequest: require('./messages/search-request'),
  UnbindRequest: require('./messages/unbind-request'),

  AbandonResponse: require('./messages/abandon-response'),
  AddResponse: require('./messages/add-response'),
  BindResponse: require('./messages/bind-response'),
  CompareResponse: require('./messages/compare-response'),
  DeleteResponse: require('./messages/delete-response'),
  ExtensionResponse: require('./messages/extension-response'),
  ModifyResponse: require('./messages/modify-response'),
  ModifyDnResponse: require('./messages/modifydn-response'),

  // Search result messages.
  SearchResultEntry: require('./messages/search-result-entry'),
  SearchResultReference: require('./messages/search-result-reference'),
  SearchResultDone: require('./messages/search-result-done'),

  // Miscellaneous messages.
  IntermediateResponse: require('./messages/intermediate-response')
}

/**
 * Utility function that inspects a BER object and parses it into an instance
 * of a specific LDAP message.
 *
 * @param {import('@ldapjs/asn1').BerReader} ber An object that represents a
 * full LDAP Message sequence as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.1.
 *
 * @returns {LdapMessage} Some specific instance of the base LDAP Message
 * type.
 *
 * @throws When the input data is malformed.
 */
function parseToMessage (ber) {
  const inputType = Object.prototype.toString.apply(ber)
  if (inputType !== '[object BerReader]') {
    throw TypeError(`Expected BerReader but got ${inputType}.`)
  }

  ber.readSequence()

  const messageId = ber.readInt()
  const messageType = identifyType(ber)
  const MessageClass = messageClasses[messageType]
  const pojoMessage = MessageClass.parseToPojo(ber)
  const message = new MessageClass({
    messageId,
    ...pojoMessage
  })

  // Look for controls
  if (ber.peek() === 0xa0) {
    ber.readSequence()
    const end = ber.offset + ber.length
    while (ber.offset < end) {
      const c = getControl(ber)
      /* istanbul ignore else */
      if (c) {
        message.addControl(c)
      }
    }
  }

  return message
}

/**
 * Determines the type of LDAP message the BER represents, e.g. a "Bind Request"
 * message.
 *
 * @param {BerReader} ber
 *
 * @returns {string}
 */
function identifyType (ber) {
  let result
  switch (ber.peek()) {
    case operations.LDAP_REQ_ABANDON: {
      result = 'AbandonRequest'
      break
    }

    case 0x00: {
      result = 'AbandonResponse'
      break
    }

    case operations.LDAP_REQ_ADD: {
      result = 'AddRequest'
      break
    }

    case operations.LDAP_RES_ADD: {
      result = 'AddResponse'
      break
    }

    case operations.LDAP_REQ_BIND: {
      result = 'BindRequest'
      break
    }

    case operations.LDAP_RES_BIND: {
      result = 'BindResponse'
      break
    }

    case operations.LDAP_REQ_COMPARE: {
      result = 'CompareRequest'
      break
    }

    case operations.LDAP_RES_COMPARE: {
      result = 'CompareResponse'
      break
    }

    case operations.LDAP_REQ_DELETE: {
      result = 'DeleteRequest'
      break
    }

    case operations.LDAP_RES_DELETE: {
      result = 'DeleteResponse'
      break
    }

    case operations.LDAP_REQ_EXTENSION: {
      result = 'ExtensionRequest'
      break
    }

    case operations.LDAP_RES_EXTENSION: {
      result = 'ExtensionResponse'
      break
    }

    case operations.LDAP_REQ_MODIFY: {
      result = 'ModifyRequest'
      break
    }

    case operations.LDAP_RES_MODIFY: {
      result = 'ModifyResponse'
      break
    }

    case operations.LDAP_REQ_MODRDN: {
      result = 'ModifyDnRequest'
      break
    }

    case operations.LDAP_RES_MODRDN: {
      result = 'ModifyDnResponse'
      break
    }

    case operations.LDAP_REQ_SEARCH: {
      result = 'SearchRequest'
      break
    }

    case operations.LDAP_RES_SEARCH_ENTRY: {
      result = 'SearchResultEntry'
      break
    }

    case operations.LDAP_RES_SEARCH_REF: {
      result = 'SearchResultReference'
      break
    }

    case operations.LDAP_RES_SEARCH_DONE: {
      result = 'SearchResultDone'
      break
    }

    case operations.LDAP_REQ_UNBIND: {
      result = 'UnbindRequest'
      break
    }

    case operations.LDAP_RES_INTERMEDIATE: {
      result = 'IntermediateResponse'
      break
    }
  }

  return result
}

/**
 * Implements a base LDAP message as defined in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.1.
 */
class LdapMessage {
  #messageId = 0;
  #protocolOp;
  #controls = [];

  /**
   * @typedef {object} LdapMessageOptions
   * @property {number} [messageId=1] An identifier for the message.
   * @property {number} [protocolOp] The tag for the message operation.
   * @property {import('@ldapjs/controls').Control[]} [controls] A set of LDAP
   * controls to send with the message. See the `@ldapjs/controls` package.
   */

  /**
   * @param {LdapMessageOptions} [options]
   */
  constructor (options = {}) {
    this.#messageId = parseInt(options.messageId ?? options.messageID ?? '1', 10)
    if (options.messageID !== undefined) {
      warning.emit('LDAP_MESSAGE_DEP_001')
    }

    if (typeof options.protocolOp === 'number') {
      this.#protocolOp = options.protocolOp
    }

    this.controls = options.controls ?? []
  }

  get [Symbol.toStringTag] () {
    return 'LdapMessage'
  }

  /**
   * A copy of the list of controls that will be sent with the request.
   *
   * @returns {import('@ldapjs/controls').Control[]}
   */
  get controls () {
    return this.#controls.slice(0)
  }

  /**
   * Define the list of controls that will be sent with the request. Any
   * existing controls will be discarded.
   *
   * @param {import('@ldapjs/controls').Control[]} values
   *
   * @throws When a control value is invalid.
   */
  set controls (values) {
    if (Array.isArray(values) !== true) {
      throw Error('controls must be an array')
    }
    const newControls = []
    for (const val of values) {
      if (Object.prototype.toString.call(val) !== '[object LdapControl]') {
        throw Error('control must be an instance of LdapControl')
      }
      newControls.push(val)
    }
    this.#controls = newControls
  }

  /**
   * The message identifier.
   *
   * @type {number}
   */
  get id () {
    return this.#messageId
  }

  /**
   * Define the message identifier for the request.
   *
   * @param {number} value
   */
  set id (value) {
    if (Number.isInteger(value) === false) {
      throw Error('id must be an integer')
    }
    this.#messageId = value
  }

  /**
   * Alias for {@link id}.
   *
   * @returns {number}
   */
  get messageId () {
    return this.id
  }

  /**
   * Alias for {@link id}.
   *
   * @param {number} value
   */
  set messageId (value) {
    this.id = value
  }

  /**
   * Alias for {@link id}.
   *
   * @returns {number}
   *
   * @deprecated
   */
  get messageID () {
    warning.emit('LDAP_MESSAGE_DEP_001')
    return this.id
  }

  /**
   * Alias for {@link id}.
   *
   * @param {number} value
   *
   * @deprecated
   */
  set messageID (value) {
    warning.emit('LDAP_MESSAGE_DEP_001')
    this.id = value
  }

  /**
   * Message type specific. Each message type must implement a `_dn` property
   * that provides this value.
   *
   * @type {string}
   */
  get dn () {
    return this._dn
  }

  /**
   * The LDAP protocol operation code for the message.
   *
   * @type {number}
   */
  get protocolOp () {
    return this.#protocolOp
  }

  /**
   * The name of the message class.
   *
   * @type {string}
   */
  get type () {
    return 'LdapMessage'
  }

  /**
   * Use {@link pojo} instead.
   *
   * @deprecated
   */
  get json () {
    warning.emit('LDAP_MESSAGE_DEP_002')
    return this.pojo
  }

  /**
   * A serialized representation of the message as a plain JavaScript object.
   * Specific message types must implement the `_pojo(obj)` method. The passed
   * in `obj` must be extended with the specific message's unique properties
   * and returned as the result.
   *
   * @returns {object}
   */
  get pojo () {
    let result = {
      messageId: this.id,
      protocolOp: this.#protocolOp,
      type: this.type
    }

    if (typeof this._pojo === 'function') {
      result = this._pojo(result)
    }

    result.controls = this.#controls.map(c => c.pojo)

    return result
  }

  addControl (control) {
    this.#controls.push(control)
  }

  /**
   * Converts an {@link LdapMessage} object into a set of BER bytes that can
   * be sent across the wire. Specific message implementations must implement
   * the `_toBer(ber)` method. This method will write its unique sequence(s)
   * to the passed in `ber` object.
   *
   * @returns {import('@ldapjs/asn1').BerReader}
   */
  toBer () {
    if (typeof this._toBer !== 'function') {
      throw Error(`${this.type} does not implement _toBer`)
    }

    const writer = new BerWriter()
    writer.startSequence()
    writer.writeInt(this.id)

    this._toBer(writer)

    if (this.#controls.length > 0) {
      writer.startSequence(0xa0)
      for (const control of this.#controls) {
        control.toBer(writer)
      }
      writer.endSequence()
    }

    writer.endSequence()
    return new BerReader(writer.buffer)
  }

  /**
   * Serializes the message into a JSON representation.
   *
   * @returns {string}
   */
  toString () {
    return JSON.stringify(this.pojo)
  }

  /**
   * Parses a BER into a message object. The offset of the BER _must_ point
   * to the start of an LDAP Message sequence. That is, the first few bytes
   * must indicate:
   *
   * 1. a sequence tag and how many bytes are in that sequence
   * 2. an integer representing the message identifier
   * 3. a protocol operation, e.g. BindRequest, and the number of bytes in
   * that operation
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {LdapMessage}
   */
  static parse (ber) {
    return parseToMessage(ber)
  }

  /**
   * When invoked on specific message types, e.g. {@link BindRequest}, this
   * method will parse a BER into a plain JavaScript object that is usable as
   * an options object for constructing that specific message object.
   *
   * @param {import('@ldapjs/asn1').BerReader} ber A BER to parse. The reader
   * offset must point to the start of a valid sequence, i.e. the "tag" byte
   * in the TLV tuple, that represents the message to be parsed. For example,
   * in a {@link BindRequest} the starting sequence and message identifier must
   * already be read such that the offset is at the protocol operation sequence
   * byte.
   */
  static parseToPojo (ber) {
    throw Error('Use LdapMessage.parse, or a specific message type\'s parseToPojo, instead.')
  }
}

module.exports = LdapMessage

},{"./deprecations":65,"./messages/abandon-request":68,"./messages/abandon-response":69,"./messages/add-request":70,"./messages/add-response":71,"./messages/bind-request":72,"./messages/bind-response":73,"./messages/compare-request":74,"./messages/compare-response":75,"./messages/delete-request":76,"./messages/delete-response":77,"./messages/extension-request":78,"./messages/extension-response":79,"./messages/intermediate-response":83,"./messages/modify-request":84,"./messages/modify-response":85,"./messages/modifydn-request":86,"./messages/modifydn-response":87,"./messages/search-request":88,"./messages/search-result-done":89,"./messages/search-result-entry":90,"./messages/search-result-reference":91,"./messages/unbind-request":92,"@ldapjs/asn1":2,"@ldapjs/controls":10,"@ldapjs/protocol":93}],67:[function(require,module,exports){
'use strict'

const LdapMessage = require('./ldap-message')
const { resultCodes, operations } = require('@ldapjs/protocol')
const warning = require('./deprecations')

/**
 * Implements the base LDAP response message as defined in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.9.
 */
class LdapResult extends LdapMessage {
  #connection = null;
  #diagnosticMessage;
  #matchedDN;
  #referrals = [];
  #status;

  /**
   * @typedef {LdapMessageOptions} LdapResultOptions
   * @property {number} [status=0] An LDAP status code.
   * @param {string} [matchedDN=''] The DN that matched the request.
   * @param {string[]} [referrals=[]] A set of servers to query for references.
   * @param {string} [diagnosticMessage] A message indicating why a request
   * failed.
   */

  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    super(options)

    this.#status = options.status ?? resultCodes.SUCCESS
    this.#matchedDN = options.matchedDN || ''
    this.#referrals = options.referrals || []
    this.#diagnosticMessage = options.diagnosticMessage || options.errorMessage || ''
    if (options.errorMessage) {
      warning.emit('LDAP_MESSAGE_DEP_004')
    }
  }

  /**
   * The failure message as returned by the server if one is present.
   *
   * @returns {string}
   */
  get diagnosticMessage () {
    return this.#diagnosticMessage
  }

  /**
   * Add a diagnostic message to the instance.
   *
   * @param {string} message
   */
  set diagnosticMessage (message) {
    this.#diagnosticMessage = message
  }

  /**
   * The DN that a request matched.
   *
   * @returns {string}
   */
  get matchedDN () {
    return this.#matchedDN
  }

  /**
   * Define which DN a request matched.
   *
   * @param {string} dn
   */
  set matchedDN (dn) {
    this.#matchedDN = dn
  }

  /**
   * A serialized representation of the message as a plain JavaScript object.
   * Specific message types must implement the `_pojo(obj)` method. The passed
   * in `obj` must be extended with the specific message's unique properties
   * and returned as the result.
   *
   * @returns {object}
   */
  get pojo () {
    let result = {
      status: this.status,
      matchedDN: this.matchedDN,
      diagnosticMessage: this.diagnosticMessage,
      referrals: this.referrals
    }

    if (typeof this._pojo === 'function') {
      result = this._pojo(result)
    }

    return result
  }

  /**
   * The list of servers that should be consulted to get an answer
   * to the query.
   *
   * @returns {string[]}
   */
  get referrals () {
    return this.#referrals.slice(0)
  }

  /**
   * The LDAP response code for the request.
   *
   * @returns {number}
   */
  get status () {
    return this.#status
  }

  /**
   * Set the response code for the request.
   *
   * @param {number} s
   */
  set status (s) {
    this.#status = s
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'LdapResult'
  }

  /**
   * Add a new server to the list of servers that should be
   * consulted for an answer to the query.
   *
   * @param {string} referral
   */
  addReferral (referral) {
    this.#referrals.push(referral)
  }

  /**
   * Internal use only. Subclasses may implement a `_writeResponse`
   * method to add to the sequence after any referrals.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   *
   * @private
   */
  _toBer (ber) {
    ber.startSequence(this.protocolOp)
    ber.writeEnumeration(this.status)
    ber.writeString(this.matchedDN)
    ber.writeString(this.diagnosticMessage)

    if (this.referrals.length > 0) {
      ber.startSequence(operations.LDAP_RES_REFERRAL)
      ber.writeStringArray(this.referrals)
      ber.endSequence()
    }

    if (typeof this._writeResponse === 'function') {
      this._writeResponse(ber)
    }

    ber.endSequence()
  }

  /**
   * When invoked on specific message types, e.g. {@link AddResponse}, this
   * method will parse a BER into a plain JavaScript object that is usable as
   * an options object for constructing that specific message object.
   *
   * @param {import('@ldapjs/asn1').BerReader} ber A BER to parse. The reader
   * offset must point to the start of a valid sequence, i.e. the "tag" byte
   * in the TLV tuple, that represents the message to be parsed. For example,
   * in a {@link AddResponse} the starting sequence and message identifier must
   * already be read such that the offset is at the protocol operation sequence
   * byte.
   */
  static parseToPojo (ber) {
    throw Error('Use LdapMessage.parse, or a specific message type\'s parseToPojo, instead.')
  }

  /**
   * Internal use only.
   *
   * Response messages are a little more generic to parse than request messages.
   * However, they still need to recognize the correct protocol operation. So
   * the public {@link parseToPojo} for each response object should invoke this
   * private static method to parse the BER and indicate the correct protocol
   * operation to recognize.
   *
   * @param {object} input
   * @param {number} input.opCode The expected protocol operation to look for.
   * @param {import('@ldapjs/asn1').BerReader} berReader The BER to process. It
   * must start at an offset representing a protocol operation tag.
   * @param {object} [input.pojo] A plain JavaScript object to populate with
   * the parsed keys and values.
   *
   * @returns {object}
   *
   * @private
   */
  static _parseToPojo ({ opCode, berReader, pojo = {} }) {
    const protocolOp = berReader.readSequence()
    if (protocolOp !== opCode) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const status = berReader.readEnumeration()
    const matchedDN = berReader.readString()
    const diagnosticMessage = berReader.readString()
    const referrals = []

    if (berReader.peek() === operations.LDAP_RES_REFERRAL) {
      // Advance the offset to the start of the value and
      // put the sequence length into the `reader.length` field.
      berReader.readSequence(operations.LDAP_RES_REFERRAL)
      const end = berReader.length
      while (berReader.offset < end) {
        referrals.push(berReader.readString())
      }
    }

    pojo.status = status
    pojo.matchedDN = matchedDN
    pojo.diagnosticMessage = diagnosticMessage
    pojo.referrals = referrals

    return pojo
  }
}

module.exports = LdapResult

},{"./deprecations":65,"./ldap-message":66,"@ldapjs/protocol":93}],68:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const Protocol = require('@ldapjs/protocol')
const warning = require('../deprecations')

/**
 * Implements the abandon request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.11
 */
class AbandonRequest extends LdapMessage {
  #abandonId;

  /**
   * @typedef {LdapMessageOptions} AbandonRequestOptions
   * @property {number} [abandonId=0] The message id of the request to abandon.
   */

  /**
   * @param {AbandonRequestOptions} [options]
   */
  constructor (options = {}) {
    options.protocolOp = Protocol.operations.LDAP_REQ_ABANDON
    super(options)

    const abandonId = options.abandonId || options.abandonID || 0
    if (options.abandonID) {
      warning.emit('LDAP_MESSAGE_DEP_003')
    }
    this.#abandonId = abandonId
  }

  /**
   * The identifier for the request that the instance will request be abandoned.
   *
   * @type {number}
   */
  get abandonId () {
    return this.#abandonId
  }

  /**
   * Use {@link abandonId} instead.
   *
   * @deprecated
   */
  get abandonID () {
    warning.emit('LDAP_MESSAGE_DEP_003')
    return this.#abandonId
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'AbandonRequest'
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.writeInt(this.#abandonId, Protocol.operations.LDAP_REQ_ABANDON)
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.abandonId = this.#abandonId
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   */
  static parseToPojo (ber) {
    const protocolOp = ber.peek()
    if (protocolOp !== Protocol.operations.LDAP_REQ_ABANDON) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const abandonId = ber.readInt(Protocol.operations.LDAP_REQ_ABANDON)
    return { protocolOp, abandonId }
  }
}

module.exports = AbandonRequest

},{"../deprecations":65,"../ldap-message":66,"@ldapjs/protocol":93}],69:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')

/**
 * Implements the ldapjs specific ABANDON response object.
 */
class AbandonResponse extends LdapResult {
  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = 0x00
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'AbandonResponse'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: 0x00,
      berReader: ber
    })
  }
}

module.exports = AbandonResponse

},{"../ldap-result":67}],70:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const Attribute = require('@ldapjs/attribute')
const Protocol = require('@ldapjs/protocol')
const { DN } = require('@ldapjs/dn')

/**
 * Implements the add request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.7
 */
class AddRequest extends LdapMessage {
  /**
   * Path to the LDAP object.
   *
   * @type {null | import('@ldapjs/dn').DN}
   */
  #entry;

  /**
   * A set of attribute objects.
   *
   * @type {import('@ldapjs/attribute')[]}
   */
  #attributes = [];

  /**
   * @typedef {LdapMessageOptions} AddRequestOptions
   * @property {string} [entry=null] The path to the LDAP object.
   * @property {import('@ldapjs/attribute')[]} [attributes=[]] A set of
   * attributes to store at the `entry` path.
   */

  /**
   * @param {AddRequestOptions} [options]
   *
   * @throws When the provided attributes list is invalid.
   */
  constructor (options = {}) {
    options.protocolOp = Protocol.operations.LDAP_REQ_ADD
    super(options)

    this.entry = options.entry || null
    this.attributes = options.attributes || []
  }

  /**
   * Get a copy of the attributes associated with the request.
   *
   * @returns {import('@ldapjs/attribute')[]}
   */
  get attributes () {
    return this.#attributes.slice(0)
  }

  /**
   * Set the attributes to be added to the entry. Replaces any existing
   * attributes.
   *
   * @param {import('@ldapjs/attribute')[]} attrs
   *
   * @throws If the input is not an array, or any element is not an
   * {@link Attribute} or attribute-like object.
   */
  set attributes (attrs) {
    if (Array.isArray(attrs) === false) {
      throw Error('attrs must be an array')
    }
    const newAttrs = []
    for (const attr of attrs) {
      if (Attribute.isAttribute(attr) === false) {
        throw Error('attr must be an Attribute instance or Attribute-like object')
      }
      if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
        newAttrs.push(new Attribute(attr))
        continue
      }
      newAttrs.push(attr)
    }
    this.#attributes = newAttrs
  }

  /**
   * The directory path to the object to add.
   *
   * @type {string}
   */
  get entry () {
    return this.#entry ?? null
  }

  /**
   * Define the entry path to the LDAP object.
   *
   * @param {string | import('@ldapjs/dn').DN} path
   */
  set entry (path) {
    if (path === null) return
    if (typeof path === 'string') {
      this.#entry = DN.fromString(path)
    } else if (Object.prototype.toString.call(path) === '[object LdapDn]') {
      this.#entry = path
    } else {
      throw Error('entry must be a valid DN string or instance of LdapDn')
    }
  }

  /**
   * Alias of {@link entry}.
   *
   * @type {string}
   */
  get _dn () {
    return this.entry
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'AddRequest'
  }

  /**
   * Add a new {@link Attribute} to the list of request attributes.
   *
   * @param {import('@ldapjs/attribute')} attr
   *
   * @throws When the input is not an {@link Attribute} instance.
   */
  addAttribute (attr) {
    if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
      throw Error('attr must be an instance of Attribute')
    }

    this.#attributes.push(attr)
  }

  /**
   * Get the list of attribute names for the attributes in the
   * request.
   *
   * @returns {string[]}
   */
  attributeNames () {
    return this.#attributes.map(attr => attr.type)
  }

  /**
   * Retrieve an attribute by name from the attributes associated with
   * the request.
   *
   * @param {string} attributeName
   *
   * @returns {import('@ldapjs/attribute')|null}
   *
   * @throws When `attributeName` is not a string.
   */
  getAttribute (attributeName) {
    if (typeof attributeName !== 'string') {
      throw Error('attributeName must be a string')
    }

    for (const attr of this.#attributes) {
      if (attr.type === attributeName) {
        return attr
      }
    }

    return null
  }

  /**
   * Find the index of an {@link Attribute} in the request's
   * attribute set.
   *
   * @param {string} attributeName
   *
   * @returns {number} The index of the attribute, or `-1` if not
   * found.
   *
   * @throws When `attributeName` is not a string.
   */
  indexOf (attributeName) {
    if (typeof attributeName !== 'string') {
      throw Error('attributeName must be a string')
    }

    for (let i = 0; i < this.#attributes.length; i += 1) {
      if (this.#attributes[i].type === attributeName) {
        return i
      }
    }

    return -1
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(Protocol.operations.LDAP_REQ_ADD)
    ber.writeString(this.#entry.toString())
    ber.startSequence()
    for (const attr of this.#attributes) {
      const attrBer = attr.toBer()
      ber.appendBuffer(attrBer.buffer)
    }
    ber.endSequence()
    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.entry = this.#entry ? this.#entry.toString() : null
    obj.attributes = []
    for (const attr of this.#attributes) {
      obj.attributes.push(attr.pojo)
    }
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== Protocol.operations.LDAP_REQ_ADD) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const entry = ber.readString()
    const attributes = []

    // Advance to the first attribute sequence in the set
    // of attribute sequences.
    ber.readSequence()

    const endOfAttributesPos = ber.offset + ber.length
    while (ber.offset < endOfAttributesPos) {
      const attribute = Attribute.fromBer(ber)
      attribute.type = attribute.type.toLowerCase()

      if (attribute.type === 'objectclass') {
        for (let i = 0; i < attribute.values.length; i++) {
          attribute.values[i] = attribute.values[i].toLowerCase()
        }
      }

      attributes.push(attribute)
    }

    return { protocolOp, entry, attributes }
  }
}

module.exports = AddRequest

},{"../ldap-message":66,"@ldapjs/attribute":7,"@ldapjs/dn":27,"@ldapjs/protocol":93}],71:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the add response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.7
 */
class AddResponse extends LdapResult {
  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_ADD
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'AddResponse'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_ADD,
      berReader: ber
    })
  }
}

module.exports = AddResponse

},{"../ldap-result":67,"@ldapjs/protocol":93}],72:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const Protocol = require('@ldapjs/protocol')
const { BerTypes } = require('@ldapjs/asn1')

/**
 * Implements the bind request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.2.
 *
 * The bind request is further defined by:
 * https://www.rfc-editor.org/rfc/rfc4513#section-5.
 */
class BindRequest extends LdapMessage {
  static SIMPLE_BIND = 'simple'
  static SASL_BIND = 'sasl'

  #version = 0x03;
  #name;
  #authentication = BindRequest.SIMPLE_BIND;
  #credentials = '';

  /**
   * @typedef {LdapMessageOptions} BindRequestOptions
   * @property {number} [version=3] Version of the protocol being used.
   * @property {string} [name=null] The "username" (dn) to connect with.
   * @property {string} [authentication='simple'] The authentication
   * mechanism to use. Currently, only `simple` is supported.
   * @property {string} [credentials=''] The password to use.
   */

  /**
   * @param {BindRequestOptions} [options]
   */
  constructor (options = {}) {
    options.protocolOp = Protocol.operations.LDAP_REQ_BIND
    super(options)

    const {
      version = 0x03,
      name = null,
      authentication = BindRequest.SIMPLE_BIND,
      credentials = ''
    } = options
    this.#version = version
    this.#name = name
    this.#authentication = authentication
    this.#credentials = credentials
  }

  /**
   * The authentication credentials for the request.
   *
   * @returns {string}
   */
  get credentials () {
    return this.#credentials
  }

  /**
   * The DN, or "username", that is to be used in the bind request.
   *
   * @type {string}
   */
  get name () {
    return this.#name
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'BindRequest'
  }

  /**
   * The version number that the bind request conforms to.
   *
   * @type {number}
   */
  get version () {
    return this.#version
  }

  /**
   * Use {@link name} instead.
   *
   * @type {string}
   */
  get _dn () {
    return this.#name
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(Protocol.operations.LDAP_REQ_BIND)
    ber.writeInt(this.#version)
    ber.writeString(this.#name || '')
    // TODO add support for SASL et al
    ber.writeString(this.#credentials || '', BerTypes.Context)
    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.version = this.#version
    obj.name = this.#name
    obj.authenticationType = this.#authentication
    obj.credentials = this.#credentials
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== Protocol.operations.LDAP_REQ_BIND) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const version = ber.readInt()
    const name = ber.readString()

    const tag = ber.peek()

    // TODO: add support for SASL et al
    if (tag !== BerTypes.Context) {
      // Currently only support 0x80. To support SASL, must support 0x83.
      const authType = tag.toString(16).padStart(2, '0')
      throw Error(`authentication 0x${authType} not supported`)
    }

    const authentication = BindRequest.SIMPLE_BIND
    const credentials = ber.readString(BerTypes.Context)

    return {
      protocolOp,
      version,
      name,
      authentication,
      credentials
    }
  }
}

module.exports = BindRequest

},{"../ldap-message":66,"@ldapjs/asn1":2,"@ldapjs/protocol":93}],73:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the bind response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.2.2
 */
class BindResponse extends LdapResult {
  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_BIND
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'BindResponse'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_BIND,
      berReader: ber
    })
  }
}

module.exports = BindResponse

},{"../ldap-result":67,"@ldapjs/protocol":93}],74:[function(require,module,exports){
'use strict'

const { operations } = require('@ldapjs/protocol')
const { DN } = require('@ldapjs/dn')
const LdapMessage = require('../ldap-message')

/**
 * Implements the compare request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.10.
 */
class CompareRequest extends LdapMessage {
  #attribute;
  #entry;
  #value;

  /**
   * @typedef {LdapMessageOptions} CompareRequestOptions
   * @property {string|null} [attribute] The attribute name to compare
   * against.
   * @property {string} [entry] The target LDAP entity whose attribute
   * will be compared.
   * @property {string} [value] The value of the attribute to compare.
   */

  /**
   * @param {CompareRequestOptions} [options]
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_REQ_COMPARE
    super(options)

    this.attribute = options.attribute || ''
    this.entry = options.entry || null
    this.value = options.value || ''
  }

  /**
   * The property of an LDAP entry to compare against.
   *
   * @returns {string}
   */
  get attribute () {
    return this.#attribute
  }

  /**
   * Define the LDAP entry property to compare against.
   *
   * @param {string} value
   */
  set attribute (value) {
    this.#attribute = value
  }

  /**
   * The LDAP entry that will be inspected.
   *
   * @returns {string | null}
   */
  get entry () {
    return this.#entry ?? null
  }

  /**
   * Define the LDAP entity to inspect.
   *
   * @param {string | null} value
   */
  set entry (value) {
    if (value === null) return
    if (typeof value === 'string') {
      this.#entry = DN.fromString(value)
    } else if (Object.prototype.toString.call(value) === '[object LdapDn]') {
      this.#entry = value
    } else {
      throw Error('entry must be a valid DN string or instance of LdapDn')
    }
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'CompareRequest'
  }

  /**
   * The value the attribute should be set to.
   *
   * @returns {string}
   */
  get value () {
    return this.#value
  }

  /**
   * Define the value the attribute should match.
   *
   * @param {string} value
   */
  set value (value) {
    this.#value = value
  }

  get _dn () {
    return this.#entry
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_REQ_COMPARE)

    ber.writeString(this.#entry.toString())
    ber.startSequence()
    ber.writeString(this.#attribute)
    ber.writeString(this.#value)
    ber.endSequence()

    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.attribute = this.#attribute
    obj.entry = this.#entry ? this.#entry.toString() : null
    obj.value = this.#value
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_REQ_COMPARE) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const entry = ber.readString()
    ber.readSequence()
    const attribute = ber.readString()
    const value = ber.readString()

    return {
      protocolOp,
      entry,
      attribute,
      value
    }
  }
}

module.exports = CompareRequest

},{"../ldap-message":66,"@ldapjs/dn":27,"@ldapjs/protocol":93}],75:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the compare response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.10.
 */
class CompareResponse extends LdapResult {
  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_COMPARE
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'CompareResponse'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_COMPARE,
      berReader: ber
    })
  }
}

module.exports = CompareResponse

},{"../ldap-result":67,"@ldapjs/protocol":93}],76:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const Protocol = require('@ldapjs/protocol')
const { DN } = require('@ldapjs/dn')

/**
 * Implements the delete request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.8
 */
class DeleteRequest extends LdapMessage {
  #entry

  /**
   * @typedef {LdapMessageOptions} DeleteRequestOptions
   * @property {string} [entry=null] The LDAP entry path to remove.
   */

  /**
   * @param {DeleteRequestOptions} [options]
   */
  constructor (options = {}) {
    options.protocolOp = Protocol.operations.LDAP_REQ_DELETE
    super(options)

    this.entry = options.entry ?? null
  }

  /**
   * Alias of {@link name}.
   *
   * @type {string}
   */
  get _dn () {
    return this.entry
  }

  /**
   * The identifier for the request that the instance will request be abandoned.
   *
   * @type {number}
   */
  get entry () {
    return this.#entry ?? null
  }

  /**
   * Define the path to the LDAP object that will be deleted.
   *
   * @param {string | null | import('@ldapjs/dn').DN} value
   */
  set entry (value) {
    if (value === null) return
    if (typeof value === 'string') {
      this.#entry = DN.fromString(value)
    } else if (Object.prototype.toString.call(value) === '[object LdapDn]') {
      this.#entry = value
    } else {
      throw Error('entry must be a valid DN string or instance of LdapDn')
    }
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'DeleteRequest'
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.writeString(this.#entry.toString(), Protocol.operations.LDAP_REQ_DELETE)
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.protocolOp = Protocol.operations.LDAP_REQ_DELETE
    obj.entry = this.#entry ? this.#entry.toString() : null
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   */
  static parseToPojo (ber) {
    const protocolOp = ber.peek()
    if (protocolOp !== Protocol.operations.LDAP_REQ_DELETE) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const entry = ber.readString(Protocol.operations.LDAP_REQ_DELETE)
    return { protocolOp, entry }
  }
}

module.exports = DeleteRequest

},{"../ldap-message":66,"@ldapjs/dn":27,"@ldapjs/protocol":93}],77:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the delete response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.8.
 */
class DeleteResponse extends LdapResult {
  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_DELETE
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'DeleteResponse'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_DELETE,
      berReader: ber
    })
  }
}

module.exports = DeleteResponse

},{"../ldap-result":67,"@ldapjs/protocol":93}],78:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const { operations } = require('@ldapjs/protocol')
const RECOGNIZED_OIDS = require('./extension-utils/recognized-oids')

/**
 * Implements the extension request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.12.
 *
 * There is a set of supported extension request OIDs supported. Any
 * unrecognized OID will be treated a simple string pair, i.e. both
 * `requestName` and `requestValue` will be assumed to be simple strings.
 */
class ExtensionRequest extends LdapMessage {
  #requestName;
  #requestValue;

  /**
   * @typedef {LdapMessageOptions} ExtensionRequestOptions
   * @property {string} [requestName=''] The name of the extension, i.e.
   * OID for the request.
   * @property {string|object} [requestValue] The value for the request.
   * If `undefined`, no value will be sent. If the request requires a simple
   * string value, provide such a string. For complex valued requests, e.g.
   * for a password modify request, it should be a plain object with the
   * appropriate properties. See the implementation of {@link parseToPojo}
   * for the set of supported objects.
   */

  /**
   * @param {ExtensionRequestOptions} [options]
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_REQ_EXTENSION
    super(options)

    this.requestName = options.requestName || ''
    this.requestValue = options.requestValue
  }

  /**
   * Alias of {@link requestName}.
   *
   * @type {string}
   */
  get _dn () {
    return this.#requestName
  }

  /**
   * The name (OID) of the request.
   *
   * @returns {string}
   */
  get requestName () {
    return this.#requestName
  }

  /**
   * Set the name for the request. Should be an OID that
   * matches a specification.
   *
   * @param {string} value
   */
  set requestName (value) {
    this.#requestName = value
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'ExtensionRequest'
  }

  /**
   * The value, if any, for the request.
   *
   * @returns {undefined|string|object} value
   */
  get requestValue () {
    return this.#requestValue
  }

  /**
   * Set the value for the request. The value should conform
   * to the specification identified by the {@link requestName}.
   * See the implemenation of {@link parseToPojo} for valid
   * value shapes.
   *
   * @param {undefined|string|object} value
   */
  set requestValue (val) {
    this.#requestValue = val
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_REQ_EXTENSION)
    ber.writeString(this.requestName, 0x80)

    if (this.requestValue) {
      switch (this.requestName) {
        case RECOGNIZED_OIDS.get('CANCEL_REQUEST'): {
          encodeCancelRequest({ ber, requestValue: this.requestValue })
          break
        }

        case RECOGNIZED_OIDS.get('PASSWORD_MODIFY'): {
          encodePasswordModify({
            ber,
            requestValue: this.requestValue
          })
          break
        }

        default: {
          // We assume the value is a plain string since
          // we do not recognize the request OID, or we know
          // that the OID uses a plain string value.
          ber.writeString(this.requestValue, 0x81)
        }
      }
    }

    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.requestName = this.requestName
    obj.requestValue = this.requestValue
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_REQ_EXTENSION) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    // While the requestName is an OID, it is not an
    // _encoded_ OID. It is a plain string. So we do
    // not use `.readOID` here.
    const requestName = ber.readString(0x80)
    if (ber.peek() !== 0x81) {
      // There is not a request value present, so we just
      // return an empty value representation.
      return { protocolOp, requestName }
    }

    let requestValue
    switch (requestName) {
      case RECOGNIZED_OIDS.get('CANCEL_REQUEST'): {
        requestValue = readCancelRequest(ber)
        break
      }

      case RECOGNIZED_OIDS.get('PASSWORD_MODIFY'): {
        requestValue = readPasswordModify(ber)
        break
      }

      default: {
        // We will assume it is a plain string value
        // since we do not recognize the OID, or we know
        // that the OID uses a plain string value.
        requestValue = ber.readString(0x81)
        break
      }
    }

    return { protocolOp, requestName, requestValue }
  }

  /**
   * A list of EXTENDED operation OIDs that this module
   * recognizes. Key names are named according to the common name
   * of the extension. Key values are the OID associated with that
   * extension. For example, key `PASSWORD_MODIFY` corresponds to
   * OID `1.3.6.1.4.1.4203.1.11.1`.
   *
   * @returns {Map<string, string>}
   */
  static recognizedOIDs () {
    return RECOGNIZED_OIDS
  }
}

module.exports = ExtensionRequest

/**
 * @param {object} input
 * @param {@import('@ldapjs/asn1').BerWriter} input.ber
 * @param {object} requestValue
 */
function encodeCancelRequest ({ ber, requestValue }) {
  ber.startSequence(0x81)
  ber.startSequence()
  ber.writeInt(requestValue)
  ber.endSequence()
  ber.endSequence()
}

/**
 * @param {@import('@ldapjs/asn1').BerReader} ber
 * @returns {number}
 */
function readCancelRequest (ber) {
  ber.readSequence(0x81)
  ber.readSequence()
  return ber.readInt()
}

/**
 * @param {object} input
 * @param {@import('@ldapjs/asn1').BerWriter} input.ber
 * @param {object} requestValue
 */
function encodePasswordModify ({ ber, requestValue }) {
  // start the value sequence
  ber.startSequence(0x81)
  // start the generic packed sequence
  ber.startSequence()
  if (requestValue.userIdentity) {
    ber.writeString(requestValue.userIdentity, 0x80)
  }
  if (requestValue.oldPassword) {
    ber.writeString(requestValue.oldPassword, 0x81)
  }
  if (requestValue.newPassword) {
    ber.writeString(requestValue.newPassword, 0x82)
  }
  ber.endSequence()
  ber.endSequence()
}

/**
 * @param {@import('@ldapjs/asn1').BerReader} ber
 * @returns {object}
 */
function readPasswordModify (ber) {
  // advance to the embedded sequence
  ber.readSequence(0x81)
  // advance to the value of the embedded sequence
  ber.readSequence()
  let userIdentity
  if (ber.peek() === 0x80) {
    userIdentity = ber.readString(0x80)
  }
  let oldPassword
  if (ber.peek() === 0x81) {
    oldPassword = ber.readString(0x81)
  }
  let newPassword
  if (ber.peek() === 0x82) {
    newPassword = ber.readString(0x82)
  }
  return { userIdentity, oldPassword, newPassword }
}

},{"../ldap-message":66,"./extension-utils/recognized-oids":82,"@ldapjs/protocol":93}],79:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the extension response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.12.
 *
 * The type of response is impossible to determine in isolation.
 * Most EXTENSION responses do not include the request OID. And they
 * all encode their values in unique ways. Therefore, this object's
 * {@link parseToPojo} never attempts to parse the response value.
 * Instead, if it is present, it reads the value as a buffer and
 * encodes it into a hexadecimal string prefixed with a `<buffer>`
 * token. This string is then used by the `#fromExtension` method
 * on specific implementations to build a new object. It is left up to
 * the implementor to know when certain responses are expected and
 * to act accordingly.
 */
class ExtensionResponse extends LdapResult {
  #responseName;
  #responseValue;

  /**
   * @typedef {LdapResultOptions} ExtensionResponseOptions
   * @property {string|undefined} [responseName] The name of the extension, i.e.
   * OID for the response.
   * @property {string|undefined} [responseValue] The value for the
   * response. It may be a buffer string; such a string is a series of
   * hexadecimal pairs preceded by the token `<buffer>`. Buffer strings
   * are used by specific response object types to get that type's specific
   * encoded value.
   */

  /**
   * @param {ExtensionResponseOptions} [options]
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_EXTENSION
    super(options)

    this.responseName = options.responseName
    this.responseValue = options.responseValue
  }

  /**
   * The OID, if any, of the response.
   *
   * @returns {string|undefined}
   */
  get responseName () {
    return this.#responseName
  }

  /**
   * Define the name (OID) of the response.
   *
   * @param {string} value
   */
  set responseName (value) {
    this.#responseName = value
  }

  /**
   * The response value, if any. For specific extensions that
   * are not simple string values, the initial value is a buffer string.
   * That is, it is a hexadecimal string of bytes prefixed with `<buffer>`.
   * To parse this value, use a specific extension's `#fromResponse` method.
   *
   * @returns {string|undefined}
   */
  get responseValue () {
    return this.#responseValue
  }

  /**
   * Set the response value. Should be a buffer string if the value is
   * an encoded value.
   *
   * @param {string} value
   */
  set responseValue (value) {
    this.#responseValue = value
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'ExtensionResponse'
  }

  /**
   * Internal use only. Used to write the response name and
   * response value into the BER object.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _writeResponse (ber) {
    if (this.responseName) {
      ber.writeString(this.responseName, 0x8a)
    }

    if (this.responseValue === undefined) {
      return ber
    }

    switch (this.responseName) {
      default: {
        // We assume the value is a plain string since
        // we do not recognize the response OID, or we
        // know it would be a plain string.
        ber.writeString(this.responseValue, 0x8b)
      }
    }

    return ber
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const pojo = LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_EXTENSION,
      berReader: ber
    })

    let responseName
    if (ber.peek() === 0x8a) {
      responseName = ber.readString(0x8a)
    }

    if (ber.peek() !== 0x8b) {
      return { ...pojo, responseName }
    }

    const valueBuffer = ber.readTag(0x8b)
    const responseValue = `<buffer>${valueBuffer.toString('hex')}`

    return { ...pojo, responseName, responseValue }
  }
}

module.exports = ExtensionResponse

},{"../ldap-result":67,"@ldapjs/protocol":93}],80:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const { BerReader } = require('@ldapjs/asn1')
const ExtensionResponse = require('../extension-response')

/**
 * Implements the password modify extension defined by
 * https://www.rfc-editor.org/rfc/rfc3062.
 */
class PasswordModifyResponse extends ExtensionResponse {
  /**
   * Given a basic {@link ExtensionResponse} with a buffer string in
   * `responseValue`, parse into a specific {@link PasswordModifyResponse}
   * instance.
   *
   * @param {ExtensionResponse} response
   *
   * @returns {PasswordModifyResponse}
   */
  static fromResponse (response) {
    if (response.responseValue === undefined) {
      return new PasswordModifyResponse()
    }

    const valueBuffer = Buffer.from(response.responseValue.substring(8), 'hex')
    const reader = new BerReader(valueBuffer)
    reader.readSequence()
    const responseValue = reader.readString(0x80)
    return new PasswordModifyResponse({ responseValue })
  }
}

module.exports = PasswordModifyResponse

}).call(this)}).call(this,require("buffer").Buffer)
},{"../extension-response":79,"@ldapjs/asn1":2,"buffer":110}],81:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const ExtensionResponse = require('../extension-response')

/**
 * Implements the "Who Am I" extension defined by
 * https://www.rfc-editor.org/rfc/rfc4532.
 */
class WhoAmIResponse extends ExtensionResponse {
  /**
   * Given a basic {@link ExtensionResponse} with a buffer string in
   * `responseValue`, parse into a specific {@link WhoAmIResponse}
   * instance.
   *
   * @param {ExtensionResponse} response
   *
   * @returns {WhoAmIResponse}
   */
  static fromResponse (response) {
    if (response.responseValue === undefined) {
      return new WhoAmIResponse()
    }

    const valueBuffer = Buffer.from(response.responseValue.substring(8), 'hex')
    const responseValue = valueBuffer.toString('utf8')
    return new WhoAmIResponse({ responseValue })
  }
}

module.exports = WhoAmIResponse

}).call(this)}).call(this,require("buffer").Buffer)
},{"../extension-response":79,"buffer":110}],82:[function(require,module,exports){
'use strict'

const OIDS = new Map([
  ['CANCEL_REQUEST', '1.3.6.1.1.8'], // RFC 3909
  ['DISCONNECTION_NOTIFICATION', '1.3.6.1.4.1.1466.20036'], // RFC 4511
  ['PASSWORD_MODIFY', '1.3.6.1.4.1.4203.1.11.1'], // RFC 3062
  ['START_TLS', '1.3.6.1.4.1.1466.20037'], // RFC 4511
  ['WHO_AM_I', '1.3.6.1.4.1.4203.1.11.3'] // RFC 4532
])

Object.defineProperty(OIDS, 'lookupName', {
  value: function (oid) {
    for (const [key, value] of this.entries()) {
      /* istanbul ignore else */
      if (value === oid) return key
    }
  }
})

Object.defineProperty(OIDS, 'lookupOID', {
  value: function (name) {
    for (const [key, value] of this.entries()) {
      /* istanbul ignore else */
      if (key === name) return value
    }
  }
})

module.exports = OIDS

},{}],83:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const { operations } = require('@ldapjs/protocol')

const partIsNotNumeric = part => /^\d+$/.test(part) === false

/**
 * Determines if a passed in string is a dotted decimal string.
 *
 * Copied from `@ldapjs/dn`.
 *
 * @param {string} value
 *
 * @returns {boolean}
 */
function isDottedDecimal (value) {
  if (typeof value !== 'string') return false

  const parts = value.split('.')
  const nonNumericParts = parts.filter(partIsNotNumeric)

  return nonNumericParts.length === 0
}

/**
 * Implements the intermediate response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.13.
 *
 * TODO: actual implementations of this, e.g. RFC 4533 §2.5, seem to encode
 * sequences in the responseValue. That means this needs a more robust
 * implementation like is found in the ExtensionResponse implementation (i.e.
 * detection of recognized OIDs and specific sub-implementations). As of now,
 * this implementation follows the baseline spec without any sub-implementations.
 */
class IntermediateResponse extends LdapMessage {
  #responseName;
  #responseValue;

  /**
   * @typedef {LdapMessageOptions} IntermediateResponseOptions
   * @property {string} responseName
   * @property {string} responseValue
   */

  /**
   * @param {IntermediateResponseOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_INTERMEDIATE
    super(options)

    this.responseName = options.responseName ?? null
    this.responseValue = options.responseValue ?? null
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'IntermediateResponse'
  }

  /**
   * The numeric OID that identifies the type of intermediate response.
   *
   * @returns {string | undefined}
   */
  get responseName () {
    return this.#responseName
  }

  /**
   * Define the numeric OID that identifies the type of intermediate response.
   *
   * @param {string | null} value
   *
   * @throws For an invalid value.
   */
  set responseName (value) {
    if (value === null) return
    if (isDottedDecimal(value) === false) {
      throw Error('responseName must be a numeric OID')
    }
    this.#responseName = value
  }

  /**
   * The value for the intermidate response if any.
   *
   * @returns {string | undefined}
   */
  get responseValue () {
    return this.#responseValue
  }

  /**
   * Define the value for the intermediate response.
   *
   * @param {string | null} value
   *
   * @throws For an invalid value.
   */
  set responseValue (value) {
    if (value === null) return
    if (typeof value !== 'string') {
      throw Error('responseValue must be a string')
    }
    this.#responseValue = value
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_RES_INTERMEDIATE)

    if (this.#responseName) {
      ber.writeString(this.#responseName, 0x80)
    }
    if (this.#responseValue) {
      ber.writeString(this.#responseValue, 0x81)
    }

    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.responseName = this.#responseName
    obj.responseValue = this.#responseValue
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_RES_INTERMEDIATE) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    let responseName
    let responseValue

    let tag = ber.peek()
    switch (tag) {
      case 0x80: {
        responseName = ber.readString(tag)

        tag = ber.peek()
        /* istanbul ignore else */
        if (tag === 0x81) {
          responseValue = ber.readString(tag)
        }
        break
      }

      case 0x81: {
        responseValue = ber.readString(tag)
      }
    }

    return { protocolOp, responseName, responseValue }
  }
}

module.exports = IntermediateResponse

},{"../ldap-message":66,"@ldapjs/protocol":93}],84:[function(require,module,exports){
'use strict'

const { operations } = require('@ldapjs/protocol')
const Change = require('@ldapjs/change')
const LdapMessage = require('../ldap-message')

/**
 * Implements the MODIFY request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6.
 *
 * Changes should be in the order of operation as described in
 * the spec. If sorting is desired, sort the array prior to
 * adding it to the request.
 *
 * @example <caption>Sorting Changes</caption>
 * const {ModifyRequest} = require('@ldapjs/messages')
 * const Change = require('@ldapjs/change')
 * const changes = someArrayOfChanges.sort(Change.sort)
 * const req = new ModifyRequest({
 *   object: 'dn=foo,dc=example,dc=com',
 *   changes
 * })
 */
class ModifyRequest extends LdapMessage {
  #object;
  #changes;

  /**
   * @typedef {LdapMessageOptions} ModifyRequestOptions
   * @property {string|null} [object] The LDAP object (DN) to modify.
   * @property {import('@ldapjs/change')[]} [changes] The set of changes to
   * apply.
   */

  /**
   * @param {ModifyRequestOptions} [options]
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_REQ_MODIFY
    super(options)

    this.#object = options.object || null
    this.changes = options.changes || []
  }

  /**
   * A copy of the set of changes to be applied to the LDAP object.
   *
   * @returns {import('@ldapjs/change')[]}
   */
  get changes () {
    return this.#changes.slice(0)
  }

  /**
   * Define the set of changes to apply to the LDAP object.
   *
   * @param {import('@ldapjs/change')[]} values
   *
   * @throws When `values` is not an array or contains any elements that
   * are not changes.
   */
  set changes (values) {
    this.#changes = []
    if (Array.isArray(values) === false) {
      throw Error('changes must be an array')
    }
    for (let change of values) {
      if (Change.isChange(change) === false) {
        throw Error('change must be an instance of Change or a Change-like object')
      }
      if (Object.prototype.toString.call(change) !== '[object LdapChange]') {
        change = new Change(change)
      }
      this.#changes.push(change)
    }
  }

  /**
   * The object (DN) to be modified.
   *
   * @returns {string}
   */
  get object () {
    return this.#object
  }

  /**
   * Define the object (DN) to be modified.
   *
   * @param {string} value
   */
  set object (value) {
    this.#object = value
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'ModifyRequest'
  }

  get _dn () {
    return this.#object
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_REQ_MODIFY)

    ber.writeString(this.#object.toString())
    ber.startSequence()
    for (const change of this.#changes) {
      ber.appendBuffer(change.toBer().buffer)
    }
    ber.endSequence()

    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.object = this.#object
    obj.changes = this.#changes.map(c => c.pojo)
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_REQ_MODIFY) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const object = ber.readString()
    const changes = []

    ber.readSequence()
    const end = ber.offset + ber.length
    while (ber.offset < end) {
      const change = Change.fromBer(ber)
      changes.push(change.pojo)
    }

    return { protocolOp, object, changes }
  }
}

module.exports = ModifyRequest

},{"../ldap-message":66,"@ldapjs/change":9,"@ldapjs/protocol":93}],85:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the MODIFY response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6.
 */
class ModifyResponse extends LdapResult {
  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_MODIFY
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'ModifyResponse'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_MODIFY,
      berReader: ber
    })
  }
}

module.exports = ModifyResponse

},{"../ldap-result":67,"@ldapjs/protocol":93}],86:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const { operations } = require('@ldapjs/protocol')
const { DN } = require('@ldapjs/dn')

/**
 * Implements the modifydn request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.9.
 */
class ModifyDnRequest extends LdapMessage {
  #entry;
  #newRdn;
  #deleteOldRdn;
  #newSuperior;

  /**
   * @typedef {LdapMessageOptions} ModifyDnRequestOptions
   * @property {string|null} [entry=null] The path to the LDAP object.
   * @property {string|null} [newRdn=null] Path to the new object for the
   * entry.
   * @property {boolean} [deleteOldRdn=false] Indicates if attributes
   * should be removed in the new RDN that were in the old RDN but not the
   * new one.
   * @property {string} [newSuperior] Path for the new parent for
   * the RDN.
   */

  /**
   * @param {ModifyDnRequestOptions} [options]
   *
   * @throws When an option is invalid (e.g. `deleteOldRdn` is not a boolean
   * value).
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_REQ_MODRDN
    super(options)

    this.entry = options.entry || ''
    this.newRdn = options.newRdn || ''
    this.deleteOldRdn = options.deleteOldRdn ?? false
    this.newSuperior = options.newSuperior
  }

  /**
   * The directory path to the object to modify.
   *
   * @type {import('@ldapjs/dn').DN}
   */
  get entry () {
    return this.#entry
  }

  /**
   * Define the entry path to the LDAP object.
   *
   * @param {string | import('@ldapjs/dn').dn} value
   */
  set entry (value) {
    if (typeof value === 'string') {
      this.#entry = DN.fromString(value)
    } else if (Object.prototype.toString.call(value) === '[object LdapDn]') {
      this.#entry = value
    } else {
      throw Error('entry must be a valid DN string or instance of LdapDn')
    }
  }

  /**
   * Alias of {@link entry}.
   *
   * @type {import('@ldapjs/dn').DN}
   */
  get _dn () {
    return this.#entry
  }

  /**
   * The new directory path for the object.
   *
   * @returns {import('@ldapjs/dn').DN}
   */
  get newRdn () {
    return this.#newRdn
  }

  /**
   * Define the new entry path to the LDAP object.
   *
   * @param {string | import('@ldapjs/dn').DN} value
   */
  set newRdn (value) {
    if (typeof value === 'string') {
      this.#newRdn = DN.fromString(value)
    } else if (Object.prototype.toString.call(value) === '[object LdapDn]') {
      this.#newRdn = value
    } else {
      throw Error('newRdn must be a valid DN string or instance of LdapDn')
    }
  }

  /**
   * Indicates if the old RDN should be removed or not.
   *
   * @returns {boolean}
   */
  get deleteOldRdn () {
    return this.#deleteOldRdn
  }

  set deleteOldRdn (value) {
    if (typeof value !== 'boolean') {
      throw Error('deleteOldRdn must be a boolean value')
    }
    this.#deleteOldRdn = value
  }

  /**
   * The new superior for the entry, if any is defined.
   *
   * @returns {undefined | import('@ldapjs/dn').DN}
   */
  get newSuperior () {
    return this.#newSuperior
  }

  /**
   * Define the new superior path.
   *
   * @param {undefined | string | import('@ldapjs/dn').DN} value
   */
  set newSuperior (value) {
    if (value) {
      if (typeof value === 'string') {
        this.#newSuperior = DN.fromString(value)
      } else if (Object.prototype.toString.call(value) === '[object LdapDn]') {
        this.#newSuperior = value
      } else {
        throw Error('newSuperior must be a valid DN string or instance of LdapDn')
      }
    } else {
      this.#newSuperior = undefined
    }
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'ModifyDnRequest'
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_REQ_MODRDN)

    ber.writeString(this.#entry.toString())
    ber.writeString(this.#newRdn.toString())
    ber.writeBoolean(this.#deleteOldRdn)
    /* istanbul ignore else */
    if (this.#newSuperior !== undefined) {
      ber.writeString(this.#newSuperior.toString(), 0x80)
    }

    ber.endSequence()

    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.entry = this.#entry.toString()
    obj.newRdn = this.#newRdn.toString()
    obj.deleteOldRdn = this.#deleteOldRdn
    obj.newSuperior = this.#newSuperior ? this.#newSuperior.toString() : undefined
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_REQ_MODRDN) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const entry = ber.readString()
    const newRdn = ber.readString()
    const deleteOldRdn = ber.readBoolean()
    let newSuperior
    /* istanbul ignore else */
    if (ber.peek() === 0x80) {
      newSuperior = ber.readString(0x80)
    }

    return { protocolOp, entry, newRdn, deleteOldRdn, newSuperior }
  }
}

module.exports = ModifyDnRequest

},{"../ldap-message":66,"@ldapjs/dn":27,"@ldapjs/protocol":93}],87:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the modifydn response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.9.
 */
class ModifyDnResponse extends LdapResult {
  /**
   * @param {LdapResultOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_MODRDN
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'ModifyDnResponse'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_MODRDN,
      berReader: ber
    })
  }
}

module.exports = ModifyDnResponse

},{"../ldap-result":67,"@ldapjs/protocol":93}],88:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const { operations, search } = require('@ldapjs/protocol')
const { DN } = require('@ldapjs/dn')
const filter = require('@ldapjs/filter')
const { BerReader, BerTypes } = require('@ldapjs/asn1')

const recognizedScopes = new Map([
  ['base', [search.SCOPE_BASE_OBJECT, 'base']],
  ['single', [search.SCOPE_ONE_LEVEL, 'single', 'one']],
  ['subtree', [search.SCOPE_SUBTREE, 'subtree', 'sub']]
])
const scopeAliasToScope = alias => {
  alias = typeof alias === 'string' ? alias.toLowerCase() : alias
  if (recognizedScopes.has(alias)) {
    return recognizedScopes.get(alias)[0]
  }
  for (const value of recognizedScopes.values()) {
    if (value.includes(alias)) {
      return value[0]
    }
  }
  return undefined
}

const isValidAttributeString = str => {
  // special filter strings
  if (['*', '1.1', '+'].includes(str) === true) {
    return true
  }
  // "@<object_clas>"
  if (/^@[a-zA-Z][\w\d.-]*$/.test(str) === true) {
    return true
  }
  // ascii attribute names
  if (/^[a-zA-Z][\w\d.;-]+$/.test(str) === true) {
    return true
  }
  return false
}

/**
 * Implements the add request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.1.
 *
 * Various constants for searching and options can be used from the `search`
 * object in the `@ldapjs/protocol` package. The same constants are exported
 * here as static properties for convenience.
 */
class SearchRequest extends LdapMessage {
  /**
   * Limit searches to the specified {@link baseObject}.
   *
   * @type {number}
   */
  static SCOPE_BASE = search.SCOPE_BASE_OBJECT

  /**
   * Limit searches to the immediate children of the specified
   * {@link baseObject}.
   *
   * @type {number}
   */
  static SCOPE_SINGLE = search.SCOPE_ONE_LEVEL

  /**
   * Limit searches to the {@link baseObject} and all descendents of that
   * object.
   *
   * @type {number}
   */
  static SCOPE_SUBTREE = search.SCOPE_SUBTREE

  /**
   * Do not perform any dereferencing of aliases at all.
   *
   * @type {number}
   */
  static DEREF_ALIASES_NEVER = search.NEVER_DEREF_ALIASES

  /**
   * Dereference aliases in subordinate searches of the {@link baseObject}.
   *
   * @type {number}
   */
  static DEREF_IN_SEARCHING = search.DEREF_IN_SEARCHING

  /**
   * Dereference aliases when finding the base object only.
   *
   * @type {number}
   */
  static DEREF_BASE_OBJECT = search.DEREF_BASE_OBJECT

  /**
   * Dereference aliases when finding the base object and when searching
   * subordinates.
   *
   * @type {number}
   */
  static DEREF_ALWAYS = search.DEREF_ALWAYS

  #baseObject;
  #scope;
  #derefAliases;
  #sizeLimit;
  #timeLimit;
  #typesOnly;
  #filter;
  #attributes = [];

  /**
   * @typedef {LdapMessageOptions} SearchRequestOptions
   * @property {string | import('@ldapjs/dn').DN} baseObject The path to the
   * LDAP object that will serve as the basis of the search.
   * @property {number | string} scope The type of search to be performed.
   * May be one of {@link SCOPE_BASE}, {@link SCOPE_SINGLE},
   * {@link SCOPE_SUBTREE}, `'base'`, `'single'` (`'one'`), or `'subtree'`
   * (`'sub'`).
   * @property {number} derefAliases Indicates if aliases should be dereferenced
   * during searches. May be one of {@link DEREF_ALIASES_NEVER},
   * {@link DEREF_BASE_OBJECT}, {@link DEREF_IN_SEARCHING}, or
   * {@link DEREF_ALWAYS}.
   * @property {number} sizeLimit The number of search results the server should
   * limit the result set to. `0` indicates no desired limit.
   * @property {number} timeLimit The number of seconds the server should work
   * before aborting the search request. `0` indicates no desired limit.
   * @property {boolean} typesOnly Indicates if only attribute names should
   * be returned (`true`), or both names and values should be returned (`false`).
   * @property {string | import('@ldapjs/filter').FilterString} filter The
   * filter to apply when searching.
   * @property {string[]} attributes A set of attribute filtering strings
   * to apply. See the docs for the {@link attributes} setter.
   */

  /**
   * @param {SearchRequestOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_REQ_SEARCH
    super(options)

    this.baseObject = options.baseObject ?? ''
    this.scope = options.scope ?? search.SCOPE_BASE_OBJECT
    this.derefAliases = options.derefAliases ?? search.NEVER_DEREF_ALIASES
    this.sizeLimit = options.sizeLimit ?? 0
    this.timeLimit = options.timeLimit ?? 0
    this.typesOnly = options.typesOnly ?? false
    this.filter = options.filter ?? new filter.PresenceFilter({ attribute: 'objectclass' })
    this.attributes = options.attributes ?? []
  }

  /**
   * Alias of {@link baseObject}.
   *
   * @type {import('@ldapjs/dn').DN}
   */
  get _dn () {
    return this.#baseObject
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'SearchRequest'
  }

  /**
   * The list of attributes to match against.
   *
   * @returns {string[]}
   */
  get attributes () {
    return this.#attributes
  }

  /**
   * Set the list of attributes to match against. Overwrites any existing
   * attributes. The list is a set of spec defined strings. They are not
   * instances of `@ldapjs/attribute`.
   *
   * See:
   * + https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.1.8
   * + https://www.rfc-editor.org/rfc/rfc3673.html
   * + https://www.rfc-editor.org/rfc/rfc4529.html
   *
   * @param {string)[]} attrs
   */
  set attributes (attrs) {
    if (Array.isArray(attrs) === false) {
      throw Error('attributes must be an array of attribute strings')
    }
    const newAttrs = []
    for (const attr of attrs) {
      if (typeof attr === 'string' && isValidAttributeString(attr) === true) {
        newAttrs.push(attr)
      } else {
        throw Error('attribute must be a valid string')
      }
    }
    this.#attributes = newAttrs
  }

  /**
   * The base LDAP object that the search will start from.
   *
   * @returns {import('@ldapjs/dn').DN}
   */
  get baseObject () {
    return this.#baseObject
  }

  /**
   * Define the base LDAP object to start searches from.
   *
   * @param {string | import('@ldapjs/dn').DN} obj
   */
  set baseObject (obj) {
    if (typeof obj === 'string') {
      this.#baseObject = DN.fromString(obj)
    } else if (Object.prototype.toString.call(obj) === '[object LdapDn]') {
      this.#baseObject = obj
    } else {
      throw Error('baseObject must be a DN string or DN instance')
    }
  }

  /**
   * The alias dereferencing method that will be provided to the server.
   * May be one of {@link DEREF_ALIASES_NEVER}, {@link DEREF_IN_SEARCHING},
   * {@link DEREF_BASE_OBJECT},or  {@link DEREF_ALWAYS}.
   *
   * @returns {number}
   */
  get derefAliases () {
    return this.#derefAliases
  }

  /**
   * Define the dereferencing method that will be provided to the server.
   * May be one of {@link DEREF_ALIASES_NEVER}, {@link DEREF_IN_SEARCHING},
   * {@link DEREF_BASE_OBJECT},or  {@link DEREF_ALWAYS}.
   *
   * @param {number} value
   */
  set derefAliases (value) {
    if (Number.isInteger(value) === false) {
      throw Error('derefAliases must be set to an integer')
    }
    this.#derefAliases = value
  }

  /**
   * The filter that will be used in the search.
   *
   * @returns {import('@ldapjs/filter').FilterString}
   */
  get filter () {
    return this.#filter
  }

  /**
   * Define the filter to use in the search.
   *
   * @param {string | import('@ldapjs/filter').FilterString} value
   */
  set filter (value) {
    if (
      typeof value !== 'string' &&
      Object.prototype.toString.call(value) !== '[object FilterString]'
    ) {
      throw Error('filter must be a string or a FilterString instance')
    }

    if (typeof value === 'string') {
      this.#filter = filter.parseString(value)
    } else {
      this.#filter = value
    }
  }

  /**
   * The current search scope value. Can be matched against the exported
   * scope statics.
   *
   * @returns {number}
   *
   * @throws When the scope is set to an unrecognized scope constant.
   */
  get scope () {
    return this.#scope
  }

  /**
   * Define the scope of the search.
   *
   * @param {number|string} value Accepts one of {@link SCOPE_BASE},
   * {@link SCOPE_SINGLE}, or {@link SCOPE_SUBTREE}. Or, as a string, one of
   * "base", "single", "one", "subtree", or "sub".
   *
   * @throws When the provided scope does not resolve to a recognized scope.
   */
  set scope (value) {
    const resolvedScope = scopeAliasToScope(value)
    if (resolvedScope === undefined) {
      throw Error(value + ' is an invalid search scope')
    }
    this.#scope = resolvedScope
  }

  /**
   * The current search scope value as a string name.
   *
   * @returns {string} One of 'base', 'single', or 'subtree'.
   *
   * @throws When the scope is set to an unrecognized scope constant.
   */
  get scopeName () {
    switch (this.#scope) {
      case search.SCOPE_BASE_OBJECT:
        return 'base'
      case search.SCOPE_ONE_LEVEL:
        return 'single'
      case search.SCOPE_SUBTREE:
        return 'subtree'
    }
  }

  /**
   * The number of entries to limit search results to.
   *
   * @returns {number}
   */
  get sizeLimit () {
    return this.#sizeLimit
  }

  /**
   * Define the number of entries to limit search results to.
   *
   * @param {number} value `0` indicates no restriction.
   */
  set sizeLimit (value) {
    if (Number.isInteger(value) === false) {
      throw Error('sizeLimit must be an integer')
    }
    this.#sizeLimit = value
  }

  /**
   * The number of seconds that the search should be limited to for execution.
   * A value of `0` indicates a willingness to wait as long as the server is
   * willing to work.
   *
   * @returns {number}
   */
  get timeLimit () {
    return this.#timeLimit
  }

  /**
   * Define the number of seconds to wait for a search result before the server
   * should abort the search.
   *
   * @param {number} value `0` indicates no time limit restriction.
   */
  set timeLimit (value) {
    if (Number.isInteger(value) === false) {
      throw Error('timeLimit must be an integer')
    }
    this.#timeLimit = value
  }

  /**
   * Indicates if only attribute names (`true`) should be returned, or if both
   * attribute names and attribute values (`false`) should be returned.
   *
   * @returns {boolean}
   */
  get typesOnly () {
    return this.#typesOnly
  }

  /**
   * Define if the search results should include only the attributes names
   * or attribute names and attribute values.
   *
   * @param {boolean} value `false` for both names and values, `true` for
   * names only.
   */
  set typesOnly (value) {
    if (typeof value !== 'boolean') {
      throw Error('typesOnly must be set to a boolean value')
    }
    this.#typesOnly = value
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_REQ_SEARCH)

    ber.writeString(this.#baseObject.toString())
    ber.writeEnumeration(this.#scope)
    ber.writeEnumeration(this.#derefAliases)
    ber.writeInt(this.#sizeLimit)
    ber.writeInt(this.#timeLimit)
    ber.writeBoolean(this.#typesOnly)
    ber.appendBuffer(this.#filter.toBer().buffer)

    ber.startSequence(BerTypes.Sequence | BerTypes.Constructor)
    for (const attr of this.#attributes) {
      ber.writeString(attr)
    }
    ber.endSequence()

    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.baseObject = this.baseObject.toString()
    obj.scope = this.scopeName
    obj.derefAliases = this.derefAliases
    obj.sizeLimit = this.sizeLimit
    obj.timeLimit = this.timeLimit
    obj.typesOnly = this.typesOnly
    obj.filter = this.filter.toString()

    obj.attributes = []
    for (const attr of this.#attributes) {
      obj.attributes.push(attr)
    }

    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_REQ_SEARCH) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const baseObject = ber.readString()
    const scope = ber.readEnumeration()
    const derefAliases = ber.readEnumeration()
    const sizeLimit = ber.readInt()
    const timeLimit = ber.readInt()
    const typesOnly = ber.readBoolean()

    const filterTag = ber.peek()
    const filterBuffer = ber.readRawBuffer(filterTag)
    const parsedFilter = filter.parseBer(new BerReader(filterBuffer))

    const attributes = []
    // Advance to the first attribute sequence in the set
    // of attribute sequences.
    ber.readSequence()
    const endOfAttributesPos = ber.offset + ber.length
    while (ber.offset < endOfAttributesPos) {
      const attribute = ber.readString()
      attributes.push(attribute)
    }

    return {
      protocolOp,
      baseObject,
      scope,
      derefAliases,
      sizeLimit,
      timeLimit,
      typesOnly,
      filter: parsedFilter.toString(),
      attributes
    }
  }
}

module.exports = SearchRequest

},{"../ldap-message":66,"@ldapjs/asn1":2,"@ldapjs/dn":27,"@ldapjs/filter":55,"@ldapjs/protocol":93}],89:[function(require,module,exports){
'use strict'

const LdapResult = require('../ldap-result')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the search result done response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.2.
 */
class SearchResultDone extends LdapResult {
  #uri

  /**
   * @typedef {LdapResultOptions} SearchResultDoneOptions
   * @property {string[]} [uri=[]] The set of reference URIs the message is
   * providing.
   * @property {string[]} [uris] An alias for uri.
   */

  /**
   * @param {SearchResultDoneOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_SEARCH_DONE
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'SearchResultDone'
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    return LdapResult._parseToPojo({
      opCode: operations.LDAP_RES_SEARCH_DONE,
      berReader: ber
    })
  }
}

module.exports = SearchResultDone

},{"../ldap-result":67,"@ldapjs/protocol":93}],90:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const Attribute = require('@ldapjs/attribute')
const { operations } = require('@ldapjs/protocol')
const { DN } = require('@ldapjs/dn')

/**
 * Implements the search result entry message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.2.
 */
class SearchResultEntry extends LdapMessage {
  /**
   * Path to the LDAP object.
   *
   * @type {import('@ldapjs/dn').DN}
   */
  #objectName;

  /**
   * A set of attribute objects.
   *
   * @type {import('@ldapjs/attribute')[]}
   */
  #attributes = [];

  /**
   * @typedef {LdapMessageOptions} SearchResultEntryOptions
   * @property {string | import('@ldapjs/dn').DN} [objectName=''] The path to
   * the LDAP object.
   * @property {import('@ldapjs/attribute')[]} attributes A set of attributes
   * to store at the `entry` path.
   */

  /**
   * @param {SearchResultEntryOptions} [options]
   *
   * @throws When the provided attributes list is invalid or the object name
   * is not a valid LdapDn object or DN string.
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_SEARCH_ENTRY
    super(options)

    this.objectName = options.objectName ?? ''
    this.attributes = options.attributes ?? []
  }

  /**
   * Alias of {@link objectName}.
   *
   * @type {string}
   */
  get _dn () {
    return this.#objectName
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'SearchResultEntry'
  }

  /**
   * Get a copy of the attributes associated with the request.
   *
   * @returns {import('@ldapjs/attribute')[]}
   */
  get attributes () {
    return this.#attributes.slice(0)
  }

  /**
   * Set the attributes to be added to the entry. Replaces any existing
   * attributes.
   *
   * @param {object[] | import('@ldapjs/attribute')[]} attrs
   *
   * @throws If the input is not an array, or any element is not an
   * {@link Attribute} or attribute-like object.
   */
  set attributes (attrs) {
    if (Array.isArray(attrs) === false) {
      throw Error('attrs must be an array')
    }
    const newAttrs = []
    for (const attr of attrs) {
      if (Attribute.isAttribute(attr) === false) {
        throw Error('attr must be an Attribute instance or Attribute-like object')
      }
      if (Object.prototype.toString.call(attr) !== '[object LdapAttribute]') {
        newAttrs.push(new Attribute(attr))
        continue
      }
      newAttrs.push(attr)
    }
    this.#attributes = newAttrs
  }

  /**
   * The path to the LDAP entry that matched the search.
   *
   * @returns {import('@ldapjs/dn').DN}
   */
  get objectName () {
    return this.#objectName
  }

  /**
   * Set the path to the LDAP entry that matched the search.
   *
   * @param {string | import('@ldapjs/dn').DN} value
   *
   * @throws When the input is invalid.
   */
  set objectName (value) {
    if (typeof value === 'string') {
      this.#objectName = DN.fromString(value)
    } else if (Object.prototype.toString.call(value) === '[object LdapDn]') {
      this.#objectName = value
    } else {
      throw Error('objectName must be a DN string or an instance of LdapDn')
    }
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_RES_SEARCH_ENTRY)
    ber.writeString(this.#objectName.toString())
    ber.startSequence()
    for (const attr of this.#attributes) {
      const attrBer = attr.toBer()
      ber.appendBuffer(attrBer.buffer)
    }
    ber.endSequence()
    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.objectName = this.#objectName.toString()
    obj.attributes = []
    for (const attr of this.#attributes) {
      obj.attributes.push(attr.pojo)
    }
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_RES_SEARCH_ENTRY) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const objectName = ber.readString()
    const attributes = []

    // Advance to the first attribute sequence in the set
    // of attribute sequences.
    ber.readSequence()

    const endOfAttributesPos = ber.offset + ber.length
    while (ber.offset < endOfAttributesPos) {
      const attribute = Attribute.fromBer(ber)
      attributes.push(attribute)
    }

    return { protocolOp, objectName, attributes }
  }
}

module.exports = SearchResultEntry

},{"../ldap-message":66,"@ldapjs/attribute":7,"@ldapjs/dn":27,"@ldapjs/protocol":93}],91:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the search result reference response message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.2.
 */
class SearchResultReference extends LdapMessage {
  #uri

  /**
   * @typedef {LdapMessageOptions} SearchResultReferenceOptions
   * @property {string[]} [uri=[]] The set of reference URIs the message is
   * providing.
   * @property {string[]} [uris] An alias for uri.
   */

  /**
   * @param {SearchResultReferenceOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_RES_SEARCH_REF
    super(options)

    this.uri = (options.uri || options.uris) ?? []
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'SearchResultReference'
  }

  /**
   * The list of reference URIs associated with the message.
   *
   * @returns {string[]}
   */
  get uri () {
    return this.#uri.slice(0)
  }

  /**
   * Define the list of reference URIs associated with the message.
   *
   * @param {string[]} value
   *
   * @throws When the value is not an array or contains a non-string element.
   */
  set uri (value) {
    if (
      Array.isArray(value) === false ||
      value.some(v => typeof v !== 'string')
    ) {
      throw Error('uri must be an array of strings')
    }
    this.#uri = value.slice(0)
  }

  /**
   * Alias of {@link uri}.
   *
   * @returns {string[]}
   */
  get uris () {
    return this.uri
  }

  /**
   * Alias of {@link uri} setter.
   *
   * @param {string[]} value
   */
  set uris (value) {
    this.uri = value
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.startSequence(operations.LDAP_RES_SEARCH_REF)

    for (const uri of this.#uri) {
      ber.writeString(uri)
    }

    ber.endSequence()
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    obj.uri = []
    for (const uri of this.#uri) {
      obj.uri.push(uri)
    }
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   *
   * @returns {object}
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_RES_SEARCH_REF) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    const uri = []

    const endOfMessagePos = ber.offset + ber.length
    while (ber.offset < endOfMessagePos) {
      const u = ber.readString()
      uri.push(u)
    }

    return { protocolOp, uri }
  }
}

module.exports = SearchResultReference

},{"../ldap-message":66,"@ldapjs/protocol":93}],92:[function(require,module,exports){
'use strict'

const LdapMessage = require('../ldap-message')
const { operations } = require('@ldapjs/protocol')

/**
 * Implements the unbind request message as described in
 * https://www.rfc-editor.org/rfc/rfc4511.html#section-4.3.
 */
class UnbindRequest extends LdapMessage {
  /**
   * @param {LdapMessageOptions} options
   */
  constructor (options = {}) {
    options.protocolOp = operations.LDAP_REQ_UNBIND
    super(options)
  }

  /**
   * The name of the request type.
   *
   * @type {string}
   */
  get type () {
    return 'UnbindRequest'
  }

  /**
   * Internal use only.
   *
   * @param {import('@ldapjs/asn1').BerWriter} ber
   *
   * @returns {import('@ldapjs/asn1').BerWriter}
   */
  _toBer (ber) {
    ber.writeString('', operations.LDAP_REQ_UNBIND)
    return ber
  }

  /**
   * Internal use only.
   *
   * @param {object}
   *
   * @returns {object}
   */
  _pojo (obj = {}) {
    return obj
  }

  /**
   * Implements the standardized `parseToPojo` method.
   *
   * @see LdapMessage.parseToPojo
   *
   * @param {import('@ldapjs/asn1').BerReader} ber
   */
  static parseToPojo (ber) {
    const protocolOp = ber.readSequence()
    if (protocolOp !== operations.LDAP_REQ_UNBIND) {
      const op = protocolOp.toString(16).padStart(2, '0')
      throw Error(`found wrong protocol operation: 0x${op}`)
    }

    return { protocolOp }
  }
}

module.exports = UnbindRequest

},{"../ldap-message":66,"@ldapjs/protocol":93}],93:[function(require,module,exports){
'use strict'

const core = Object.freeze({
  LDAP_VERSION_3: 0x03,
  LBER_SET: 0x31,
  LDAP_CONTROLS: 0xa0
})

const operations = Object.freeze({
  LDAP_REQ_BIND: 0x60,
  LDAP_REQ_UNBIND: 0x42,
  LDAP_REQ_SEARCH: 0x63,
  LDAP_REQ_MODIFY: 0x66,
  LDAP_REQ_ADD: 0x68,
  LDAP_REQ_DELETE: 0x4a,
  LDAP_REQ_MODRDN: 0x6c,
  LDAP_REQ_COMPARE: 0x6e,
  LDAP_REQ_ABANDON: 0x50,
  LDAP_REQ_EXTENSION: 0x77,

  LDAP_RES_BIND: 0x61,
  LDAP_RES_SEARCH_ENTRY: 0x64,
  LDAP_RES_SEARCH_DONE: 0x65,
  LDAP_RES_SEARCH_REF: 0x73,
  LDAP_RES_SEARCH: 0x65,
  LDAP_RES_MODIFY: 0x67,
  LDAP_RES_ADD: 0x69,
  LDAP_RES_DELETE: 0x6b,
  LDAP_RES_MODRDN: 0x6d,
  LDAP_RES_COMPARE: 0x6f,
  LDAP_RES_EXTENSION: 0x78,
  LDAP_RES_INTERMEDIATE: 0x79,

  // This is really an operation. It's a specific
  // sequence tag. But the referral situation is
  // so specific it makes more sense to put it here.
  LDAP_RES_REFERRAL: 0xa3
})

/**
 * List of LDAP response result codes. See
 * https://web.archive.org/web/20220812122129/https://nawilson.com/ldap-result-code-reference/
 */
const resultCodes = Object.freeze({
  SUCCESS: 0,
  OPERATIONS_ERROR: 1,
  PROTOCOL_ERROR: 2,
  TIME_LIMIT_EXCEEDED: 3,
  SIZE_LIMIT_EXCEEDED: 4,
  COMPARE_FALSE: 5,
  COMPARE_TRUE: 6,
  AUTH_METHOD_NOT_SUPPORTED: 7,
  STRONGER_AUTH_REQUIRED: 8,
  REFERRAL: 10,
  ADMIN_LIMIT_EXCEEDED: 11,
  UNAVAILABLE_CRITICAL_EXTENSION: 12,
  CONFIDENTIALITY_REQUIRED: 13,
  SASL_BIND_IN_PROGRESS: 14,
  NO_SUCH_ATTRIBUTE: 16,
  UNDEFINED_ATTRIBUTE_TYPE: 17,
  INAPPROPRIATE_MATCHING: 18,
  CONSTRAINT_VIOLATION: 19,
  ATTRIBUTE_OR_VALUE_EXISTS: 20,
  INVALID_ATTRIBUTE_SYNTAX: 21,
  NO_SUCH_OBJECT: 32,
  ALIAS_PROBLEM: 33,
  INVALID_DN_SYNTAX: 34,
  IS_LEAF: 35,
  ALIAS_DEREFERENCING_PROBLEM: 36,
  INAPPROPRIATE_AUTHENTICATION: 48,
  INVALID_CREDENTIALS: 49,
  INSUFFICIENT_ACCESS_RIGHTS: 50,
  BUSY: 51,
  UNAVAILABLE: 52,
  UNWILLING_TO_PERFORM: 53,
  LOOP_DETECT: 54,
  SORT_CONTROL_MISSING: 60,
  OFFSET_RANGE_ERROR: 61,
  NAMING_VIOLATION: 64,
  OBJECT_CLASS_VIOLATION: 65,
  NOT_ALLOWED_ON_NON_LEAF: 66,
  NOT_ALLOWED_ON_RDN: 67,
  ENTRY_ALREADY_EXISTS: 68,
  OBJECT_CLASS_MODS_PROHIBITED: 69,
  RESULTS_TOO_LARGE: 70,
  AFFECTS_MULTIPLE_DSAS: 71,
  CONTROL_ERROR: 76,
  OTHER: 80,
  SERVER_DOWN: 81,
  LOCAL_ERROR: 82,
  ENCODING_ERROR: 83,
  DECODING_ERROR: 84,
  TIMEOUT: 85,
  AUTH_UNKNOWN: 86,
  FILTER_ERROR: 87,
  USER_CANCELED: 88,
  PARAM_ERROR: 89,
  NO_MEMORY: 90,
  CONNECT_ERROR: 91,
  NOT_SUPPORTED: 92,
  CONTROL_NOT_FOUND: 93,
  NO_RESULTS_RETURNED: 94,
  MORE_RESULTS_TO_RETURN: 95,
  CLIENT_LOOP: 96,
  REFERRAL_LIMIT_EXCEEDED: 97,
  INVALID_RESPONSE: 100,
  AMBIGUOUS_RESPONSE: 101,
  TLS_NOT_SUPPORTED: 112,
  INTERMEDIATE_RESPONSE: 113,
  UNKNOWN_TYPE: 114,
  CANCELED: 118,
  NO_SUCH_OPERATION: 119,
  TOO_LATE: 120,
  CANNOT_CANCEL: 121,
  ASSERTION_FAILED: 122,
  AUTHORIZATION_DENIED: 123,
  E_SYNC_REFRESH_REQUIRED: 4096,
  NO_OPERATION: 16654
})

/**
 * Value constants and ASN.1 tags as defined in:
 * https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
 */
const search = Object.freeze({
  SCOPE_BASE_OBJECT: 0,
  SCOPE_ONE_LEVEL: 1,
  SCOPE_SUBTREE: 2,

  NEVER_DEREF_ALIASES: 0,
  DEREF_IN_SEARCHING: 1,
  DEREF_BASE_OBJECT: 2,
  DEREF_ALWAYS: 3,

  FILTER_AND: 0xa0,
  FILTER_OR: 0xa1,
  FILTER_NOT: 0xa2,
  FILTER_EQUALITY: 0xa3,
  FILTER_SUBSTRINGS: 0xa4,
  FILTER_GE: 0xa5,
  FILTER_LE: 0xa6,
  FILTER_PRESENT: 0x87,
  FILTER_APPROX: 0xa8,
  FILTER_EXT: 0xa9
})

module.exports = Object.freeze({
  core,
  operations,
  resultCodes,
  search,

  resultCodeToName
})

/**
 * Given an LDAP result code, return the constant name for that code.
 *
 * @param {number} code
 *
 * @returns {string|undefined}
 */
function resultCodeToName (code) {
  for (const [key, value] of Object.entries(resultCodes)) {
    if (value === code) return key
  }
}

},{}],94:[function(require,module,exports){
'use strict'

function noop () { }

const proto = {
  fatal: noop,
  error: noop,
  warn: noop,
  info: noop,
  debug: noop,
  trace: noop
}

Object.defineProperty(module, 'exports', {
  get () {
    return Object.create(proto)
  }
})

},{}],95:[function(require,module,exports){
(function (Buffer,process){(function (){
// Copyright (c) 2012, Mark Cavage. All rights reserved.
// Copyright 2015 Joyent, Inc.

var assert = require('assert');
var Stream = require('stream').Stream;
var util = require('util');


///--- Globals

/* JSSTYLED */
var UUID_REGEXP = /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/;


///--- Internal

function _capitalize(str) {
    return (str.charAt(0).toUpperCase() + str.slice(1));
}

function _toss(name, expected, oper, arg, actual) {
    throw new assert.AssertionError({
        message: util.format('%s (%s) is required', name, expected),
        actual: (actual === undefined) ? typeof (arg) : actual(arg),
        expected: expected,
        operator: oper || '===',
        stackStartFunction: _toss.caller
    });
}

function _getClass(arg) {
    return (Object.prototype.toString.call(arg).slice(8, -1));
}

function noop() {
    // Why even bother with asserts?
}


///--- Exports

var types = {
    bool: {
        check: function (arg) { return typeof (arg) === 'boolean'; }
    },
    func: {
        check: function (arg) { return typeof (arg) === 'function'; }
    },
    string: {
        check: function (arg) { return typeof (arg) === 'string'; }
    },
    object: {
        check: function (arg) {
            return typeof (arg) === 'object' && arg !== null;
        }
    },
    number: {
        check: function (arg) {
            return typeof (arg) === 'number' && !isNaN(arg);
        }
    },
    finite: {
        check: function (arg) {
            return typeof (arg) === 'number' && !isNaN(arg) && isFinite(arg);
        }
    },
    buffer: {
        check: function (arg) { return Buffer.isBuffer(arg); },
        operator: 'Buffer.isBuffer'
    },
    array: {
        check: function (arg) { return Array.isArray(arg); },
        operator: 'Array.isArray'
    },
    stream: {
        check: function (arg) { return arg instanceof Stream; },
        operator: 'instanceof',
        actual: _getClass
    },
    date: {
        check: function (arg) { return arg instanceof Date; },
        operator: 'instanceof',
        actual: _getClass
    },
    regexp: {
        check: function (arg) { return arg instanceof RegExp; },
        operator: 'instanceof',
        actual: _getClass
    },
    uuid: {
        check: function (arg) {
            return typeof (arg) === 'string' && UUID_REGEXP.test(arg);
        },
        operator: 'isUUID'
    }
};

function _setExports(ndebug) {
    var keys = Object.keys(types);
    var out;

    /* re-export standard assert */
    if (process.env.NODE_NDEBUG) {
        out = noop;
    } else {
        out = function (arg, msg) {
            if (!arg) {
                _toss(msg, 'true', arg);
            }
        };
    }

    /* standard checks */
    keys.forEach(function (k) {
        if (ndebug) {
            out[k] = noop;
            return;
        }
        var type = types[k];
        out[k] = function (arg, msg) {
            if (!type.check(arg)) {
                _toss(msg, k, type.operator, arg, type.actual);
            }
        };
    });

    /* optional checks */
    keys.forEach(function (k) {
        var name = 'optional' + _capitalize(k);
        if (ndebug) {
            out[name] = noop;
            return;
        }
        var type = types[k];
        out[name] = function (arg, msg) {
            if (arg === undefined || arg === null) {
                return;
            }
            if (!type.check(arg)) {
                _toss(msg, k, type.operator, arg, type.actual);
            }
        };
    });

    /* arrayOf checks */
    keys.forEach(function (k) {
        var name = 'arrayOf' + _capitalize(k);
        if (ndebug) {
            out[name] = noop;
            return;
        }
        var type = types[k];
        var expected = '[' + k + ']';
        out[name] = function (arg, msg) {
            if (!Array.isArray(arg)) {
                _toss(msg, expected, type.operator, arg, type.actual);
            }
            var i;
            for (i = 0; i < arg.length; i++) {
                if (!type.check(arg[i])) {
                    _toss(msg, expected, type.operator, arg, type.actual);
                }
            }
        };
    });

    /* optionalArrayOf checks */
    keys.forEach(function (k) {
        var name = 'optionalArrayOf' + _capitalize(k);
        if (ndebug) {
            out[name] = noop;
            return;
        }
        var type = types[k];
        var expected = '[' + k + ']';
        out[name] = function (arg, msg) {
            if (arg === undefined || arg === null) {
                return;
            }
            if (!Array.isArray(arg)) {
                _toss(msg, expected, type.operator, arg, type.actual);
            }
            var i;
            for (i = 0; i < arg.length; i++) {
                if (!type.check(arg[i])) {
                    _toss(msg, expected, type.operator, arg, type.actual);
                }
            }
        };
    });

    /* re-export built-in assertions */
    Object.keys(assert).forEach(function (k) {
        if (k === 'AssertionError') {
            out[k] = assert[k];
            return;
        }
        if (ndebug) {
            out[k] = noop;
            return;
        }
        out[k] = assert[k];
    });

    /* export ourselves (for unit tests _only_) */
    out._setExports = _setExports;

    return out;
}

module.exports = _setExports(process.env.NODE_NDEBUG);

}).call(this)}).call(this,{"isBuffer":require("../is-buffer/index.js")},require('_process'))
},{"../is-buffer/index.js":128,"_process":162,"assert":96,"stream":168,"util":190}],96:[function(require,module,exports){
(function (global){(function (){
'use strict';

var objectAssign = require('object-assign');

// compare and isBuffer taken from https://github.com/feross/buffer/blob/680e9e5e488f22aac27599a57dc844a6315928dd/index.js
// original notice:

/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
function compare(a, b) {
  if (a === b) {
    return 0;
  }

  var x = a.length;
  var y = b.length;

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i];
      y = b[i];
      break;
    }
  }

  if (x < y) {
    return -1;
  }
  if (y < x) {
    return 1;
  }
  return 0;
}
function isBuffer(b) {
  if (global.Buffer && typeof global.Buffer.isBuffer === 'function') {
    return global.Buffer.isBuffer(b);
  }
  return !!(b != null && b._isBuffer);
}

// based on node assert, original notice:
// NB: The URL to the CommonJS spec is kept just for tradition.
//     node-assert has evolved a lot since then, both in API and behavior.

// http://wiki.commonjs.org/wiki/Unit_Testing/1.0
//
// THIS IS NOT TESTED NOR LIKELY TO WORK OUTSIDE V8!
//
// Originally from narwhal.js (http://narwhaljs.org)
// Copyright (c) 2009 Thomas Robinson <280north.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

var util = require('util/');
var hasOwn = Object.prototype.hasOwnProperty;
var pSlice = Array.prototype.slice;
var functionsHaveNames = (function () {
  return function foo() {}.name === 'foo';
}());
function pToString (obj) {
  return Object.prototype.toString.call(obj);
}
function isView(arrbuf) {
  if (isBuffer(arrbuf)) {
    return false;
  }
  if (typeof global.ArrayBuffer !== 'function') {
    return false;
  }
  if (typeof ArrayBuffer.isView === 'function') {
    return ArrayBuffer.isView(arrbuf);
  }
  if (!arrbuf) {
    return false;
  }
  if (arrbuf instanceof DataView) {
    return true;
  }
  if (arrbuf.buffer && arrbuf.buffer instanceof ArrayBuffer) {
    return true;
  }
  return false;
}
// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

var regex = /\s*function\s+([^\(\s]*)\s*/;
// based on https://github.com/ljharb/function.prototype.name/blob/adeeeec8bfcc6068b187d7d9fb3d5bb1d3a30899/implementation.js
function getName(func) {
  if (!util.isFunction(func)) {
    return;
  }
  if (functionsHaveNames) {
    return func.name;
  }
  var str = func.toString();
  var match = str.match(regex);
  return match && match[1];
}
assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  if (options.message) {
    this.message = options.message;
    this.generatedMessage = false;
  } else {
    this.message = getMessage(this);
    this.generatedMessage = true;
  }
  var stackStartFunction = options.stackStartFunction || fail;
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, stackStartFunction);
  } else {
    // non v8 browsers so we can have a stacktrace
    var err = new Error();
    if (err.stack) {
      var out = err.stack;

      // try to strip useless frames
      var fn_name = getName(stackStartFunction);
      var idx = out.indexOf('\n' + fn_name);
      if (idx >= 0) {
        // once we have located the function frame
        // we need to strip out everything before it (and its line)
        var next_line = out.indexOf('\n', idx + 1);
        out = out.substring(next_line + 1);
      }

      this.stack = out;
    }
  }
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function truncate(s, n) {
  if (typeof s === 'string') {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}
function inspect(something) {
  if (functionsHaveNames || !util.isFunction(something)) {
    return util.inspect(something);
  }
  var rawname = getName(something);
  var name = rawname ? ': ' + rawname : '';
  return '[Function' +  name + ']';
}
function getMessage(self) {
  return truncate(inspect(self.actual), 128) + ' ' +
         self.operator + ' ' +
         truncate(inspect(self.expected), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

assert.deepStrictEqual = function deepStrictEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'deepStrictEqual', assert.deepStrictEqual);
  }
};

function _deepEqual(actual, expected, strict, memos) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;
  } else if (isBuffer(actual) && isBuffer(expected)) {
    return compare(actual, expected) === 0;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if ((actual === null || typeof actual !== 'object') &&
             (expected === null || typeof expected !== 'object')) {
    return strict ? actual === expected : actual == expected;

  // If both values are instances of typed arrays, wrap their underlying
  // ArrayBuffers in a Buffer each to increase performance
  // This optimization requires the arrays to have the same type as checked by
  // Object.prototype.toString (aka pToString). Never perform binary
  // comparisons for Float*Arrays, though, since e.g. +0 === -0 but their
  // bit patterns are not identical.
  } else if (isView(actual) && isView(expected) &&
             pToString(actual) === pToString(expected) &&
             !(actual instanceof Float32Array ||
               actual instanceof Float64Array)) {
    return compare(new Uint8Array(actual.buffer),
                   new Uint8Array(expected.buffer)) === 0;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else if (isBuffer(actual) !== isBuffer(expected)) {
    return false;
  } else {
    memos = memos || {actual: [], expected: []};

    var actualIndex = memos.actual.indexOf(actual);
    if (actualIndex !== -1) {
      if (actualIndex === memos.expected.indexOf(expected)) {
        return true;
      }
    }

    memos.actual.push(actual);
    memos.expected.push(expected);

    return objEquiv(actual, expected, strict, memos);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b, strict, actualVisitedObjects) {
  if (a === null || a === undefined || b === null || b === undefined)
    return false;
  // if one is a primitive, the other must be same
  if (util.isPrimitive(a) || util.isPrimitive(b))
    return a === b;
  if (strict && Object.getPrototypeOf(a) !== Object.getPrototypeOf(b))
    return false;
  var aIsArgs = isArguments(a);
  var bIsArgs = isArguments(b);
  if ((aIsArgs && !bIsArgs) || (!aIsArgs && bIsArgs))
    return false;
  if (aIsArgs) {
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b, strict);
  }
  var ka = objectKeys(a);
  var kb = objectKeys(b);
  var key, i;
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length !== kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] !== kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key], strict, actualVisitedObjects))
      return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

assert.notDeepStrictEqual = notDeepStrictEqual;
function notDeepStrictEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'notDeepStrictEqual', notDeepStrictEqual);
  }
}


// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  }

  try {
    if (actual instanceof expected) {
      return true;
    }
  } catch (e) {
    // Ignore.  The instanceof check doesn't work for arrow functions.
  }

  if (Error.isPrototypeOf(expected)) {
    return false;
  }

  return expected.call({}, actual) === true;
}

function _tryBlock(block) {
  var error;
  try {
    block();
  } catch (e) {
    error = e;
  }
  return error;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (typeof block !== 'function') {
    throw new TypeError('"block" argument must be a function');
  }

  if (typeof expected === 'string') {
    message = expected;
    expected = null;
  }

  actual = _tryBlock(block);

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  var userProvidedMessage = typeof message === 'string';
  var isUnwantedException = !shouldThrow && util.isError(actual);
  var isUnexpectedException = !shouldThrow && actual && !expected;

  if ((isUnwantedException &&
      userProvidedMessage &&
      expectedException(actual, expected)) ||
      isUnexpectedException) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws(true, block, error, message);
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/error, /*optional*/message) {
  _throws(false, block, error, message);
};

assert.ifError = function(err) { if (err) throw err; };

// Expose a strict only variant of assert
function strict(value, message) {
  if (!value) fail(value, true, message, '==', strict);
}
assert.strict = objectAssign(strict, assert, {
  equal: assert.strictEqual,
  deepEqual: assert.deepStrictEqual,
  notEqual: assert.notStrictEqual,
  notDeepEqual: assert.notDeepStrictEqual
});
assert.strict.strict = assert.strict;

var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) {
    if (hasOwn.call(obj, key)) keys.push(key);
  }
  return keys;
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"object-assign":156,"util/":99}],97:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],98:[function(require,module,exports){
module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}
},{}],99:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = require('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = require('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./support/isBuffer":98,"_process":162,"inherits":97}],100:[function(require,module,exports){
(function (global){(function (){
'use strict';

var possibleNames = [
	'BigInt64Array',
	'BigUint64Array',
	'Float32Array',
	'Float64Array',
	'Int16Array',
	'Int32Array',
	'Int8Array',
	'Uint16Array',
	'Uint32Array',
	'Uint8Array',
	'Uint8ClampedArray'
];

var g = typeof globalThis === 'undefined' ? global : globalThis;

module.exports = function availableTypedArrays() {
	var out = [];
	for (var i = 0; i < possibleNames.length; i++) {
		if (typeof g[possibleNames[i]] === 'function') {
			out[out.length] = possibleNames[i];
		}
	}
	return out;
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],101:[function(require,module,exports){
//      Copyright (c) 2012 Mathieu Turcotte
//      Licensed under the MIT license.

var Backoff = require('./lib/backoff');
var ExponentialBackoffStrategy = require('./lib/strategy/exponential');
var FibonacciBackoffStrategy = require('./lib/strategy/fibonacci');
var FunctionCall = require('./lib/function_call.js');

module.exports.Backoff = Backoff;
module.exports.FunctionCall = FunctionCall;
module.exports.FibonacciStrategy = FibonacciBackoffStrategy;
module.exports.ExponentialStrategy = ExponentialBackoffStrategy;

// Constructs a Fibonacci backoff.
module.exports.fibonacci = function(options) {
    return new Backoff(new FibonacciBackoffStrategy(options));
};

// Constructs an exponential backoff.
module.exports.exponential = function(options) {
    return new Backoff(new ExponentialBackoffStrategy(options));
};

// Constructs a FunctionCall for the given function and arguments.
module.exports.call = function(fn, vargs, callback) {
    var args = Array.prototype.slice.call(arguments);
    fn = args[0];
    vargs = args.slice(1, args.length - 1);
    callback = args[args.length - 1];
    return new FunctionCall(fn, vargs, callback);
};

},{"./lib/backoff":102,"./lib/function_call.js":103,"./lib/strategy/exponential":104,"./lib/strategy/fibonacci":105}],102:[function(require,module,exports){
//      Copyright (c) 2012 Mathieu Turcotte
//      Licensed under the MIT license.

var events = require('events');
var precond = require('precond');
var util = require('util');

// A class to hold the state of a backoff operation. Accepts a backoff strategy
// to generate the backoff delays.
function Backoff(backoffStrategy) {
    events.EventEmitter.call(this);

    this.backoffStrategy_ = backoffStrategy;
    this.maxNumberOfRetry_ = -1;
    this.backoffNumber_ = 0;
    this.backoffDelay_ = 0;
    this.timeoutID_ = -1;

    this.handlers = {
        backoff: this.onBackoff_.bind(this)
    };
}
util.inherits(Backoff, events.EventEmitter);

// Sets a limit, greater than 0, on the maximum number of backoffs. A 'fail'
// event will be emitted when the limit is reached.
Backoff.prototype.failAfter = function(maxNumberOfRetry) {
    precond.checkArgument(maxNumberOfRetry > 0,
        'Expected a maximum number of retry greater than 0 but got %s.',
        maxNumberOfRetry);

    this.maxNumberOfRetry_ = maxNumberOfRetry;
};

// Starts a backoff operation. Accepts an optional parameter to let the
// listeners know why the backoff operation was started.
Backoff.prototype.backoff = function(err) {
    precond.checkState(this.timeoutID_ === -1, 'Backoff in progress.');

    if (this.backoffNumber_ === this.maxNumberOfRetry_) {
        this.emit('fail', err);
        this.reset();
    } else {
        this.backoffDelay_ = this.backoffStrategy_.next();
        this.timeoutID_ = setTimeout(this.handlers.backoff, this.backoffDelay_);
        this.emit('backoff', this.backoffNumber_, this.backoffDelay_, err);
    }
};

// Handles the backoff timeout completion.
Backoff.prototype.onBackoff_ = function() {
    this.timeoutID_ = -1;
    this.emit('ready', this.backoffNumber_, this.backoffDelay_);
    this.backoffNumber_++;
};

// Stops any backoff operation and resets the backoff delay to its inital value.
Backoff.prototype.reset = function() {
    this.backoffNumber_ = 0;
    this.backoffStrategy_.reset();
    clearTimeout(this.timeoutID_);
    this.timeoutID_ = -1;
};

module.exports = Backoff;

},{"events":114,"precond":158,"util":190}],103:[function(require,module,exports){
//      Copyright (c) 2012 Mathieu Turcotte
//      Licensed under the MIT license.

var events = require('events');
var precond = require('precond');
var util = require('util');

var Backoff = require('./backoff');
var FibonacciBackoffStrategy = require('./strategy/fibonacci');

// Wraps a function to be called in a backoff loop.
function FunctionCall(fn, args, callback) {
    events.EventEmitter.call(this);

    precond.checkIsFunction(fn, 'Expected fn to be a function.');
    precond.checkIsArray(args, 'Expected args to be an array.');
    precond.checkIsFunction(callback, 'Expected callback to be a function.');

    this.function_ = fn;
    this.arguments_ = args;
    this.callback_ = callback;
    this.lastResult_ = [];
    this.numRetries_ = 0;

    this.backoff_ = null;
    this.strategy_ = null;
    this.failAfter_ = -1;
    this.retryPredicate_ = FunctionCall.DEFAULT_RETRY_PREDICATE_;

    this.state_ = FunctionCall.State_.PENDING;
}
util.inherits(FunctionCall, events.EventEmitter);

// States in which the call can be.
FunctionCall.State_ = {
    // Call isn't started yet.
    PENDING: 0,
    // Call is in progress.
    RUNNING: 1,
    // Call completed successfully which means that either the wrapped function
    // returned successfully or the maximal number of backoffs was reached.
    COMPLETED: 2,
    // The call was aborted.
    ABORTED: 3
};

// The default retry predicate which considers any error as retriable.
FunctionCall.DEFAULT_RETRY_PREDICATE_ = function(err) {
  return true;
};

// Checks whether the call is pending.
FunctionCall.prototype.isPending = function() {
    return this.state_ == FunctionCall.State_.PENDING;
};

// Checks whether the call is in progress.
FunctionCall.prototype.isRunning = function() {
    return this.state_ == FunctionCall.State_.RUNNING;
};

// Checks whether the call is completed.
FunctionCall.prototype.isCompleted = function() {
    return this.state_ == FunctionCall.State_.COMPLETED;
};

// Checks whether the call is aborted.
FunctionCall.prototype.isAborted = function() {
    return this.state_ == FunctionCall.State_.ABORTED;
};

// Sets the backoff strategy to use. Can only be called before the call is
// started otherwise an exception will be thrown.
FunctionCall.prototype.setStrategy = function(strategy) {
    precond.checkState(this.isPending(), 'FunctionCall in progress.');
    this.strategy_ = strategy;
    return this; // Return this for chaining.
};

// Sets the predicate which will be used to determine whether the errors
// returned from the wrapped function should be retried or not, e.g. a
// network error would be retriable while a type error would stop the
// function call.
FunctionCall.prototype.retryIf = function(retryPredicate) {
    precond.checkState(this.isPending(), 'FunctionCall in progress.');
    this.retryPredicate_ = retryPredicate;
    return this;
};

// Returns all intermediary results returned by the wrapped function since
// the initial call.
FunctionCall.prototype.getLastResult = function() {
    return this.lastResult_.concat();
};

// Returns the number of times the wrapped function call was retried.
FunctionCall.prototype.getNumRetries = function() {
    return this.numRetries_;
};

// Sets the backoff limit.
FunctionCall.prototype.failAfter = function(maxNumberOfRetry) {
    precond.checkState(this.isPending(), 'FunctionCall in progress.');
    this.failAfter_ = maxNumberOfRetry;
    return this; // Return this for chaining.
};

// Aborts the call.
FunctionCall.prototype.abort = function() {
    if (this.isCompleted() || this.isAborted()) {
      return;
    }

    if (this.isRunning()) {
        this.backoff_.reset();
    }

    this.state_ = FunctionCall.State_.ABORTED;
    this.lastResult_ = [new Error('Backoff aborted.')];
    this.emit('abort');
    this.doCallback_();
};

// Initiates the call to the wrapped function. Accepts an optional factory
// function used to create the backoff instance; used when testing.
FunctionCall.prototype.start = function(backoffFactory) {
    precond.checkState(!this.isAborted(), 'FunctionCall is aborted.');
    precond.checkState(this.isPending(), 'FunctionCall already started.');

    var strategy = this.strategy_ || new FibonacciBackoffStrategy();

    this.backoff_ = backoffFactory ?
        backoffFactory(strategy) :
        new Backoff(strategy);

    this.backoff_.on('ready', this.doCall_.bind(this, true /* isRetry */));
    this.backoff_.on('fail', this.doCallback_.bind(this));
    this.backoff_.on('backoff', this.handleBackoff_.bind(this));

    if (this.failAfter_ > 0) {
        this.backoff_.failAfter(this.failAfter_);
    }

    this.state_ = FunctionCall.State_.RUNNING;
    this.doCall_(false /* isRetry */);
};

// Calls the wrapped function.
FunctionCall.prototype.doCall_ = function(isRetry) {
    if (isRetry) {
        this.numRetries_++;
    }
    var eventArgs = ['call'].concat(this.arguments_);
    events.EventEmitter.prototype.emit.apply(this, eventArgs);
    var callback = this.handleFunctionCallback_.bind(this);
    this.function_.apply(null, this.arguments_.concat(callback));
};

// Calls the wrapped function's callback with the last result returned by the
// wrapped function.
FunctionCall.prototype.doCallback_ = function() {
    this.callback_.apply(null, this.lastResult_);
};

// Handles wrapped function's completion. This method acts as a replacement
// for the original callback function.
FunctionCall.prototype.handleFunctionCallback_ = function() {
    if (this.isAborted()) {
        return;
    }

    var args = Array.prototype.slice.call(arguments);
    this.lastResult_ = args; // Save last callback arguments.
    events.EventEmitter.prototype.emit.apply(this, ['callback'].concat(args));

    var err = args[0];
    if (err && this.retryPredicate_(err)) {
        this.backoff_.backoff(err);
    } else {
        this.state_ = FunctionCall.State_.COMPLETED;
        this.doCallback_();
    }
};

// Handles the backoff event by reemitting it.
FunctionCall.prototype.handleBackoff_ = function(number, delay, err) {
    this.emit('backoff', number, delay, err);
};

module.exports = FunctionCall;

},{"./backoff":102,"./strategy/fibonacci":105,"events":114,"precond":158,"util":190}],104:[function(require,module,exports){
//      Copyright (c) 2012 Mathieu Turcotte
//      Licensed under the MIT license.

var util = require('util');
var precond = require('precond');

var BackoffStrategy = require('./strategy');

// Exponential backoff strategy.
function ExponentialBackoffStrategy(options) {
    BackoffStrategy.call(this, options);
    this.backoffDelay_ = 0;
    this.nextBackoffDelay_ = this.getInitialDelay();
    this.factor_ = ExponentialBackoffStrategy.DEFAULT_FACTOR;

    if (options && options.factor !== undefined) {
        precond.checkArgument(options.factor > 1,
            'Exponential factor should be greater than 1 but got %s.',
            options.factor);
        this.factor_ = options.factor;
    }
}
util.inherits(ExponentialBackoffStrategy, BackoffStrategy);

// Default multiplication factor used to compute the next backoff delay from
// the current one. The value can be overridden by passing a custom factor as
// part of the options.
ExponentialBackoffStrategy.DEFAULT_FACTOR = 2;

ExponentialBackoffStrategy.prototype.next_ = function() {
    this.backoffDelay_ = Math.min(this.nextBackoffDelay_, this.getMaxDelay());
    this.nextBackoffDelay_ = this.backoffDelay_ * this.factor_;
    return this.backoffDelay_;
};

ExponentialBackoffStrategy.prototype.reset_ = function() {
    this.backoffDelay_ = 0;
    this.nextBackoffDelay_ = this.getInitialDelay();
};

module.exports = ExponentialBackoffStrategy;

},{"./strategy":106,"precond":158,"util":190}],105:[function(require,module,exports){
//      Copyright (c) 2012 Mathieu Turcotte
//      Licensed under the MIT license.

var util = require('util');

var BackoffStrategy = require('./strategy');

// Fibonacci backoff strategy.
function FibonacciBackoffStrategy(options) {
    BackoffStrategy.call(this, options);
    this.backoffDelay_ = 0;
    this.nextBackoffDelay_ = this.getInitialDelay();
}
util.inherits(FibonacciBackoffStrategy, BackoffStrategy);

FibonacciBackoffStrategy.prototype.next_ = function() {
    var backoffDelay = Math.min(this.nextBackoffDelay_, this.getMaxDelay());
    this.nextBackoffDelay_ += this.backoffDelay_;
    this.backoffDelay_ = backoffDelay;
    return backoffDelay;
};

FibonacciBackoffStrategy.prototype.reset_ = function() {
    this.nextBackoffDelay_ = this.getInitialDelay();
    this.backoffDelay_ = 0;
};

module.exports = FibonacciBackoffStrategy;

},{"./strategy":106,"util":190}],106:[function(require,module,exports){
//      Copyright (c) 2012 Mathieu Turcotte
//      Licensed under the MIT license.

var events = require('events');
var util = require('util');

function isDef(value) {
    return value !== undefined && value !== null;
}

// Abstract class defining the skeleton for the backoff strategies. Accepts an
// object holding the options for the backoff strategy:
//
//  * `randomisationFactor`: The randomisation factor which must be between 0
//     and 1 where 1 equates to a randomization factor of 100% and 0 to no
//     randomization.
//  * `initialDelay`: The backoff initial delay in milliseconds.
//  * `maxDelay`: The backoff maximal delay in milliseconds.
function BackoffStrategy(options) {
    options = options || {};

    if (isDef(options.initialDelay) && options.initialDelay < 1) {
        throw new Error('The initial timeout must be greater than 0.');
    } else if (isDef(options.maxDelay) && options.maxDelay < 1) {
        throw new Error('The maximal timeout must be greater than 0.');
    }

    this.initialDelay_ = options.initialDelay || 100;
    this.maxDelay_ = options.maxDelay || 10000;

    if (this.maxDelay_ <= this.initialDelay_) {
        throw new Error('The maximal backoff delay must be ' +
                        'greater than the initial backoff delay.');
    }

    if (isDef(options.randomisationFactor) &&
        (options.randomisationFactor < 0 || options.randomisationFactor > 1)) {
        throw new Error('The randomisation factor must be between 0 and 1.');
    }

    this.randomisationFactor_ = options.randomisationFactor || 0;
}

// Gets the maximal backoff delay.
BackoffStrategy.prototype.getMaxDelay = function() {
    return this.maxDelay_;
};

// Gets the initial backoff delay.
BackoffStrategy.prototype.getInitialDelay = function() {
    return this.initialDelay_;
};

// Template method that computes and returns the next backoff delay in
// milliseconds.
BackoffStrategy.prototype.next = function() {
    var backoffDelay = this.next_();
    var randomisationMultiple = 1 + Math.random() * this.randomisationFactor_;
    var randomizedDelay = Math.round(backoffDelay * randomisationMultiple);
    return randomizedDelay;
};

// Computes and returns the next backoff delay. Intended to be overridden by
// subclasses.
BackoffStrategy.prototype.next_ = function() {
    throw new Error('BackoffStrategy.next_() unimplemented.');
};

// Template method that resets the backoff delay to its initial value.
BackoffStrategy.prototype.reset = function() {
    this.reset_();
};

// Resets the backoff delay to its initial value. Intended to be overridden by
// subclasses.
BackoffStrategy.prototype.reset_ = function() {
    throw new Error('BackoffStrategy.reset_() unimplemented.');
};

module.exports = BackoffStrategy;

},{"events":114,"util":190}],107:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],108:[function(require,module,exports){

},{}],109:[function(require,module,exports){
arguments[4][108][0].apply(exports,arguments)
},{"dup":108}],110:[function(require,module,exports){
(function (Buffer){(function (){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"base64-js":107,"buffer":110,"ieee754":125}],111:[function(require,module,exports){
'use strict';

var GetIntrinsic = require('get-intrinsic');

var callBind = require('./');

var $indexOf = callBind(GetIntrinsic('String.prototype.indexOf'));

module.exports = function callBoundIntrinsic(name, allowMissing) {
	var intrinsic = GetIntrinsic(name, !!allowMissing);
	if (typeof intrinsic === 'function' && $indexOf(name, '.prototype.') > -1) {
		return callBind(intrinsic);
	}
	return intrinsic;
};

},{"./":112,"get-intrinsic":119}],112:[function(require,module,exports){
'use strict';

var bind = require('function-bind');
var GetIntrinsic = require('get-intrinsic');

var $apply = GetIntrinsic('%Function.prototype.apply%');
var $call = GetIntrinsic('%Function.prototype.call%');
var $reflectApply = GetIntrinsic('%Reflect.apply%', true) || bind.call($call, $apply);

var $gOPD = GetIntrinsic('%Object.getOwnPropertyDescriptor%', true);
var $defineProperty = GetIntrinsic('%Object.defineProperty%', true);
var $max = GetIntrinsic('%Math.max%');

if ($defineProperty) {
	try {
		$defineProperty({}, 'a', { value: 1 });
	} catch (e) {
		// IE 8 has a broken defineProperty
		$defineProperty = null;
	}
}

module.exports = function callBind(originalFunction) {
	var func = $reflectApply(bind, $call, arguments);
	if ($gOPD && $defineProperty) {
		var desc = $gOPD(func, 'length');
		if (desc.configurable) {
			// original length, plus the receiver, minus any additional arguments (after the receiver)
			$defineProperty(
				func,
				'length',
				{ value: 1 + $max(0, originalFunction.length - (arguments.length - 1)) }
			);
		}
	}
	return func;
};

var applyBind = function applyBind() {
	return $reflectApply(bind, $apply, arguments);
};

if ($defineProperty) {
	$defineProperty(module.exports, 'apply', { value: applyBind });
} else {
	module.exports.apply = applyBind;
}

},{"function-bind":118,"get-intrinsic":119}],113:[function(require,module,exports){
(function (Buffer){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.

function isArray(arg) {
  if (Array.isArray) {
    return Array.isArray(arg);
  }
  return objectToString(arg) === '[object Array]';
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = Buffer.isBuffer;

function objectToString(o) {
  return Object.prototype.toString.call(o);
}

}).call(this)}).call(this,{"isBuffer":require("../../is-buffer/index.js")})
},{"../../is-buffer/index.js":128}],114:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var R = typeof Reflect === 'object' ? Reflect : null
var ReflectApply = R && typeof R.apply === 'function'
  ? R.apply
  : function ReflectApply(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  }

var ReflectOwnKeys
if (R && typeof R.ownKeys === 'function') {
  ReflectOwnKeys = R.ownKeys
} else if (Object.getOwnPropertySymbols) {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target)
      .concat(Object.getOwnPropertySymbols(target));
  };
} else {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target);
  };
}

function ProcessEmitWarning(warning) {
  if (console && console.warn) console.warn(warning);
}

var NumberIsNaN = Number.isNaN || function NumberIsNaN(value) {
  return value !== value;
}

function EventEmitter() {
  EventEmitter.init.call(this);
}
module.exports = EventEmitter;
module.exports.once = once;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._eventsCount = 0;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
  }
}

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return defaultMaxListeners;
  },
  set: function(arg) {
    if (typeof arg !== 'number' || arg < 0 || NumberIsNaN(arg)) {
      throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + '.');
    }
    defaultMaxListeners = arg;
  }
});

EventEmitter.init = function() {

  if (this._events === undefined ||
      this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
};

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || NumberIsNaN(n)) {
    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + '.');
  }
  this._maxListeners = n;
  return this;
};

function _getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return _getMaxListeners(this);
};

EventEmitter.prototype.emit = function emit(type) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  var doError = (type === 'error');

  var events = this._events;
  if (events !== undefined)
    doError = (doError && events.error === undefined);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    var er;
    if (args.length > 0)
      er = args[0];
    if (er instanceof Error) {
      // Note: The comments on the `throw` lines are intentional, they show
      // up in Node's output if this results in an unhandled exception.
      throw er; // Unhandled 'error' event
    }
    // At least give some kind of context to the user
    var err = new Error('Unhandled error.' + (er ? ' (' + er.message + ')' : ''));
    err.context = er;
    throw err; // Unhandled 'error' event
  }

  var handler = events[type];

  if (handler === undefined)
    return false;

  if (typeof handler === 'function') {
    ReflectApply(handler, this, args);
  } else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      ReflectApply(listeners[i], this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener !== undefined) {
      target.emit('newListener', type,
                  listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (existing === undefined) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
        prepend ? [listener, existing] : [existing, listener];
      // If we've already got an array, just append.
    } else if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }

    // Check for listener leak
    m = _getMaxListeners(target);
    if (m > 0 && existing.length > m && !existing.warned) {
      existing.warned = true;
      // No error code for this since it is a Warning
      // eslint-disable-next-line no-restricted-syntax
      var w = new Error('Possible EventEmitter memory leak detected. ' +
                          existing.length + ' ' + String(type) + ' listeners ' +
                          'added. Use emitter.setMaxListeners() to ' +
                          'increase limit');
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = type;
      w.count = existing.length;
      ProcessEmitWarning(w);
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    if (arguments.length === 0)
      return this.listener.call(this.target);
    return this.listener.apply(this.target, arguments);
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = onceWrapper.bind(state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  checkListener(listener);
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      checkListener(listener);
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      checkListener(listener);

      events = this._events;
      if (events === undefined)
        return this;

      list = events[type];
      if (list === undefined)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = Object.create(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else {
          spliceOne(list, position);
        }

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener !== undefined)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (events === undefined)
        return this;

      // not listening for removeListener, no need to emit
      if (events.removeListener === undefined) {
        if (arguments.length === 0) {
          this._events = Object.create(null);
          this._eventsCount = 0;
        } else if (events[type] !== undefined) {
          if (--this._eventsCount === 0)
            this._events = Object.create(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = Object.keys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = Object.create(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners !== undefined) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (events === undefined)
    return [];

  var evlistener = events[type];
  if (evlistener === undefined)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ?
    unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events !== undefined) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener !== undefined) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
};

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function spliceOne(list, index) {
  for (; index + 1 < list.length; index++)
    list[index] = list[index + 1];
  list.pop();
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function once(emitter, name) {
  return new Promise(function (resolve, reject) {
    function errorListener(err) {
      emitter.removeListener(name, resolver);
      reject(err);
    }

    function resolver() {
      if (typeof emitter.removeListener === 'function') {
        emitter.removeListener('error', errorListener);
      }
      resolve([].slice.call(arguments));
    };

    eventTargetAgnosticAddListener(emitter, name, resolver, { once: true });
    if (name !== 'error') {
      addErrorHandlerIfEventEmitter(emitter, errorListener, { once: true });
    }
  });
}

function addErrorHandlerIfEventEmitter(emitter, handler, flags) {
  if (typeof emitter.on === 'function') {
    eventTargetAgnosticAddListener(emitter, 'error', handler, flags);
  }
}

function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
  if (typeof emitter.on === 'function') {
    if (flags.once) {
      emitter.once(name, listener);
    } else {
      emitter.on(name, listener);
    }
  } else if (typeof emitter.addEventListener === 'function') {
    // EventTarget does not have `error` event semantics like Node
    // EventEmitters, we do not listen for `error` events here.
    emitter.addEventListener(name, function wrapListener(arg) {
      // IE does not have builtin `{ once: true }` support so we
      // have to do it manually.
      if (flags.once) {
        emitter.removeEventListener(name, wrapListener);
      }
      listener(arg);
    });
  } else {
    throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof emitter);
  }
}

},{}],115:[function(require,module,exports){
(function (process){(function (){
/*
 * extsprintf.js: extended POSIX-style sprintf
 */

var mod_assert = require('assert');
var mod_util = require('util');

/*
 * Public interface
 */
exports.sprintf = jsSprintf;
exports.printf = jsPrintf;
exports.fprintf = jsFprintf;

/*
 * Stripped down version of s[n]printf(3c).  We make a best effort to throw an
 * exception when given a format string we don't understand, rather than
 * ignoring it, so that we won't break existing programs if/when we go implement
 * the rest of this.
 *
 * This implementation currently supports specifying
 *	- field alignment ('-' flag),
 * 	- zero-pad ('0' flag)
 *	- always show numeric sign ('+' flag),
 *	- field width
 *	- conversions for strings, decimal integers, and floats (numbers).
 *	- argument size specifiers.  These are all accepted but ignored, since
 *	  Javascript has no notion of the physical size of an argument.
 *
 * Everything else is currently unsupported, most notably precision, unsigned
 * numbers, non-decimal numbers, and characters.
 */
function jsSprintf(ofmt)
{
	var regex = [
	    '([^%]*)',				/* normal text */
	    '%',				/* start of format */
	    '([\'\\-+ #0]*?)',			/* flags (optional) */
	    '([1-9]\\d*)?',			/* width (optional) */
	    '(\\.([1-9]\\d*))?',		/* precision (optional) */
	    '[lhjztL]*?',			/* length mods (ignored) */
	    '([diouxXfFeEgGaAcCsSp%jr])'	/* conversion */
	].join('');

	var re = new RegExp(regex);

	/* variadic arguments used to fill in conversion specifiers */
	var args = Array.prototype.slice.call(arguments, 1);
	/* remaining format string */
	var fmt = ofmt;

	/* components of the current conversion specifier */
	var flags, width, precision, conversion;
	var left, pad, sign, arg, match;

	/* return value */
	var ret = '';

	/* current variadic argument (1-based) */
	var argn = 1;
	/* 0-based position in the format string that we've read */
	var posn = 0;
	/* 1-based position in the format string of the current conversion */
	var convposn;
	/* current conversion specifier */
	var curconv;

	mod_assert.equal('string', typeof (fmt),
	    'first argument must be a format string');

	while ((match = re.exec(fmt)) !== null) {
		ret += match[1];
		fmt = fmt.substring(match[0].length);

		/*
		 * Update flags related to the current conversion specifier's
		 * position so that we can report clear error messages.
		 */
		curconv = match[0].substring(match[1].length);
		convposn = posn + match[1].length + 1;
		posn += match[0].length;

		flags = match[2] || '';
		width = match[3] || 0;
		precision = match[4] || '';
		conversion = match[6];
		left = false;
		sign = false;
		pad = ' ';

		if (conversion == '%') {
			ret += '%';
			continue;
		}

		if (args.length === 0) {
			throw (jsError(ofmt, convposn, curconv,
			    'has no matching argument ' +
			    '(too few arguments passed)'));
		}

		arg = args.shift();
		argn++;

		if (flags.match(/[\' #]/)) {
			throw (jsError(ofmt, convposn, curconv,
			    'uses unsupported flags'));
		}

		if (precision.length > 0) {
			throw (jsError(ofmt, convposn, curconv,
			    'uses non-zero precision (not supported)'));
		}

		if (flags.match(/-/))
			left = true;

		if (flags.match(/0/))
			pad = '0';

		if (flags.match(/\+/))
			sign = true;

		switch (conversion) {
		case 's':
			if (arg === undefined || arg === null) {
				throw (jsError(ofmt, convposn, curconv,
				    'attempted to print undefined or null ' +
				    'as a string (argument ' + argn + ' to ' +
				    'sprintf)'));
			}
			ret += doPad(pad, width, left, arg.toString());
			break;

		case 'd':
			arg = Math.floor(arg);
			/*jsl:fallthru*/
		case 'f':
			sign = sign && arg > 0 ? '+' : '';
			ret += sign + doPad(pad, width, left,
			    arg.toString());
			break;

		case 'x':
			ret += doPad(pad, width, left, arg.toString(16));
			break;

		case 'j': /* non-standard */
			if (width === 0)
				width = 10;
			ret += mod_util.inspect(arg, false, width);
			break;

		case 'r': /* non-standard */
			ret += dumpException(arg);
			break;

		default:
			throw (jsError(ofmt, convposn, curconv,
			    'is not supported'));
		}
	}

	ret += fmt;
	return (ret);
}

function jsError(fmtstr, convposn, curconv, reason) {
	mod_assert.equal(typeof (fmtstr), 'string');
	mod_assert.equal(typeof (curconv), 'string');
	mod_assert.equal(typeof (convposn), 'number');
	mod_assert.equal(typeof (reason), 'string');
	return (new Error('format string "' + fmtstr +
	    '": conversion specifier "' + curconv + '" at character ' +
	    convposn + ' ' + reason));
}

function jsPrintf() {
	var args = Array.prototype.slice.call(arguments);
	args.unshift(process.stdout);
	jsFprintf.apply(null, args);
}

function jsFprintf(stream) {
	var args = Array.prototype.slice.call(arguments, 1);
	return (stream.write(jsSprintf.apply(this, args)));
}

function doPad(chr, width, left, str)
{
	var ret = str;

	while (ret.length < width) {
		if (left)
			ret += chr;
		else
			ret = chr + ret;
	}

	return (ret);
}

/*
 * This function dumps long stack traces for exceptions having a cause() method.
 * See node-verror for an example.
 */
function dumpException(ex)
{
	var ret;

	if (!(ex instanceof Error))
		throw (new Error(jsSprintf('invalid type for %%r: %j', ex)));

	/* Note that V8 prepends "ex.stack" with ex.toString(). */
	ret = 'EXCEPTION: ' + ex.constructor.name + ': ' + ex.stack;

	if (ex.cause && typeof (ex.cause) === 'function') {
		var cex = ex.cause();
		if (cex) {
			ret += '\nCaused by: ' + dumpException(cex);
		}
	}

	return (ret);
}

}).call(this)}).call(this,require('_process'))
},{"_process":162,"assert":96,"util":190}],116:[function(require,module,exports){
'use strict';

var isCallable = require('is-callable');

var toStr = Object.prototype.toString;
var hasOwnProperty = Object.prototype.hasOwnProperty;

var forEachArray = function forEachArray(array, iterator, receiver) {
    for (var i = 0, len = array.length; i < len; i++) {
        if (hasOwnProperty.call(array, i)) {
            if (receiver == null) {
                iterator(array[i], i, array);
            } else {
                iterator.call(receiver, array[i], i, array);
            }
        }
    }
};

var forEachString = function forEachString(string, iterator, receiver) {
    for (var i = 0, len = string.length; i < len; i++) {
        // no such thing as a sparse string.
        if (receiver == null) {
            iterator(string.charAt(i), i, string);
        } else {
            iterator.call(receiver, string.charAt(i), i, string);
        }
    }
};

var forEachObject = function forEachObject(object, iterator, receiver) {
    for (var k in object) {
        if (hasOwnProperty.call(object, k)) {
            if (receiver == null) {
                iterator(object[k], k, object);
            } else {
                iterator.call(receiver, object[k], k, object);
            }
        }
    }
};

var forEach = function forEach(list, iterator, thisArg) {
    if (!isCallable(iterator)) {
        throw new TypeError('iterator must be a function');
    }

    var receiver;
    if (arguments.length >= 3) {
        receiver = thisArg;
    }

    if (toStr.call(list) === '[object Array]') {
        forEachArray(list, iterator, receiver);
    } else if (typeof list === 'string') {
        forEachString(list, iterator, receiver);
    } else {
        forEachObject(list, iterator, receiver);
    }
};

module.exports = forEach;

},{"is-callable":129}],117:[function(require,module,exports){
'use strict';

/* eslint no-invalid-this: 1 */

var ERROR_MESSAGE = 'Function.prototype.bind called on incompatible ';
var slice = Array.prototype.slice;
var toStr = Object.prototype.toString;
var funcType = '[object Function]';

module.exports = function bind(that) {
    var target = this;
    if (typeof target !== 'function' || toStr.call(target) !== funcType) {
        throw new TypeError(ERROR_MESSAGE + target);
    }
    var args = slice.call(arguments, 1);

    var bound;
    var binder = function () {
        if (this instanceof bound) {
            var result = target.apply(
                this,
                args.concat(slice.call(arguments))
            );
            if (Object(result) === result) {
                return result;
            }
            return this;
        } else {
            return target.apply(
                that,
                args.concat(slice.call(arguments))
            );
        }
    };

    var boundLength = Math.max(0, target.length - args.length);
    var boundArgs = [];
    for (var i = 0; i < boundLength; i++) {
        boundArgs.push('$' + i);
    }

    bound = Function('binder', 'return function (' + boundArgs.join(',') + '){ return binder.apply(this,arguments); }')(binder);

    if (target.prototype) {
        var Empty = function Empty() {};
        Empty.prototype = target.prototype;
        bound.prototype = new Empty();
        Empty.prototype = null;
    }

    return bound;
};

},{}],118:[function(require,module,exports){
'use strict';

var implementation = require('./implementation');

module.exports = Function.prototype.bind || implementation;

},{"./implementation":117}],119:[function(require,module,exports){
'use strict';

var undefined;

var $SyntaxError = SyntaxError;
var $Function = Function;
var $TypeError = TypeError;

// eslint-disable-next-line consistent-return
var getEvalledConstructor = function (expressionSyntax) {
	try {
		return $Function('"use strict"; return (' + expressionSyntax + ').constructor;')();
	} catch (e) {}
};

var $gOPD = Object.getOwnPropertyDescriptor;
if ($gOPD) {
	try {
		$gOPD({}, '');
	} catch (e) {
		$gOPD = null; // this is IE 8, which has a broken gOPD
	}
}

var throwTypeError = function () {
	throw new $TypeError();
};
var ThrowTypeError = $gOPD
	? (function () {
		try {
			// eslint-disable-next-line no-unused-expressions, no-caller, no-restricted-properties
			arguments.callee; // IE 8 does not throw here
			return throwTypeError;
		} catch (calleeThrows) {
			try {
				// IE 8 throws on Object.getOwnPropertyDescriptor(arguments, '')
				return $gOPD(arguments, 'callee').get;
			} catch (gOPDthrows) {
				return throwTypeError;
			}
		}
	}())
	: throwTypeError;

var hasSymbols = require('has-symbols')();

var getProto = Object.getPrototypeOf || function (x) { return x.__proto__; }; // eslint-disable-line no-proto

var needsEval = {};

var TypedArray = typeof Uint8Array === 'undefined' ? undefined : getProto(Uint8Array);

var INTRINSICS = {
	'%AggregateError%': typeof AggregateError === 'undefined' ? undefined : AggregateError,
	'%Array%': Array,
	'%ArrayBuffer%': typeof ArrayBuffer === 'undefined' ? undefined : ArrayBuffer,
	'%ArrayIteratorPrototype%': hasSymbols ? getProto([][Symbol.iterator]()) : undefined,
	'%AsyncFromSyncIteratorPrototype%': undefined,
	'%AsyncFunction%': needsEval,
	'%AsyncGenerator%': needsEval,
	'%AsyncGeneratorFunction%': needsEval,
	'%AsyncIteratorPrototype%': needsEval,
	'%Atomics%': typeof Atomics === 'undefined' ? undefined : Atomics,
	'%BigInt%': typeof BigInt === 'undefined' ? undefined : BigInt,
	'%BigInt64Array%': typeof BigInt64Array === 'undefined' ? undefined : BigInt64Array,
	'%BigUint64Array%': typeof BigUint64Array === 'undefined' ? undefined : BigUint64Array,
	'%Boolean%': Boolean,
	'%DataView%': typeof DataView === 'undefined' ? undefined : DataView,
	'%Date%': Date,
	'%decodeURI%': decodeURI,
	'%decodeURIComponent%': decodeURIComponent,
	'%encodeURI%': encodeURI,
	'%encodeURIComponent%': encodeURIComponent,
	'%Error%': Error,
	'%eval%': eval, // eslint-disable-line no-eval
	'%EvalError%': EvalError,
	'%Float32Array%': typeof Float32Array === 'undefined' ? undefined : Float32Array,
	'%Float64Array%': typeof Float64Array === 'undefined' ? undefined : Float64Array,
	'%FinalizationRegistry%': typeof FinalizationRegistry === 'undefined' ? undefined : FinalizationRegistry,
	'%Function%': $Function,
	'%GeneratorFunction%': needsEval,
	'%Int8Array%': typeof Int8Array === 'undefined' ? undefined : Int8Array,
	'%Int16Array%': typeof Int16Array === 'undefined' ? undefined : Int16Array,
	'%Int32Array%': typeof Int32Array === 'undefined' ? undefined : Int32Array,
	'%isFinite%': isFinite,
	'%isNaN%': isNaN,
	'%IteratorPrototype%': hasSymbols ? getProto(getProto([][Symbol.iterator]())) : undefined,
	'%JSON%': typeof JSON === 'object' ? JSON : undefined,
	'%Map%': typeof Map === 'undefined' ? undefined : Map,
	'%MapIteratorPrototype%': typeof Map === 'undefined' || !hasSymbols ? undefined : getProto(new Map()[Symbol.iterator]()),
	'%Math%': Math,
	'%Number%': Number,
	'%Object%': Object,
	'%parseFloat%': parseFloat,
	'%parseInt%': parseInt,
	'%Promise%': typeof Promise === 'undefined' ? undefined : Promise,
	'%Proxy%': typeof Proxy === 'undefined' ? undefined : Proxy,
	'%RangeError%': RangeError,
	'%ReferenceError%': ReferenceError,
	'%Reflect%': typeof Reflect === 'undefined' ? undefined : Reflect,
	'%RegExp%': RegExp,
	'%Set%': typeof Set === 'undefined' ? undefined : Set,
	'%SetIteratorPrototype%': typeof Set === 'undefined' || !hasSymbols ? undefined : getProto(new Set()[Symbol.iterator]()),
	'%SharedArrayBuffer%': typeof SharedArrayBuffer === 'undefined' ? undefined : SharedArrayBuffer,
	'%String%': String,
	'%StringIteratorPrototype%': hasSymbols ? getProto(''[Symbol.iterator]()) : undefined,
	'%Symbol%': hasSymbols ? Symbol : undefined,
	'%SyntaxError%': $SyntaxError,
	'%ThrowTypeError%': ThrowTypeError,
	'%TypedArray%': TypedArray,
	'%TypeError%': $TypeError,
	'%Uint8Array%': typeof Uint8Array === 'undefined' ? undefined : Uint8Array,
	'%Uint8ClampedArray%': typeof Uint8ClampedArray === 'undefined' ? undefined : Uint8ClampedArray,
	'%Uint16Array%': typeof Uint16Array === 'undefined' ? undefined : Uint16Array,
	'%Uint32Array%': typeof Uint32Array === 'undefined' ? undefined : Uint32Array,
	'%URIError%': URIError,
	'%WeakMap%': typeof WeakMap === 'undefined' ? undefined : WeakMap,
	'%WeakRef%': typeof WeakRef === 'undefined' ? undefined : WeakRef,
	'%WeakSet%': typeof WeakSet === 'undefined' ? undefined : WeakSet
};

try {
	null.error; // eslint-disable-line no-unused-expressions
} catch (e) {
	// https://github.com/tc39/proposal-shadowrealm/pull/384#issuecomment-1364264229
	var errorProto = getProto(getProto(e));
	INTRINSICS['%Error.prototype%'] = errorProto;
}

var doEval = function doEval(name) {
	var value;
	if (name === '%AsyncFunction%') {
		value = getEvalledConstructor('async function () {}');
	} else if (name === '%GeneratorFunction%') {
		value = getEvalledConstructor('function* () {}');
	} else if (name === '%AsyncGeneratorFunction%') {
		value = getEvalledConstructor('async function* () {}');
	} else if (name === '%AsyncGenerator%') {
		var fn = doEval('%AsyncGeneratorFunction%');
		if (fn) {
			value = fn.prototype;
		}
	} else if (name === '%AsyncIteratorPrototype%') {
		var gen = doEval('%AsyncGenerator%');
		if (gen) {
			value = getProto(gen.prototype);
		}
	}

	INTRINSICS[name] = value;

	return value;
};

var LEGACY_ALIASES = {
	'%ArrayBufferPrototype%': ['ArrayBuffer', 'prototype'],
	'%ArrayPrototype%': ['Array', 'prototype'],
	'%ArrayProto_entries%': ['Array', 'prototype', 'entries'],
	'%ArrayProto_forEach%': ['Array', 'prototype', 'forEach'],
	'%ArrayProto_keys%': ['Array', 'prototype', 'keys'],
	'%ArrayProto_values%': ['Array', 'prototype', 'values'],
	'%AsyncFunctionPrototype%': ['AsyncFunction', 'prototype'],
	'%AsyncGenerator%': ['AsyncGeneratorFunction', 'prototype'],
	'%AsyncGeneratorPrototype%': ['AsyncGeneratorFunction', 'prototype', 'prototype'],
	'%BooleanPrototype%': ['Boolean', 'prototype'],
	'%DataViewPrototype%': ['DataView', 'prototype'],
	'%DatePrototype%': ['Date', 'prototype'],
	'%ErrorPrototype%': ['Error', 'prototype'],
	'%EvalErrorPrototype%': ['EvalError', 'prototype'],
	'%Float32ArrayPrototype%': ['Float32Array', 'prototype'],
	'%Float64ArrayPrototype%': ['Float64Array', 'prototype'],
	'%FunctionPrototype%': ['Function', 'prototype'],
	'%Generator%': ['GeneratorFunction', 'prototype'],
	'%GeneratorPrototype%': ['GeneratorFunction', 'prototype', 'prototype'],
	'%Int8ArrayPrototype%': ['Int8Array', 'prototype'],
	'%Int16ArrayPrototype%': ['Int16Array', 'prototype'],
	'%Int32ArrayPrototype%': ['Int32Array', 'prototype'],
	'%JSONParse%': ['JSON', 'parse'],
	'%JSONStringify%': ['JSON', 'stringify'],
	'%MapPrototype%': ['Map', 'prototype'],
	'%NumberPrototype%': ['Number', 'prototype'],
	'%ObjectPrototype%': ['Object', 'prototype'],
	'%ObjProto_toString%': ['Object', 'prototype', 'toString'],
	'%ObjProto_valueOf%': ['Object', 'prototype', 'valueOf'],
	'%PromisePrototype%': ['Promise', 'prototype'],
	'%PromiseProto_then%': ['Promise', 'prototype', 'then'],
	'%Promise_all%': ['Promise', 'all'],
	'%Promise_reject%': ['Promise', 'reject'],
	'%Promise_resolve%': ['Promise', 'resolve'],
	'%RangeErrorPrototype%': ['RangeError', 'prototype'],
	'%ReferenceErrorPrototype%': ['ReferenceError', 'prototype'],
	'%RegExpPrototype%': ['RegExp', 'prototype'],
	'%SetPrototype%': ['Set', 'prototype'],
	'%SharedArrayBufferPrototype%': ['SharedArrayBuffer', 'prototype'],
	'%StringPrototype%': ['String', 'prototype'],
	'%SymbolPrototype%': ['Symbol', 'prototype'],
	'%SyntaxErrorPrototype%': ['SyntaxError', 'prototype'],
	'%TypedArrayPrototype%': ['TypedArray', 'prototype'],
	'%TypeErrorPrototype%': ['TypeError', 'prototype'],
	'%Uint8ArrayPrototype%': ['Uint8Array', 'prototype'],
	'%Uint8ClampedArrayPrototype%': ['Uint8ClampedArray', 'prototype'],
	'%Uint16ArrayPrototype%': ['Uint16Array', 'prototype'],
	'%Uint32ArrayPrototype%': ['Uint32Array', 'prototype'],
	'%URIErrorPrototype%': ['URIError', 'prototype'],
	'%WeakMapPrototype%': ['WeakMap', 'prototype'],
	'%WeakSetPrototype%': ['WeakSet', 'prototype']
};

var bind = require('function-bind');
var hasOwn = require('has');
var $concat = bind.call(Function.call, Array.prototype.concat);
var $spliceApply = bind.call(Function.apply, Array.prototype.splice);
var $replace = bind.call(Function.call, String.prototype.replace);
var $strSlice = bind.call(Function.call, String.prototype.slice);
var $exec = bind.call(Function.call, RegExp.prototype.exec);

/* adapted from https://github.com/lodash/lodash/blob/4.17.15/dist/lodash.js#L6735-L6744 */
var rePropName = /[^%.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|%$))/g;
var reEscapeChar = /\\(\\)?/g; /** Used to match backslashes in property paths. */
var stringToPath = function stringToPath(string) {
	var first = $strSlice(string, 0, 1);
	var last = $strSlice(string, -1);
	if (first === '%' && last !== '%') {
		throw new $SyntaxError('invalid intrinsic syntax, expected closing `%`');
	} else if (last === '%' && first !== '%') {
		throw new $SyntaxError('invalid intrinsic syntax, expected opening `%`');
	}
	var result = [];
	$replace(string, rePropName, function (match, number, quote, subString) {
		result[result.length] = quote ? $replace(subString, reEscapeChar, '$1') : number || match;
	});
	return result;
};
/* end adaptation */

var getBaseIntrinsic = function getBaseIntrinsic(name, allowMissing) {
	var intrinsicName = name;
	var alias;
	if (hasOwn(LEGACY_ALIASES, intrinsicName)) {
		alias = LEGACY_ALIASES[intrinsicName];
		intrinsicName = '%' + alias[0] + '%';
	}

	if (hasOwn(INTRINSICS, intrinsicName)) {
		var value = INTRINSICS[intrinsicName];
		if (value === needsEval) {
			value = doEval(intrinsicName);
		}
		if (typeof value === 'undefined' && !allowMissing) {
			throw new $TypeError('intrinsic ' + name + ' exists, but is not available. Please file an issue!');
		}

		return {
			alias: alias,
			name: intrinsicName,
			value: value
		};
	}

	throw new $SyntaxError('intrinsic ' + name + ' does not exist!');
};

module.exports = function GetIntrinsic(name, allowMissing) {
	if (typeof name !== 'string' || name.length === 0) {
		throw new $TypeError('intrinsic name must be a non-empty string');
	}
	if (arguments.length > 1 && typeof allowMissing !== 'boolean') {
		throw new $TypeError('"allowMissing" argument must be a boolean');
	}

	if ($exec(/^%?[^%]*%?$/, name) === null) {
		throw new $SyntaxError('`%` may not be present anywhere but at the beginning and end of the intrinsic name');
	}
	var parts = stringToPath(name);
	var intrinsicBaseName = parts.length > 0 ? parts[0] : '';

	var intrinsic = getBaseIntrinsic('%' + intrinsicBaseName + '%', allowMissing);
	var intrinsicRealName = intrinsic.name;
	var value = intrinsic.value;
	var skipFurtherCaching = false;

	var alias = intrinsic.alias;
	if (alias) {
		intrinsicBaseName = alias[0];
		$spliceApply(parts, $concat([0, 1], alias));
	}

	for (var i = 1, isOwn = true; i < parts.length; i += 1) {
		var part = parts[i];
		var first = $strSlice(part, 0, 1);
		var last = $strSlice(part, -1);
		if (
			(
				(first === '"' || first === "'" || first === '`')
				|| (last === '"' || last === "'" || last === '`')
			)
			&& first !== last
		) {
			throw new $SyntaxError('property names with quotes must have matching quotes');
		}
		if (part === 'constructor' || !isOwn) {
			skipFurtherCaching = true;
		}

		intrinsicBaseName += '.' + part;
		intrinsicRealName = '%' + intrinsicBaseName + '%';

		if (hasOwn(INTRINSICS, intrinsicRealName)) {
			value = INTRINSICS[intrinsicRealName];
		} else if (value != null) {
			if (!(part in value)) {
				if (!allowMissing) {
					throw new $TypeError('base intrinsic for ' + name + ' exists, but the property is not available.');
				}
				return void undefined;
			}
			if ($gOPD && (i + 1) >= parts.length) {
				var desc = $gOPD(value, part);
				isOwn = !!desc;

				// By convention, when a data property is converted to an accessor
				// property to emulate a data property that does not suffer from
				// the override mistake, that accessor's getter is marked with
				// an `originalValue` property. Here, when we detect this, we
				// uphold the illusion by pretending to see that original data
				// property, i.e., returning the value rather than the getter
				// itself.
				if (isOwn && 'get' in desc && !('originalValue' in desc.get)) {
					value = desc.get;
				} else {
					value = value[part];
				}
			} else {
				isOwn = hasOwn(value, part);
				value = value[part];
			}

			if (isOwn && !skipFurtherCaching) {
				INTRINSICS[intrinsicRealName] = value;
			}
		}
	}
	return value;
};

},{"function-bind":118,"has":124,"has-symbols":121}],120:[function(require,module,exports){
'use strict';

var GetIntrinsic = require('get-intrinsic');

var $gOPD = GetIntrinsic('%Object.getOwnPropertyDescriptor%', true);

if ($gOPD) {
	try {
		$gOPD([], 'length');
	} catch (e) {
		// IE 8 has a broken gOPD
		$gOPD = null;
	}
}

module.exports = $gOPD;

},{"get-intrinsic":119}],121:[function(require,module,exports){
'use strict';

var origSymbol = typeof Symbol !== 'undefined' && Symbol;
var hasSymbolSham = require('./shams');

module.exports = function hasNativeSymbols() {
	if (typeof origSymbol !== 'function') { return false; }
	if (typeof Symbol !== 'function') { return false; }
	if (typeof origSymbol('foo') !== 'symbol') { return false; }
	if (typeof Symbol('bar') !== 'symbol') { return false; }

	return hasSymbolSham();
};

},{"./shams":122}],122:[function(require,module,exports){
'use strict';

/* eslint complexity: [2, 18], max-statements: [2, 33] */
module.exports = function hasSymbols() {
	if (typeof Symbol !== 'function' || typeof Object.getOwnPropertySymbols !== 'function') { return false; }
	if (typeof Symbol.iterator === 'symbol') { return true; }

	var obj = {};
	var sym = Symbol('test');
	var symObj = Object(sym);
	if (typeof sym === 'string') { return false; }

	if (Object.prototype.toString.call(sym) !== '[object Symbol]') { return false; }
	if (Object.prototype.toString.call(symObj) !== '[object Symbol]') { return false; }

	// temp disabled per https://github.com/ljharb/object.assign/issues/17
	// if (sym instanceof Symbol) { return false; }
	// temp disabled per https://github.com/WebReflection/get-own-property-symbols/issues/4
	// if (!(symObj instanceof Symbol)) { return false; }

	// if (typeof Symbol.prototype.toString !== 'function') { return false; }
	// if (String(sym) !== Symbol.prototype.toString.call(sym)) { return false; }

	var symVal = 42;
	obj[sym] = symVal;
	for (sym in obj) { return false; } // eslint-disable-line no-restricted-syntax, no-unreachable-loop
	if (typeof Object.keys === 'function' && Object.keys(obj).length !== 0) { return false; }

	if (typeof Object.getOwnPropertyNames === 'function' && Object.getOwnPropertyNames(obj).length !== 0) { return false; }

	var syms = Object.getOwnPropertySymbols(obj);
	if (syms.length !== 1 || syms[0] !== sym) { return false; }

	if (!Object.prototype.propertyIsEnumerable.call(obj, sym)) { return false; }

	if (typeof Object.getOwnPropertyDescriptor === 'function') {
		var descriptor = Object.getOwnPropertyDescriptor(obj, sym);
		if (descriptor.value !== symVal || descriptor.enumerable !== true) { return false; }
	}

	return true;
};

},{}],123:[function(require,module,exports){
'use strict';

var hasSymbols = require('has-symbols/shams');

module.exports = function hasToStringTagShams() {
	return hasSymbols() && !!Symbol.toStringTag;
};

},{"has-symbols/shams":122}],124:[function(require,module,exports){
'use strict';

var bind = require('function-bind');

module.exports = bind.call(Function.call, Object.prototype.hasOwnProperty);

},{"function-bind":118}],125:[function(require,module,exports){
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],126:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      ctor.prototype = Object.create(superCtor.prototype, {
        constructor: {
          value: ctor,
          enumerable: false,
          writable: true,
          configurable: true
        }
      })
    }
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      var TempCtor = function () {}
      TempCtor.prototype = superCtor.prototype
      ctor.prototype = new TempCtor()
      ctor.prototype.constructor = ctor
    }
  }
}

},{}],127:[function(require,module,exports){
'use strict';

var hasToStringTag = require('has-tostringtag/shams')();
var callBound = require('call-bind/callBound');

var $toString = callBound('Object.prototype.toString');

var isStandardArguments = function isArguments(value) {
	if (hasToStringTag && value && typeof value === 'object' && Symbol.toStringTag in value) {
		return false;
	}
	return $toString(value) === '[object Arguments]';
};

var isLegacyArguments = function isArguments(value) {
	if (isStandardArguments(value)) {
		return true;
	}
	return value !== null &&
		typeof value === 'object' &&
		typeof value.length === 'number' &&
		value.length >= 0 &&
		$toString(value) !== '[object Array]' &&
		$toString(value.callee) === '[object Function]';
};

var supportsStandardArguments = (function () {
	return isStandardArguments(arguments);
}());

isStandardArguments.isLegacyArguments = isLegacyArguments; // for tests

module.exports = supportsStandardArguments ? isStandardArguments : isLegacyArguments;

},{"call-bind/callBound":111,"has-tostringtag/shams":123}],128:[function(require,module,exports){
/*!
 * Determine if an object is a Buffer
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */

// The _isBuffer check is for Safari 5-7 support, because it's missing
// Object.prototype.constructor. Remove this eventually
module.exports = function (obj) {
  return obj != null && (isBuffer(obj) || isSlowBuffer(obj) || !!obj._isBuffer)
}

function isBuffer (obj) {
  return !!obj.constructor && typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj)
}

// For Node v0.10 support. Remove this eventually.
function isSlowBuffer (obj) {
  return typeof obj.readFloatLE === 'function' && typeof obj.slice === 'function' && isBuffer(obj.slice(0, 0))
}

},{}],129:[function(require,module,exports){
'use strict';

var fnToStr = Function.prototype.toString;
var reflectApply = typeof Reflect === 'object' && Reflect !== null && Reflect.apply;
var badArrayLike;
var isCallableMarker;
if (typeof reflectApply === 'function' && typeof Object.defineProperty === 'function') {
	try {
		badArrayLike = Object.defineProperty({}, 'length', {
			get: function () {
				throw isCallableMarker;
			}
		});
		isCallableMarker = {};
		// eslint-disable-next-line no-throw-literal
		reflectApply(function () { throw 42; }, null, badArrayLike);
	} catch (_) {
		if (_ !== isCallableMarker) {
			reflectApply = null;
		}
	}
} else {
	reflectApply = null;
}

var constructorRegex = /^\s*class\b/;
var isES6ClassFn = function isES6ClassFunction(value) {
	try {
		var fnStr = fnToStr.call(value);
		return constructorRegex.test(fnStr);
	} catch (e) {
		return false; // not a function
	}
};

var tryFunctionObject = function tryFunctionToStr(value) {
	try {
		if (isES6ClassFn(value)) { return false; }
		fnToStr.call(value);
		return true;
	} catch (e) {
		return false;
	}
};
var toStr = Object.prototype.toString;
var objectClass = '[object Object]';
var fnClass = '[object Function]';
var genClass = '[object GeneratorFunction]';
var ddaClass = '[object HTMLAllCollection]'; // IE 11
var ddaClass2 = '[object HTML document.all class]';
var ddaClass3 = '[object HTMLCollection]'; // IE 9-10
var hasToStringTag = typeof Symbol === 'function' && !!Symbol.toStringTag; // better: use `has-tostringtag`

var isIE68 = !(0 in [,]); // eslint-disable-line no-sparse-arrays, comma-spacing

var isDDA = function isDocumentDotAll() { return false; };
if (typeof document === 'object') {
	// Firefox 3 canonicalizes DDA to undefined when it's not accessed directly
	var all = document.all;
	if (toStr.call(all) === toStr.call(document.all)) {
		isDDA = function isDocumentDotAll(value) {
			/* globals document: false */
			// in IE 6-8, typeof document.all is "object" and it's truthy
			if ((isIE68 || !value) && (typeof value === 'undefined' || typeof value === 'object')) {
				try {
					var str = toStr.call(value);
					return (
						str === ddaClass
						|| str === ddaClass2
						|| str === ddaClass3 // opera 12.16
						|| str === objectClass // IE 6-8
					) && value('') == null; // eslint-disable-line eqeqeq
				} catch (e) { /**/ }
			}
			return false;
		};
	}
}

module.exports = reflectApply
	? function isCallable(value) {
		if (isDDA(value)) { return true; }
		if (!value) { return false; }
		if (typeof value !== 'function' && typeof value !== 'object') { return false; }
		try {
			reflectApply(value, null, badArrayLike);
		} catch (e) {
			if (e !== isCallableMarker) { return false; }
		}
		return !isES6ClassFn(value) && tryFunctionObject(value);
	}
	: function isCallable(value) {
		if (isDDA(value)) { return true; }
		if (!value) { return false; }
		if (typeof value !== 'function' && typeof value !== 'object') { return false; }
		if (hasToStringTag) { return tryFunctionObject(value); }
		if (isES6ClassFn(value)) { return false; }
		var strClass = toStr.call(value);
		if (strClass !== fnClass && strClass !== genClass && !(/^\[object HTML/).test(strClass)) { return false; }
		return tryFunctionObject(value);
	};

},{}],130:[function(require,module,exports){
'use strict';

var toStr = Object.prototype.toString;
var fnToStr = Function.prototype.toString;
var isFnRegex = /^\s*(?:function)?\*/;
var hasToStringTag = require('has-tostringtag/shams')();
var getProto = Object.getPrototypeOf;
var getGeneratorFunc = function () { // eslint-disable-line consistent-return
	if (!hasToStringTag) {
		return false;
	}
	try {
		return Function('return function*() {}')();
	} catch (e) {
	}
};
var GeneratorFunction;

module.exports = function isGeneratorFunction(fn) {
	if (typeof fn !== 'function') {
		return false;
	}
	if (isFnRegex.test(fnToStr.call(fn))) {
		return true;
	}
	if (!hasToStringTag) {
		var str = toStr.call(fn);
		return str === '[object GeneratorFunction]';
	}
	if (!getProto) {
		return false;
	}
	if (typeof GeneratorFunction === 'undefined') {
		var generatorFunc = getGeneratorFunc();
		GeneratorFunction = generatorFunc ? getProto(generatorFunc) : false;
	}
	return getProto(fn) === GeneratorFunction;
};

},{"has-tostringtag/shams":123}],131:[function(require,module,exports){
(function (global){(function (){
'use strict';

var forEach = require('for-each');
var availableTypedArrays = require('available-typed-arrays');
var callBound = require('call-bind/callBound');

var $toString = callBound('Object.prototype.toString');
var hasToStringTag = require('has-tostringtag/shams')();
var gOPD = require('gopd');

var g = typeof globalThis === 'undefined' ? global : globalThis;
var typedArrays = availableTypedArrays();

var $indexOf = callBound('Array.prototype.indexOf', true) || function indexOf(array, value) {
	for (var i = 0; i < array.length; i += 1) {
		if (array[i] === value) {
			return i;
		}
	}
	return -1;
};
var $slice = callBound('String.prototype.slice');
var toStrTags = {};
var getPrototypeOf = Object.getPrototypeOf; // require('getprototypeof');
if (hasToStringTag && gOPD && getPrototypeOf) {
	forEach(typedArrays, function (typedArray) {
		var arr = new g[typedArray]();
		if (Symbol.toStringTag in arr) {
			var proto = getPrototypeOf(arr);
			var descriptor = gOPD(proto, Symbol.toStringTag);
			if (!descriptor) {
				var superProto = getPrototypeOf(proto);
				descriptor = gOPD(superProto, Symbol.toStringTag);
			}
			toStrTags[typedArray] = descriptor.get;
		}
	});
}

var tryTypedArrays = function tryAllTypedArrays(value) {
	var anyTrue = false;
	forEach(toStrTags, function (getter, typedArray) {
		if (!anyTrue) {
			try {
				anyTrue = getter.call(value) === typedArray;
			} catch (e) { /**/ }
		}
	});
	return anyTrue;
};

module.exports = function isTypedArray(value) {
	if (!value || typeof value !== 'object') { return false; }
	if (!hasToStringTag || !(Symbol.toStringTag in value)) {
		var tag = $slice($toString(value), 8, -1);
		return $indexOf(typedArrays, tag) > -1;
	}
	if (!gOPD) { return false; }
	return tryTypedArrays(value);
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"available-typed-arrays":100,"call-bind/callBound":111,"for-each":116,"gopd":120,"has-tostringtag/shams":123}],132:[function(require,module,exports){
(function (Buffer){(function (){
'use strict'

const requestQueueFactory = require('./request-queue')
const messageTrackerFactory = require('./message-tracker')
const { MAX_MSGID } = require('./constants')

const EventEmitter = require('events').EventEmitter
const net = require('net')
const tls = require('tls')
const util = require('util')

const once = require('once')
const backoff = require('backoff')
const vasync = require('vasync')
const assert = require('assert-plus')
const VError = require('verror').VError

const Attribute = require('@ldapjs/attribute')
const Change = require('@ldapjs/change')
const Control = require('../controls/index').Control
const { Control: LdapControl } = require('@ldapjs/controls')
const SearchPager = require('./search_pager')
const Protocol = require('@ldapjs/protocol')
const { DN } = require('@ldapjs/dn')
const errors = require('../errors')
const filters = require('@ldapjs/filter')
const Parser = require('../messages/parser')
const url = require('../url')
const CorkedEmitter = require('../corked_emitter')

/// --- Globals

const messages = require('@ldapjs/messages')
const {
  AbandonRequest,
  AddRequest,
  BindRequest,
  CompareRequest,
  DeleteRequest,
  ExtensionRequest: ExtendedRequest,
  ModifyRequest,
  ModifyDnRequest: ModifyDNRequest,
  SearchRequest,
  UnbindRequest,
  LdapResult: LDAPResult,
  SearchResultEntry: SearchEntry,
  SearchResultReference: SearchReference
} = messages

const PresenceFilter = filters.PresenceFilter

const ConnectionError = errors.ConnectionError

const CMP_EXPECT = [errors.LDAP_COMPARE_TRUE, errors.LDAP_COMPARE_FALSE]

// node 0.6 got rid of FDs, so make up a client id for logging
let CLIENT_ID = 0

/// --- Internal Helpers

function nextClientId () {
  if (++CLIENT_ID === MAX_MSGID) { return 1 }

  return CLIENT_ID
}

function validateControls (controls) {
  if (Array.isArray(controls)) {
    controls.forEach(function (c) {
      if (!(c instanceof Control) && !(c instanceof LdapControl)) { throw new TypeError('controls must be [Control]') }
    })
  } else if (controls instanceof Control || controls instanceof LdapControl) {
    controls = [controls]
  } else {
    throw new TypeError('controls must be [Control]')
  }

  return controls
}

function ensureDN (input) {
  if (DN.isDn(input)) {
    return DN
  } else if (typeof (input) === 'string') {
    return DN.fromString(input)
  } else {
    throw new Error('invalid DN')
  }
}

/// --- API

/**
 * Constructs a new client.
 *
 * The options object is required, and must contain either a URL (string) or
 * a socketPath (string); the socketPath is only if you want to talk to an LDAP
 * server over a Unix Domain Socket.  Additionally, you can pass in a bunyan
 * option that is the result of `new Logger()`, presumably after you've
 * configured it.
 *
 * @param {Object} options must have either url or socketPath.
 * @throws {TypeError} on bad input.
 */
function Client (options) {
  assert.ok(options)

  EventEmitter.call(this, options)

  const self = this
  this.urls = options.url ? [].concat(options.url).map(url.parse) : []
  this._nextServer = 0
  // updated in connectSocket() after each connect
  this.host = undefined
  this.port = undefined
  this.secure = undefined
  this.url = undefined
  this.tlsOptions = options.tlsOptions
  this.socketPath = options.socketPath || false

  this.log = options.log.child({ clazz: 'Client' }, true)

  this.timeout = parseInt((options.timeout || 0), 10)
  this.connectTimeout = parseInt((options.connectTimeout || 0), 10)
  this.idleTimeout = parseInt((options.idleTimeout || 0), 10)
  if (options.reconnect) {
    // Fall back to defaults if options.reconnect === true
    const rOpts = (typeof (options.reconnect) === 'object')
      ? options.reconnect
      : {}
    this.reconnect = {
      initialDelay: parseInt(rOpts.initialDelay || 100, 10),
      maxDelay: parseInt(rOpts.maxDelay || 10000, 10),
      failAfter: parseInt(rOpts.failAfter, 10) || Infinity
    }
  }

  this.queue = requestQueueFactory({
    size: parseInt((options.queueSize || 0), 10),
    timeout: parseInt((options.queueTimeout || 0), 10)
  })
  if (options.queueDisable) {
    this.queue.freeze()
  }

  // Implicitly configure setup action to bind the client if bindDN and
  // bindCredentials are passed in.  This will more closely mimic PooledClient
  // auto-login behavior.
  if (options.bindDN !== undefined &&
      options.bindCredentials !== undefined) {
    this.on('setup', function (clt, cb) {
      clt.bind(options.bindDN, options.bindCredentials, function (err) {
        if (err) {
          if (self._socket) {
            self._socket.destroy()
          }
          self.emit('error', err)
        }
        cb(err)
      })
    })
  }

  this._socket = null
  this.connected = false
  this.connect()
}
util.inherits(Client, EventEmitter)
module.exports = Client

/**
 * Sends an abandon request to the LDAP server.
 *
 * The callback will be invoked as soon as the data is flushed out to the
 * network, as there is never a response from abandon.
 *
 * @param {Number} messageId the messageId to abandon.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.abandon = function abandon (messageId, controls, callback) {
  assert.number(messageId, 'messageId')
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  const req = new AbandonRequest({
    abandonId: messageId,
    controls
  })

  return this._send(req, 'abandon', null, callback)
}

/**
 * Adds an entry to the LDAP server.
 *
 * Entry can be either [Attribute] or a plain JS object where the
 * values are either a plain value or an array of values.  Any value (that's
 * not an array) will get converted to a string, so keep that in mind.
 *
 * @param {String} name the DN of the entry to add.
 * @param {Object} entry an array of Attributes to be added or a JS object.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.add = function add (name, entry, controls, callback) {
  assert.ok(name !== undefined, 'name')
  assert.object(entry, 'entry')
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  if (Array.isArray(entry)) {
    entry.forEach(function (a) {
      if (!Attribute.isAttribute(a)) { throw new TypeError('entry must be an Array of Attributes') }
    })
  } else {
    const save = entry

    entry = []
    Object.keys(save).forEach(function (k) {
      const attr = new Attribute({ type: k })
      if (Array.isArray(save[k])) {
        save[k].forEach(function (v) {
          attr.addValue(v.toString())
        })
      } else if (Buffer.isBuffer(save[k])) {
        attr.addValue(save[k])
      } else {
        attr.addValue(save[k].toString())
      }
      entry.push(attr)
    })
  }

  const req = new AddRequest({
    entry: ensureDN(name),
    attributes: entry,
    controls
  })

  return this._send(req, [errors.LDAP_SUCCESS], null, callback)
}

/**
 * Performs a simple authentication against the server.
 *
 * @param {String} name the DN to bind as.
 * @param {String} credentials the userPassword associated with name.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.bind = function bind (name,
  credentials,
  controls,
  callback,
  _bypass) {
  if (
    typeof (name) !== 'string' &&
    Object.prototype.toString.call(name) !== '[object LdapDn]'
  ) {
    throw new TypeError('name (string) required')
  }
  assert.optionalString(credentials, 'credentials')
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  const req = new BindRequest({
    name: name || '',
    authentication: 'Simple',
    credentials: credentials || '',
    controls
  })

  // Connection errors will be reported to the bind callback too (useful when the LDAP server is not available)
  const self = this
  function callbackWrapper (err, ret) {
    self.removeListener('connectError', callbackWrapper)
    callback(err, ret)
  }
  this.addListener('connectError', callbackWrapper)

  return this._send(req, [errors.LDAP_SUCCESS], null, callbackWrapper, _bypass)
}

/**
 * Compares an attribute/value pair with an entry on the LDAP server.
 *
 * @param {String} name the DN of the entry to compare attributes with.
 * @param {String} attr name of an attribute to check.
 * @param {String} value value of an attribute to check.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, boolean, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.compare = function compare (name,
  attr,
  value,
  controls,
  callback) {
  assert.ok(name !== undefined, 'name')
  assert.string(attr, 'attr')
  assert.string(value, 'value')
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  const req = new CompareRequest({
    entry: ensureDN(name),
    attribute: attr,
    value,
    controls
  })

  return this._send(req, CMP_EXPECT, null, function (err, res) {
    if (err) { return callback(err) }

    return callback(null, (res.status === errors.LDAP_COMPARE_TRUE), res)
  })
}

/**
 * Deletes an entry from the LDAP server.
 *
 * @param {String} name the DN of the entry to delete.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.del = function del (name, controls, callback) {
  assert.ok(name !== undefined, 'name')
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  const req = new DeleteRequest({
    entry: ensureDN(name),
    controls
  })

  return this._send(req, [errors.LDAP_SUCCESS], null, callback)
}

/**
 * Performs an extended operation on the LDAP server.
 *
 * Pretty much none of the LDAP extended operations return an OID
 * (responseName), so I just don't bother giving it back in the callback.
 * It's on the third param in `res` if you need it.
 *
 * @param {String} name the OID of the extended operation to perform.
 * @param {String} value value to pass in for this operation.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, value, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.exop = function exop (name, value, controls, callback) {
  assert.string(name, 'name')
  if (typeof (value) === 'function') {
    callback = value
    controls = []
    value = undefined
  }
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  const req = new ExtendedRequest({
    requestName: name,
    requestValue: value,
    controls
  })

  return this._send(req, [errors.LDAP_SUCCESS], null, function (err, res) {
    if (err) { return callback(err) }

    return callback(null, res.responseValue || '', res)
  })
}

/**
 * Performs an LDAP modify against the server.
 *
 * @param {String} name the DN of the entry to modify.
 * @param {Change} change update to perform (can be [Change]).
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.modify = function modify (name, change, controls, callback) {
  assert.ok(name !== undefined, 'name')
  assert.object(change, 'change')

  const changes = []

  function changeFromObject (obj) {
    if (!obj.operation && !obj.type) { throw new Error('change.operation required') }
    if (typeof (obj.modification) !== 'object') { throw new Error('change.modification (object) required') }

    if (Object.keys(obj.modification).length === 2 &&
        typeof (obj.modification.type) === 'string' &&
        Array.isArray(obj.modification.vals)) {
      // Use modification directly if it's already normalized:
      changes.push(new Change({
        operation: obj.operation || obj.type,
        modification: obj.modification
      }))
    } else {
      // Normalize the modification object
      Object.keys(obj.modification).forEach(function (k) {
        const mod = {}
        mod[k] = obj.modification[k]
        changes.push(new Change({
          operation: obj.operation || obj.type,
          modification: mod
        }))
      })
    }
  }

  if (Change.isChange(change)) {
    changes.push(change)
  } else if (Array.isArray(change)) {
    change.forEach(function (c) {
      if (Change.isChange(c)) {
        changes.push(c)
      } else {
        changeFromObject(c)
      }
    })
  } else {
    changeFromObject(change)
  }

  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  const req = new ModifyRequest({
    object: ensureDN(name),
    changes,
    controls
  })

  return this._send(req, [errors.LDAP_SUCCESS], null, callback)
}

/**
 * Performs an LDAP modifyDN against the server.
 *
 * This does not allow you to keep the old DN, as while the LDAP protocol
 * has a facility for that, it's stupid. Just Search/Add.
 *
 * This will automatically deal with "new superior" logic.
 *
 * @param {String} name the DN of the entry to modify.
 * @param {String} newName the new DN to move this entry to.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.modifyDN = function modifyDN (name,
  newName,
  controls,
  callback) {
  assert.ok(name !== undefined, 'name')
  assert.string(newName, 'newName')
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback)

  const newDN = DN.fromString(newName)

  const req = new ModifyDNRequest({
    entry: DN.fromString(name),
    deleteOldRdn: true,
    controls
  })

  if (newDN.length !== 1) {
    req.newRdn = DN.fromString(newDN.shift().toString())
    req.newSuperior = newDN
  } else {
    req.newRdn = newDN
  }

  return this._send(req, [errors.LDAP_SUCCESS], null, callback)
}

/**
 * Performs an LDAP search against the server.
 *
 * Note that the defaults for options are a 'base' search, if that's what
 * you want you can just pass in a string for options and it will be treated
 * as the search filter.  Also, you can either pass in programatic Filter
 * objects or a filter string as the filter option.
 *
 * Note that this method is 'special' in that the callback 'res' param will
 * have two important events on it, namely 'entry' and 'end' that you can hook
 * to.  The former will emit a SearchEntry object for each record that comes
 * back, and the latter will emit a normal LDAPResult object.
 *
 * @param {String} base the DN in the tree to start searching at.
 * @param {Object} options parameters:
 *                           - {String} scope default of 'base'.
 *                           - {String} filter default of '(objectclass=*)'.
 *                           - {Array} attributes [string] to return.
 *                           - {Boolean} attrsOnly whether to return values.
 * @param {Control} controls (optional) either a Control or [Control].
 * @param {Function} callback of the form f(err, res).
 * @throws {TypeError} on invalid input.
 */
Client.prototype.search = function search (base,
  options,
  controls,
  callback,
  _bypass) {
  assert.ok(base !== undefined, 'search base')
  if (Array.isArray(options) || (options instanceof Control)) {
    controls = options
    options = {}
  } else if (typeof (options) === 'function') {
    callback = options
    controls = []
    options = {
      filter: new PresenceFilter({ attribute: 'objectclass' })
    }
  } else if (typeof (options) === 'string') {
    options = { filter: filters.parseString(options) }
  } else if (typeof (options) !== 'object') {
    throw new TypeError('options (object) required')
  }
  if (typeof (options.filter) === 'string') {
    options.filter = filters.parseString(options.filter)
  } else if (!options.filter) {
    options.filter = new PresenceFilter({ attribute: 'objectclass' })
  } else if (Object.prototype.toString.call(options.filter) !== '[object FilterString]') {
    throw new TypeError('options.filter (Filter) required')
  }
  if (typeof (controls) === 'function') {
    callback = controls
    controls = []
  } else {
    controls = validateControls(controls)
  }
  assert.func(callback, 'callback')

  if (options.attributes) {
    if (!Array.isArray(options.attributes)) {
      if (typeof (options.attributes) === 'string') {
        options.attributes = [options.attributes]
      } else {
        throw new TypeError('options.attributes must be an Array of Strings')
      }
    }
  }

  const self = this
  const baseDN = ensureDN(base)

  function sendRequest (ctrls, emitter, cb) {
    const req = new SearchRequest({
      baseObject: baseDN,
      scope: options.scope || 'base',
      filter: options.filter,
      derefAliases: options.derefAliases || Protocol.search.NEVER_DEREF_ALIASES,
      sizeLimit: options.sizeLimit || 0,
      timeLimit: options.timeLimit || 10,
      typesOnly: options.typesOnly || false,
      attributes: options.attributes || [],
      controls: ctrls
    })

    return self._send(req,
      [errors.LDAP_SUCCESS],
      emitter,
      cb,
      _bypass)
  }

  if (options.paged) {
    // Perform automated search paging
    const pageOpts = typeof (options.paged) === 'object' ? options.paged : {}
    let size = 100 // Default page size
    if (pageOpts.pageSize > 0) {
      size = pageOpts.pageSize
    } else if (options.sizeLimit > 1) {
      // According to the RFC, servers should ignore the paging control if
      // pageSize >= sizelimit.  Some might still send results, but it's safer
      // to stay under that figure when assigning a default value.
      size = options.sizeLimit - 1
    }

    const pager = new SearchPager({
      callback,
      controls,
      pageSize: size,
      pagePause: pageOpts.pagePause,
      sendRequest
    })
    pager.begin()
  } else {
    sendRequest(controls, new CorkedEmitter(), callback)
  }
}

/**
 * Unbinds this client from the LDAP server.
 *
 * Note that unbind does not have a response, so this callback is actually
 * optional; either way, the client is disconnected.
 *
 * @param {Function} callback of the form f(err).
 * @throws {TypeError} if you pass in callback as not a function.
 */
Client.prototype.unbind = function unbind (callback) {
  if (!callback) { callback = function () {} }

  if (typeof (callback) !== 'function') { throw new TypeError('callback must be a function') }

  // When the socket closes, it is useful to know whether it was due to a
  // user-initiated unbind or something else.
  this.unbound = true

  if (!this._socket) { return callback() }

  const req = new UnbindRequest()
  return this._send(req, 'unbind', null, callback)
}

/**
 * Attempt to secure connection with StartTLS.
 */
Client.prototype.starttls = function starttls (options,
  controls,
  callback,
  _bypass) {
  assert.optionalObject(options)
  options = options || {}
  callback = once(callback)
  const self = this

  if (this._starttls) {
    return callback(new Error('STARTTLS already in progress or active'))
  }

  function onSend (sendErr, emitter) {
    if (sendErr) {
      callback(sendErr)
      return
    }
    /*
     * Now that the request has been sent, block all outgoing messages
     * until an error is received or we successfully complete the setup.
     */
    // TODO: block traffic
    self._starttls = {
      started: true
    }

    emitter.on('error', function (err) {
      self._starttls = null
      callback(err)
    })
    emitter.on('end', function (_res) {
      const sock = self._socket
      /*
       * Unplumb socket data during SSL negotiation.
       * This will prevent the LDAP parser from stumbling over the TLS
       * handshake and raising a ruckus.
       */
      sock.removeAllListeners('data')

      options.socket = sock
      const secure = tls.connect(options)
      secure.once('secureConnect', function () {
        /*
         * Wire up 'data' and 'error' handlers like the normal socket.
         * Handling 'end' events isn't necessary since the underlying socket
         * will handle those.
         */
        secure.removeAllListeners('error')
        secure.on('data', function onData (data) {
          self.log.trace('data event: %s', util.inspect(data))

          self._tracker.parser.write(data)
        })
        secure.on('error', function (err) {
          self.log.trace({ err }, 'error event: %s', new Error().stack)

          self.emit('error', err)
          sock.destroy()
        })
        callback(null)
      })
      secure.once('error', function (err) {
        // If the SSL negotiation failed, to back to plain mode.
        self._starttls = null
        secure.removeAllListeners()
        callback(err)
      })
      self._starttls.success = true
      self._socket = secure
    })
  }

  const req = new ExtendedRequest({
    requestName: '1.3.6.1.4.1.1466.20037',
    requestValue: null,
    controls
  })

  return this._send(req,
    [errors.LDAP_SUCCESS],
    new EventEmitter(),
    onSend,
    _bypass)
}

/**
 * Disconnect from the LDAP server and do not allow reconnection.
 *
 * If the client is instantiated with proper reconnection options, it's
 * possible to initiate new requests after a call to unbind since the client
 * will attempt to reconnect in order to fulfill the request.
 *
 * Calling destroy will prevent any further reconnection from occurring.
 *
 * @param {Object} err (Optional) error that was cause of client destruction
 */
Client.prototype.destroy = function destroy (err) {
  this.destroyed = true
  this.queue.freeze()
  // Purge any queued requests which are now meaningless
  this.queue.flush(function (msg, expect, emitter, cb) {
    if (typeof (cb) === 'function') {
      cb(new Error('client destroyed'))
    }
  })
  if (this.connected) {
    this.unbind()
  }
  if (this._socket) {
    this._socket.destroy()
  }

  this.emit('destroy', err)
}

/**
 * Initiate LDAP connection.
 */
Client.prototype.connect = function connect () {
  if (this.connecting || this.connected) {
    return
  }
  const self = this
  const log = this.log
  let socket
  let tracker

  // Establish basic socket connection
  function connectSocket (cb) {
    const server = self.urls[self._nextServer]
    self._nextServer = (self._nextServer + 1) % self.urls.length

    cb = once(cb)

    function onResult (err, res) {
      if (err) {
        if (self.connectTimer) {
          clearTimeout(self.connectTimer)
          self.connectTimer = null
        }
        self.emit('connectError', err)
      }
      cb(err, res)
    }
    function onConnect () {
      if (self.connectTimer) {
        clearTimeout(self.connectTimer)
        self.connectTimer = null
      }
      socket.removeAllListeners('error')
        .removeAllListeners('connect')
        .removeAllListeners('secureConnect')

      tracker.id = nextClientId() + '__' + tracker.id
      self.log = self.log.child({ ldap_id: tracker.id }, true)

      // Move on to client setup
      setupClient(cb)
    }

    const port = (server && server.port) || self.socketPath
    const host = server && server.hostname
    if (server && server.secure) {
      socket = tls.connect(port, host, self.tlsOptions)
      socket.once('secureConnect', onConnect)
    } else {
      socket = net.connect(port, host)
      socket.once('connect', onConnect)
    }
    socket.once('error', onResult)
    initSocket(server)

    // Setup connection timeout handling, if desired
    if (self.connectTimeout) {
      self.connectTimer = setTimeout(function onConnectTimeout () {
        if (!socket || !socket.readable || !socket.writeable) {
          socket.destroy()
          self._socket = null
          onResult(new ConnectionError('connection timeout'))
        }
      }, self.connectTimeout)
    }
  }

  // Initialize socket events and LDAP parser.
  function initSocket (server) {
    tracker = messageTrackerFactory({
      id: server ? server.href : self.socketPath,
      parser: new Parser({ log })
    })

    // This won't be set on TLS. So. Very. Annoying.
    if (typeof (socket.setKeepAlive) !== 'function') {
      socket.setKeepAlive = function setKeepAlive (enable, delay) {
        return socket.socket
          ? socket.socket.setKeepAlive(enable, delay)
          : false
      }
    }

    socket.on('data', function onData (data) {
      log.trace('data event: %s', util.inspect(data))

      tracker.parser.write(data)
    })

    // The "router"
    //
    // This is invoked after the incoming BER has been parsed into a JavaScript
    // object.
    tracker.parser.on('message', function onMessage (message) {
      message.connection = self._socket
      const { message: trackedMessage, callback } = tracker.fetch(message.messageId)

      if (!callback) {
        log.error({ message: message.pojo }, 'unsolicited message')
        return false
      }

      // Some message types have narrower implementations and require extra
      // parsing to be complete. In particular, ExtensionRequest messages will
      // return responses that do not identify the request that generated them.
      // Therefore, we have to match the response to the request and handle
      // the extra processing accordingly.
      switch (trackedMessage.type) {
        case 'ExtensionRequest': {
          const extensionType = ExtendedRequest.recognizedOIDs().lookupName(trackedMessage.requestName)
          switch (extensionType) {
            case 'PASSWORD_MODIFY': {
              message = messages.PasswordModifyResponse.fromResponse(message)
              break
            }

            case 'WHO_AM_I': {
              message = messages.WhoAmIResponse.fromResponse(message)
              break
            }

            default:
          }

          break
        }

        default:
      }

      return callback(message)
    })

    tracker.parser.on('error', function onParseError (err) {
      self.emit('error', new VError(err, 'Parser error for %s',
        tracker.id))
      self.connected = false
      socket.end()
    })
  }

  // After connect, register socket event handlers and run any setup actions
  function setupClient (cb) {
    cb = once(cb)

    // Indicate failure if anything goes awry during setup
    function bail (err) {
      socket.destroy()
      cb(err || new Error('client error during setup'))
    }
    // Work around lack of close event on tls.socket in node < 0.11
    ((socket.socket) ? socket.socket : socket).once('close', bail)
    socket.once('error', bail)
    socket.once('end', bail)
    socket.once('timeout', bail)
    socket.once('cleanupSetupListeners', function onCleanup () {
      socket.removeListener('error', bail)
        .removeListener('close', bail)
        .removeListener('end', bail)
        .removeListener('timeout', bail)
    })

    self._socket = socket
    self._tracker = tracker

    // Run any requested setup (such as automatically performing a bind) on
    // socket before signalling successful connection.
    // This setup needs to bypass the request queue since all other activity is
    // blocked until the connection is considered fully established post-setup.
    // Only allow bind/search/starttls for now.
    const basicClient = {
      bind: function bindBypass (name, credentials, controls, callback) {
        return self.bind(name, credentials, controls, callback, true)
      },
      search: function searchBypass (base, options, controls, callback) {
        return self.search(base, options, controls, callback, true)
      },
      starttls: function starttlsBypass (options, controls, callback) {
        return self.starttls(options, controls, callback, true)
      },
      unbind: self.unbind.bind(self)
    }
    vasync.forEachPipeline({
      func: function (f, callback) {
        f(basicClient, callback)
      },
      inputs: self.listeners('setup')
    }, function (err, _res) {
      if (err) {
        self.emit('setupError', err)
      }
      cb(err)
    })
  }

  // Wire up "official" event handlers after successful connect/setup
  function postSetup () {
    // cleanup the listeners we attached in setup phrase.
    socket.emit('cleanupSetupListeners');

    // Work around lack of close event on tls.socket in node < 0.11
    ((socket.socket) ? socket.socket : socket).once('close',
      self._onClose.bind(self))
    socket.on('end', function onEnd () {
      log.trace('end event')

      self.emit('end')
      socket.end()
    })
    socket.on('error', function onSocketError (err) {
      log.trace({ err }, 'error event: %s', new Error().stack)

      self.emit('error', err)
      socket.destroy()
    })
    socket.on('timeout', function onTimeout () {
      log.trace('timeout event')

      self.emit('socketTimeout')
      socket.end()
    })

    const server = self.urls[self._nextServer]
    if (server) {
      self.host = server.hostname
      self.port = server.port
      self.secure = server.secure
    }
  }

  let retry
  let failAfter
  if (this.reconnect) {
    retry = backoff.exponential({
      initialDelay: this.reconnect.initialDelay,
      maxDelay: this.reconnect.maxDelay
    })
    failAfter = this.reconnect.failAfter
    if (this.urls.length > 1 && failAfter) {
      failAfter *= this.urls.length
    }
  } else {
    retry = backoff.exponential({
      initialDelay: 1,
      maxDelay: 2
    })
    failAfter = this.urls.length || 1
  }
  retry.failAfter(failAfter)

  retry.on('ready', function (num, _delay) {
    if (self.destroyed) {
      // Cease connection attempts if destroyed
      return
    }
    connectSocket(function (err) {
      if (!err) {
        postSetup()
        self.connecting = false
        self.connected = true
        self.emit('connect', socket)
        self.log.debug('connected after %d attempt(s)', num + 1)
        // Flush any queued requests
        self._flushQueue()
        self._connectRetry = null
      } else {
        retry.backoff(err)
      }
    })
  })
  retry.on('fail', function (err) {
    if (self.destroyed) {
      // Silence any connect/setup errors if destroyed
      return
    }
    self.log.debug('failed to connect after %d attempts', failAfter)
    // Communicate the last-encountered error
    if (err instanceof ConnectionError) {
      self.emitError('connectTimeout', err)
    } else if (err.code === 'ECONNREFUSED') {
      self.emitError('connectRefused', err)
    } else {
      self.emit('error', err)
    }
  })

  this._connectRetry = retry
  this.connecting = true
  retry.backoff()
}

/// --- Private API

/**
 * Flush queued requests out to the socket.
 */
Client.prototype._flushQueue = function _flushQueue () {
  // Pull items we're about to process out of the queue.
  this.queue.flush(this._send.bind(this))
}

/**
 * Clean up socket/parser resources after socket close.
 */
Client.prototype._onClose = function _onClose (closeError) {
  const socket = this._socket
  const tracker = this._tracker
  socket.removeAllListeners('connect')
    .removeAllListeners('data')
    .removeAllListeners('drain')
    .removeAllListeners('end')
    .removeAllListeners('error')
    .removeAllListeners('timeout')
  this._socket = null
  this.connected = false;

  ((socket.socket) ? socket.socket : socket).removeAllListeners('close')

  this.log.trace('close event had_err=%s', closeError ? 'yes' : 'no')

  this.emit('close', closeError)
  // On close we have to walk the outstanding messages and go invoke their
  // callback with an error.
  tracker.purge(function (msgid, cb) {
    if (socket.unbindMessageID !== msgid) {
      return cb(new ConnectionError(tracker.id + ' closed'))
    } else {
      // Unbinds will be communicated as a success since we're closed
      // TODO: we are faking this "UnbindResponse" object in order to make
      // tests pass. There is no such thing as an "unbind response" in the LDAP
      // protocol. When the client is revamped, this logic should be removed.
      // ~ jsumners 2023-02-16
      const Unbind = class extends LDAPResult {
        messageID = msgid
        messageId = msgid
        status = 'unbind'
      }
      const unbind = new Unbind()
      return cb(unbind)
    }
  })

  // Trash any parser or starttls state
  this._tracker = null
  delete this._starttls

  // Automatically fire reconnect logic if the socket was closed for any reason
  // other than a user-initiated unbind.
  if (this.reconnect && !this.unbound) {
    this.connect()
  }
  this.unbound = false
  return false
}

/**
 * Maintain idle timer for client.
 *
 * Will start timer to fire 'idle' event if conditions are satisfied.  If
 * conditions are not met and a timer is running, it will be cleared.
 *
 * @param {Boolean} override explicitly disable timer.
 */
Client.prototype._updateIdle = function _updateIdle (override) {
  if (this.idleTimeout === 0) {
    return
  }
  // Client must be connected but not waiting on any request data
  const self = this
  function isIdle (disable) {
    return ((disable !== true) &&
      (self._socket && self.connected) &&
      (self._tracker.pending === 0))
  }
  if (isIdle(override)) {
    if (!this._idleTimer) {
      this._idleTimer = setTimeout(function () {
        // Double-check idleness in case socket was torn down
        if (isIdle()) {
          self.emit('idle')
        }
      }, this.idleTimeout)
    }
  } else {
    if (this._idleTimer) {
      clearTimeout(this._idleTimer)
      this._idleTimer = null
    }
  }
}

/**
 * Attempt to send an LDAP request.
 */
Client.prototype._send = function _send (message,
  expect,
  emitter,
  callback,
  _bypass) {
  assert.ok(message)
  assert.ok(expect)
  assert.optionalObject(emitter)
  assert.ok(callback)

  // Allow connect setup traffic to bypass checks
  if (_bypass && this._socket && this._socket.writable) {
    return this._sendSocket(message, expect, emitter, callback)
  }
  if (!this._socket || !this.connected) {
    if (!this.queue.enqueue(message, expect, emitter, callback)) {
      callback(new ConnectionError('connection unavailable'))
    }
    // Initiate reconnect if needed
    if (this.reconnect) {
      this.connect()
    }
    return false
  } else {
    this._flushQueue()
    return this._sendSocket(message, expect, emitter, callback)
  }
}

Client.prototype._sendSocket = function _sendSocket (message,
  expect,
  emitter,
  callback) {
  const conn = this._socket
  const tracker = this._tracker
  const log = this.log
  const self = this
  let timer = false
  let sentEmitter = false

  function sendResult (event, obj) {
    if (event === 'error') {
      self.emit('resultError', obj)
    }
    if (emitter) {
      if (event === 'error') {
        // Error will go unhandled if emitter hasn't been sent via callback.
        // Execute callback with the error instead.
        if (!sentEmitter) { return callback(obj) }
      }
      return emitter.emit(event, obj)
    }

    if (event === 'error') { return callback(obj) }

    return callback(null, obj)
  }

  function messageCallback (msg) {
    if (timer) { clearTimeout(timer) }

    log.trace({ msg: msg ? msg.pojo : null }, 'response received')

    if (expect === 'abandon') { return sendResult('end', null) }

    if (msg instanceof SearchEntry || msg instanceof SearchReference) {
      let event = msg.constructor.name
      // Generate the event name for the event emitter, i.e. "searchEntry"
      // and "searchReference".
      event = (event[0].toLowerCase() + event.slice(1)).replaceAll('Result', '')
      return sendResult(event, msg)
    } else {
      tracker.remove(message.messageId)
      // Potentially mark client as idle
      self._updateIdle()

      if (msg instanceof LDAPResult) {
        if (msg.status !== 0 && expect.indexOf(msg.status) === -1) {
          return sendResult('error', errors.getError(msg))
        }
        return sendResult('end', msg)
      } else if (msg instanceof Error) {
        return sendResult('error', msg)
      } else {
        return sendResult('error', new errors.ProtocolError(msg.type))
      }
    }
  }

  function onRequestTimeout () {
    self.emit('timeout', message)
    const { callback: cb } = tracker.fetch(message.messageId)
    if (cb) {
      // FIXME: the timed-out request should be abandoned
      cb(new errors.TimeoutError('request timeout (client interrupt)'))
    }
  }

  function writeCallback () {
    if (expect === 'abandon') {
      // Mark the messageId specified as abandoned
      tracker.abandon(message.abandonId)
      // No need to track the abandon request itself
      tracker.remove(message.id)
      return callback(null)
    } else if (expect === 'unbind') {
      conn.unbindMessageID = message.id
      // Mark client as disconnected once unbind clears the socket
      self.connected = false
      // Some servers will RST the connection after receiving an unbind.
      // Socket errors are blackholed since the connection is being closed.
      conn.removeAllListeners('error')
      conn.on('error', function () {})
      conn.end()
    } else if (emitter) {
      sentEmitter = true
      callback(null, emitter)
      emitter.emit('searchRequest', message)
      return
    }
    return false
  }

  // Start actually doing something...
  tracker.track(message, messageCallback)
  // Mark client as active
  this._updateIdle(true)

  if (self.timeout) {
    log.trace('Setting timeout to %d', self.timeout)
    timer = setTimeout(onRequestTimeout, self.timeout)
  }

  log.trace('sending request %j', message.pojo)

  try {
    const messageBer = message.toBer()
    return conn.write(messageBer.buffer, writeCallback)
  } catch (e) {
    if (timer) { clearTimeout(timer) }

    log.trace({ err: e }, 'Error writing message to socket')
    return callback(e)
  }
}

Client.prototype.emitError = function emitError (event, err) {
  if (event !== 'error' && err && this.listenerCount(event) === 0) {
    if (typeof err === 'string') {
      err = event + ': ' + err
    } else if (err.message) {
      err.message = event + ': ' + err.message
    }
    this.emit('error', err)
  }
  this.emit(event, err)
}

}).call(this)}).call(this,{"isBuffer":require("../../../is-buffer/index.js")})
},{"../../../is-buffer/index.js":128,"../controls/index":144,"../corked_emitter":145,"../errors":147,"../messages/parser":151,"../url":155,"./constants":133,"./message-tracker":137,"./request-queue":141,"./search_pager":143,"@ldapjs/attribute":7,"@ldapjs/change":9,"@ldapjs/controls":10,"@ldapjs/dn":27,"@ldapjs/filter":55,"@ldapjs/messages":64,"@ldapjs/protocol":93,"assert-plus":95,"backoff":101,"events":114,"net":109,"once":157,"tls":109,"util":190,"vasync":191,"verror":193}],133:[function(require,module,exports){
'use strict'

module.exports = {
  // https://tools.ietf.org/html/rfc4511#section-4.1.1
  // Message identifiers are an integer between (0, maxint).
  MAX_MSGID: Math.pow(2, 31) - 1
}

},{}],134:[function(require,module,exports){
'use strict'

const logger = require('../logger')
const Client = require('./client')

module.exports = {
  Client,
  createClient: function createClient (options) {
    if (isObject(options) === false) throw TypeError('options (object) required')
    if (options.url && typeof options.url !== 'string' && !Array.isArray(options.url)) throw TypeError('options.url (string|array) required')
    if (options.socketPath && typeof options.socketPath !== 'string') throw TypeError('options.socketPath must be a string')
    if ((options.url && options.socketPath) || !(options.url || options.socketPath)) throw TypeError('options.url ^ options.socketPath (String) required')
    if (!options.log) options.log = logger
    if (isObject(options.log) !== true) throw TypeError('options.log must be an object')
    if (!options.log.child) options.log.child = function () { return options.log }

    return new Client(options)
  }
}

function isObject (input) {
  return Object.prototype.toString.apply(input) === '[object Object]'
}

},{"../logger":149,"./client":132}],135:[function(require,module,exports){
'use strict'

const { MAX_MSGID } = require('../constants')

/**
 * Compare a reference id with another id to determine "greater than or equal"
 * between the two values according to a sliding window.
 *
 * @param {integer} ref
 * @param {integer} comp
 *
 * @returns {boolean} `true` if the `comp` value is >= to the `ref` value
 * within the computed window, otherwise `false`.
 */
module.exports = function geWindow (ref, comp) {
  let max = ref + Math.floor(MAX_MSGID / 2)
  const min = ref
  if (max >= MAX_MSGID) {
    // Handle roll-over
    max = max - MAX_MSGID - 1
    return ((comp <= max) || (comp >= min))
  } else {
    return ((comp <= max) && (comp >= min))
  }
}

},{"../constants":133}],136:[function(require,module,exports){
'use strict'

const { MAX_MSGID } = require('../constants')

/**
 * Returns a function that generates message identifiers. According to RFC 4511
 * the identifers should be `(0, MAX_MSGID)`. The returned function handles
 * this and wraps around when the maximum has been reached.
 *
 * @param {integer} [start=0] Starting number in the identifier sequence.
 *
 * @returns {function} This function accepts no parameters and returns an
 * increasing sequence identifier each invocation until it reaches the maximum
 * identifier. At this point the sequence starts over.
 */
module.exports = function idGeneratorFactory (start = 0) {
  let currentID = start
  return function nextID () {
    const id = currentID + 1
    currentID = (id >= MAX_MSGID) ? 1 : id
    return currentID
  }
}

},{"../constants":133}],137:[function(require,module,exports){
'use strict'

const idGeneratorFactory = require('./id-generator')
const purgeAbandoned = require('./purge-abandoned')

/**
 * Returns a message tracker object that keeps track of which message
 * identifiers correspond to which message handlers. Also handles keeping track
 * of abandoned messages.
 *
 * @param {object} options
 * @param {string} options.id An identifier for the tracker.
 * @param {object} options.parser An object that will be used to parse messages.
 *
 * @returns {MessageTracker}
 */
module.exports = function messageTrackerFactory (options) {
  if (Object.prototype.toString.call(options) !== '[object Object]') {
    throw Error('options object is required')
  }
  if (!options.id || typeof options.id !== 'string') {
    throw Error('options.id string is required')
  }
  if (!options.parser || Object.prototype.toString.call(options.parser) !== '[object Object]') {
    throw Error('options.parser object is required')
  }

  let currentID = 0
  const nextID = idGeneratorFactory()
  const messages = new Map()
  const abandoned = new Map()

  /**
   * @typedef {object} MessageTracker
   * @property {string} id The identifier of the tracker as supplied via the options.
   * @property {object} parser The parser object given by the the options.
   */
  const tracker = {
    id: options.id,
    parser: options.parser
  }

  /**
   * Count of messages awaiting response.
   *
   * @alias pending
   * @memberof! MessageTracker#
   */
  Object.defineProperty(tracker, 'pending', {
    get () {
      return messages.size
    }
  })

  /**
   * Move a specific message to the abanded track.
   *
   * @param {integer} msgID The identifier for the message to move.
   *
   * @memberof MessageTracker
   * @method abandon
   */
  tracker.abandon = function abandonMessage (msgID) {
    if (messages.has(msgID) === false) return false
    const toAbandon = messages.get(msgID)
    abandoned.set(msgID, {
      age: currentID,
      message: toAbandon.message,
      cb: toAbandon.callback
    })
    return messages.delete(msgID)
  }

  /**
   * @typedef {object} Tracked
   * @property {object} message The tracked message. Usually the outgoing
   * request object.
   * @property {Function} callback The handler to use when receiving a
   * response to the tracked message.
   */

  /**
   * Retrieves the message handler for a message. Removes abandoned messages
   * that have been given time to be resolved.
   *
   * @param {integer} msgID The identifier for the message to get the handler for.
   *
   * @memberof MessageTracker
   * @method fetch
   */
  tracker.fetch = function fetchMessage (msgID) {
    const tracked = messages.get(msgID)
    if (tracked) {
      purgeAbandoned(msgID, abandoned)
      return tracked
    }

    // We sent an abandon request but the server either wasn't able to process
    // it or has not received it yet. Therefore, we received a response for the
    // abandoned message. So we must return the abandoned message's callback
    // to be processed normally.
    const abandonedMsg = abandoned.get(msgID)
    if (abandonedMsg) {
      return { message: abandonedMsg, callback: abandonedMsg.cb }
    }

    return null
  }

  /**
   * Removes all message tracks, cleans up the abandoned track, and invokes
   * a callback for each message purged.
   *
   * @param {function} cb A function with the signature `(msgID, handler)`.
   *
   * @memberof MessageTracker
   * @method purge
   */
  tracker.purge = function purgeMessages (cb) {
    messages.forEach((val, key) => {
      purgeAbandoned(key, abandoned)
      tracker.remove(key)
      cb(key, val.callback)
    })
  }

  /**
   * Removes a message from all tracking.
   *
   * @param {integer} msgID The identifier for the message to remove from tracking.
   *
   * @memberof MessageTracker
   * @method remove
   */
  tracker.remove = function removeMessage (msgID) {
    if (messages.delete(msgID) === false) {
      abandoned.delete(msgID)
    }
  }

  /**
   * Add a message handler to be tracked.
   *
   * @param {object} message The message object to be tracked. This object will
   * have a new property added to it: `messageId`.
   * @param {function} callback The handler for the message.
   *
   * @memberof MessageTracker
   * @method track
   */
  tracker.track = function trackMessage (message, callback) {
    currentID = nextID()
    // This side effect is not ideal but the client doesn't attach the tracker
    // to itself until after the `.connect` method has fired. If this can be
    // refactored later, then we can possibly get rid of this side effect.
    message.messageId = currentID
    messages.set(currentID, { callback, message })
  }

  return tracker
}

},{"./id-generator":136,"./purge-abandoned":138}],138:[function(require,module,exports){
'use strict'

const { AbandonedError } = require('../../errors')
const geWindow = require('./ge-window')

/**
 * Given a `msgID` and a set of `abandoned` messages, remove any abandoned
 * messages that existed _prior_ to the specified `msgID`. For example, let's
 * assume the server has sent 3 messages:
 *
 * 1. A search message.
 * 2. An abandon message for the search message.
 * 3. A new search message.
 *
 * When the response for message #1 comes in, if it does, it will be processed
 * normally due to the specification. Message #2 will not receive a response, or
 * if the server does send one since the spec sort of allows it, we won't do
 * anything with it because we just discard that listener. Now the response
 * for message #3 comes in. At this point, we will issue a purge of responses
 * by passing in `msgID = 3`. This result is that we will remove the tracking
 * for message #1.
 *
 * @param {integer} msgID An upper bound for the messages to be purged.
 * @param {Map} abandoned A set of abandoned messages. Each message is an object
 * `{ age: <id>, cb: <func> }` where `age` was the current message id when the
 * abandon message was sent.
 */
module.exports = function purgeAbandoned (msgID, abandoned) {
  abandoned.forEach((val, key) => {
    if (geWindow(val.age, msgID) === false) return
    val.cb(new AbandonedError('client request abandoned'))
    abandoned.delete(key)
  })
}

},{"../../errors":147,"./ge-window":135}],139:[function(require,module,exports){
'use strict'

/**
 * Adds requests to the queue. If a timeout has been added to the queue then
 * this will freeze the queue with the newly added item, flush it, and then
 * unfreeze it when the queue has been cleared.
 *
 * @param {object} message An LDAP message object.
 * @param {object} expect An expectation object.
 * @param {object} emitter An event emitter or `null`.
 * @param {function} cb A callback to invoke when the request is finished.
 *
 * @returns {boolean} `true` if the requested was queued. `false` if the queue
 * is not accepting any requests.
 */
module.exports = function enqueue (message, expect, emitter, cb) {
  if (this._queue.size >= this.size || this._frozen) {
    return false
  }

  this._queue.add({ message, expect, emitter, cb })

  if (this.timeout === 0) return true
  if (this._timer === null) return true

  // A queue can have a specified time allotted for it to be cleared. If that
  // time has been reached, reject new entries until the queue has been cleared.
  this._timer = setTimeout(queueTimeout.bind(this), this.timeout)

  return true

  function queueTimeout () {
    this.freeze()
    this.purge()
  }
}

},{}],140:[function(require,module,exports){
'use strict'

/**
 * Invokes all requests in the queue by passing them to the supplied callback
 * function and then clears all items from the queue.
 *
 * @param {function} cb A function used to handle the requests.
 */
module.exports = function flush (cb) {
  if (this._timer) {
    clearTimeout(this._timer)
    this._timer = null
  }

  // We must get a local copy of the queue and clear it before iterating it.
  // The client will invoke this flush function _many_ times. If we try to
  // iterate it without a local copy and clearing first then we will overflow
  // the stack.
  const requests = Array.from(this._queue.values())
  this._queue.clear()
  for (const req of requests) {
    cb(req.message, req.expect, req.emitter, req.cb)
  }
}

},{}],141:[function(require,module,exports){
'use strict'

const enqueue = require('./enqueue')
const flush = require('./flush')
const purge = require('./purge')

/**
 * Builds a request queue object and returns it.
 *
 * @param {object} [options]
 * @param {integer} [options.size] Maximum size of the request queue. Must be
 * a number greater than `0` if supplied. Default: `Infinity`.
 * @param {integer} [options.timeout] Time in milliseconds a queue has to
 * complete the requests it contains.
 *
 * @returns {object} A queue instance.
 */
module.exports = function requestQueueFactory (options) {
  const opts = Object.assign({}, options)
  const q = {
    size: (opts.size > 0) ? opts.size : Infinity,
    timeout: (opts.timeout > 0) ? opts.timeout : 0,
    _queue: new Set(),
    _timer: null,
    _frozen: false
  }

  q.enqueue = enqueue.bind(q)
  q.flush = flush.bind(q)
  q.purge = purge.bind(q)
  q.freeze = function freeze () {
    this._frozen = true
  }
  q.thaw = function thaw () {
    this._frozen = false
  }

  return q
}

},{"./enqueue":139,"./flush":140,"./purge":142}],142:[function(require,module,exports){
'use strict'

const { TimeoutError } = require('../../errors')

/**
 * Flushes the queue by rejecting all pending requests with a timeout error.
 */
module.exports = function purge () {
  this.flush(function flushCB (a, b, c, cb) {
    cb(new TimeoutError('request queue timeout'))
  })
}

},{"../../errors":147}],143:[function(require,module,exports){
'use strict'

const EventEmitter = require('events').EventEmitter
const util = require('util')
const assert = require('assert-plus')
const { PagedResultsControl } = require('@ldapjs/controls')
const CorkedEmitter = require('../corked_emitter.js')

/// --- API

/**
 * Handler object for paged search operations.
 *
 * Provided to consumers in place of the normal search EventEmitter it adds the
 * following new events:
 * 1. page      - Emitted whenever the end of a result page is encountered.
 *                If this is the last page, 'end' will also be emitted.
 *                The event passes two arguments:
 *                1. The result object (similar to 'end')
 *                2. A callback function optionally used to continue the search
 *                   operation if the pagePause option was specified during
 *                   initialization.
 * 2. pageError - Emitted if the server does not support paged search results
 *                If there are no listeners for this event, the 'error' event
 *                will be emitted (and 'end' will not be).  By listening to
 *                'pageError', a successful search that lacks paging will be
 *                able to emit 'end'.
 */
function SearchPager (opts) {
  assert.object(opts)
  assert.func(opts.callback)
  assert.number(opts.pageSize)
  assert.func(opts.sendRequest)

  CorkedEmitter.call(this, {})

  this.callback = opts.callback
  this.controls = opts.controls
  this.pageSize = opts.pageSize
  this.pagePause = opts.pagePause
  this.sendRequest = opts.sendRequest

  this.controls.forEach(function (control) {
    if (control.type === PagedResultsControl.OID) {
      // The point of using SearchPager is not having to do this.
      // Toss an error if the pagedResultsControl is present
      throw new Error('redundant pagedResultControl')
    }
  })

  this.finished = false
  this.started = false

  const emitter = new EventEmitter()
  emitter.on('searchRequest', this.emit.bind(this, 'searchRequest'))
  emitter.on('searchEntry', this.emit.bind(this, 'searchEntry'))
  emitter.on('end', this._onEnd.bind(this))
  emitter.on('error', this._onError.bind(this))
  this.childEmitter = emitter
}
util.inherits(SearchPager, CorkedEmitter)
module.exports = SearchPager

/**
 * Start the paged search.
 */
SearchPager.prototype.begin = function begin () {
  // Starting first page
  this._nextPage(null)
}

SearchPager.prototype._onEnd = function _onEnd (res) {
  const self = this
  let cookie = null
  res.controls.forEach(function (control) {
    if (control.type === PagedResultsControl.OID) {
      cookie = control.value.cookie
    }
  })
  // Pass a noop callback by default for page events
  const nullCb = function () { }

  if (cookie === null) {
    // paged search not supported
    this.finished = true
    this.emit('page', res, nullCb)
    const err = new Error('missing paged control')
    err.name = 'PagedError'
    if (this.listeners('pageError').length > 0) {
      this.emit('pageError', err)
      // If the consumer as subscribed to pageError, SearchPager is absolved
      // from delivering the fault via the 'error' event.  Emitting an 'end'
      // event after 'error' breaks the contract that the standard client
      // provides, so it's only a possibility if 'pageError' is used instead.
      this.emit('end', res)
    } else {
      this.emit('error', err)
      // No end event possible per explanation above.
    }
    return
  }

  if (cookie.length === 0) {
    // end of paged results
    this.finished = true
    this.emit('page', nullCb)
    this.emit('end', res)
  } else {
    if (this.pagePause) {
      // Wait to fetch next page until callback is invoked
      // Halt page fetching if called with error
      this.emit('page', res, function (err) {
        if (!err) {
          self._nextPage(cookie)
        } else {
          // the paged search has been canceled so emit an end
          self.emit('end', res)
        }
      })
    } else {
      this.emit('page', res, nullCb)
      this._nextPage(cookie)
    }
  }
}

SearchPager.prototype._onError = function _onError (err) {
  this.finished = true
  this.emit('error', err)
}

/**
 * Initiate a search for the next page using the returned cookie value.
 */
SearchPager.prototype._nextPage = function _nextPage (cookie) {
  const controls = this.controls.slice(0)
  controls.push(new PagedResultsControl({
    value: {
      size: this.pageSize,
      cookie
    }
  }))

  this.sendRequest(controls, this.childEmitter, this._sendCallback.bind(this))
}

/**
 * Callback provided to the client API for successful transmission.
 */
SearchPager.prototype._sendCallback = function _sendCallback (err) {
  if (err) {
    this.finished = true
    if (!this.started) {
      // EmitSend error during the first page, bail via callback
      this.callback(err, null)
    } else {
      this.emit('error', err)
    }
  } else {
    // search successfully send
    if (!this.started) {
      this.started = true
      // send self as emitter as the client would
      this.callback(null, this)
    }
  }
}

},{"../corked_emitter.js":145,"@ldapjs/controls":10,"assert-plus":95,"events":114,"util":190}],144:[function(require,module,exports){
// Copyright 2011 Mark Cavage, Inc.  All rights reserved.

const controls = require('@ldapjs/controls')
module.exports = controls

},{"@ldapjs/controls":10}],145:[function(require,module,exports){
(function (setImmediate){(function (){
'use strict'

const EventEmitter = require('events').EventEmitter

/**
 * A CorkedEmitter is a variant of an EventEmitter where events emitted
 *  wait for the appearance of the first listener of any kind. That is,
 *  a CorkedEmitter will store all .emit()s it receives, to be replayed
 *  later when an .on() is applied.
 * It is meant for situations where the consumers of the emitter are
 *  unable to register listeners right away, and cannot afford to miss
 *  any events emitted from the start.
 * Note that, whenever the first emitter (for any event) appears,
 *  the emitter becomes uncorked and works as usual for ALL events, and
 *  will not cache anything anymore. This is necessary to avoid
 *  re-ordering emits - either everything is being buffered, or nothing.
 */
function CorkedEmitter () {
  const self = this
  EventEmitter.call(self)
  /**
     * An array of arguments objects (array-likes) to emit on open.
     */
  self._outstandingEmits = []
  /**
     * Whether the normal flow of emits is restored yet.
     */
  self._opened = false
  // When the first listener appears, we enqueue an opening.
  // It is not done immediately, so that other listeners can be
  //  registered in the same critical section.
  self.once('newListener', function () {
    setImmediate(function releaseStoredEvents () {
      self._opened = true
      self._outstandingEmits.forEach(function (args) {
        self.emit.apply(self, args)
      })
    })
  })
}
CorkedEmitter.prototype = Object.create(EventEmitter.prototype)
CorkedEmitter.prototype.emit = function emit (eventName) {
  if (this._opened || eventName === 'newListener') {
    EventEmitter.prototype.emit.apply(this, arguments)
  } else {
    this._outstandingEmits.push(arguments)
  }
}

module.exports = CorkedEmitter

}).call(this)}).call(this,require("timers").setImmediate)
},{"events":114,"timers":184}],146:[function(require,module,exports){
'use strict'

module.exports = {
  LDAP_SUCCESS: 0,
  LDAP_OPERATIONS_ERROR: 1,
  LDAP_PROTOCOL_ERROR: 2,
  LDAP_TIME_LIMIT_EXCEEDED: 3,
  LDAP_SIZE_LIMIT_EXCEEDED: 4,
  LDAP_COMPARE_FALSE: 5,
  LDAP_COMPARE_TRUE: 6,
  LDAP_AUTH_METHOD_NOT_SUPPORTED: 7,
  LDAP_STRONG_AUTH_REQUIRED: 8,
  LDAP_REFERRAL: 10,
  LDAP_ADMIN_LIMIT_EXCEEDED: 11,
  LDAP_UNAVAILABLE_CRITICAL_EXTENSION: 12,
  LDAP_CONFIDENTIALITY_REQUIRED: 13,
  LDAP_SASL_BIND_IN_PROGRESS: 14,
  LDAP_NO_SUCH_ATTRIBUTE: 16,
  LDAP_UNDEFINED_ATTRIBUTE_TYPE: 17,
  LDAP_INAPPROPRIATE_MATCHING: 18,
  LDAP_CONSTRAINT_VIOLATION: 19,
  LDAP_ATTRIBUTE_OR_VALUE_EXISTS: 20,
  LDAP_INVALID_ATTRIBUTE_SYNTAX: 21,
  LDAP_NO_SUCH_OBJECT: 32,
  LDAP_ALIAS_PROBLEM: 33,
  LDAP_INVALID_DN_SYNTAX: 34,
  LDAP_ALIAS_DEREF_PROBLEM: 36,
  LDAP_INAPPROPRIATE_AUTHENTICATION: 48,
  LDAP_INVALID_CREDENTIALS: 49,
  LDAP_INSUFFICIENT_ACCESS_RIGHTS: 50,
  LDAP_BUSY: 51,
  LDAP_UNAVAILABLE: 52,
  LDAP_UNWILLING_TO_PERFORM: 53,
  LDAP_LOOP_DETECT: 54,
  LDAP_SORT_CONTROL_MISSING: 60,
  LDAP_INDEX_RANGE_ERROR: 61,
  LDAP_NAMING_VIOLATION: 64,
  LDAP_OBJECTCLASS_VIOLATION: 65,
  LDAP_NOT_ALLOWED_ON_NON_LEAF: 66,
  LDAP_NOT_ALLOWED_ON_RDN: 67,
  LDAP_ENTRY_ALREADY_EXISTS: 68,
  LDAP_OBJECTCLASS_MODS_PROHIBITED: 69,
  LDAP_AFFECTS_MULTIPLE_DSAS: 71,
  LDAP_CONTROL_ERROR: 76,
  LDAP_OTHER: 80,
  LDAP_PROXIED_AUTHORIZATION_DENIED: 123
}

},{}],147:[function(require,module,exports){
'use strict'

const util = require('util')
const assert = require('assert-plus')

const LDAPResult = require('../messages').LDAPResult

/// --- Globals

const CODES = require('./codes')
const ERRORS = []

/// --- Error Base class

function LDAPError (message, dn, caller) {
  if (Error.captureStackTrace) { Error.captureStackTrace(this, caller || LDAPError) }

  this.lde_message = message
  this.lde_dn = dn
}
util.inherits(LDAPError, Error)
Object.defineProperties(LDAPError.prototype, {
  name: {
    get: function getName () { return 'LDAPError' },
    configurable: false
  },
  code: {
    get: function getCode () { return CODES.LDAP_OTHER },
    configurable: false
  },
  message: {
    get: function getMessage () {
      return this.lde_message || this.name
    },
    set: function setMessage (message) {
      this.lde_message = message
    },
    configurable: false
  },
  dn: {
    get: function getDN () {
      return (this.lde_dn ? this.lde_dn.toString() : '')
    },
    configurable: false
  }
})

/// --- Exported API

module.exports = {}
module.exports.LDAPError = LDAPError

// Some whacky games here to make sure all the codes are exported
Object.keys(CODES).forEach(function (code) {
  module.exports[code] = CODES[code]
  if (code === 'LDAP_SUCCESS') { return }

  let err = ''
  let msg = ''
  const pieces = code.split('_').slice(1)
  for (let i = 0; i < pieces.length; i++) {
    const lc = pieces[i].toLowerCase()
    const key = lc.charAt(0).toUpperCase() + lc.slice(1)
    err += key
    msg += key + ((i + 1) < pieces.length ? ' ' : '')
  }

  if (!/\w+Error$/.test(err)) { err += 'Error' }

  // At this point LDAP_OPERATIONS_ERROR is now OperationsError in $err
  // and 'Operations Error' in $msg
  module.exports[err] = function (message, dn, caller) {
    LDAPError.call(this, message, dn, caller || module.exports[err])
  }
  module.exports[err].constructor = module.exports[err]
  util.inherits(module.exports[err], LDAPError)
  Object.defineProperties(module.exports[err].prototype, {
    name: {
      get: function getName () { return err },
      configurable: false
    },
    code: {
      get: function getCode () { return CODES[code] },
      configurable: false
    }
  })

  ERRORS[CODES[code]] = {
    err,
    message: msg
  }
})

module.exports.getError = function (res) {
  assert.ok(res instanceof LDAPResult, 'res (LDAPResult) required')

  const errObj = ERRORS[res.status]
  const E = module.exports[errObj.err]
  return new E(res.errorMessage || errObj.message,
    res.matchedDN || null,
    module.exports.getError)
}

module.exports.getMessage = function (code) {
  assert.number(code, 'code (number) required')

  const errObj = ERRORS[code]
  return (errObj && errObj.message ? errObj.message : '')
}

/// --- Custom application errors

function ConnectionError (message) {
  LDAPError.call(this, message, null, ConnectionError)
}
util.inherits(ConnectionError, LDAPError)
module.exports.ConnectionError = ConnectionError
Object.defineProperties(ConnectionError.prototype, {
  name: {
    get: function () { return 'ConnectionError' },
    configurable: false
  }
})

function AbandonedError (message) {
  LDAPError.call(this, message, null, AbandonedError)
}
util.inherits(AbandonedError, LDAPError)
module.exports.AbandonedError = AbandonedError
Object.defineProperties(AbandonedError.prototype, {
  name: {
    get: function () { return 'AbandonedError' },
    configurable: false
  }
})

function TimeoutError (message) {
  LDAPError.call(this, message, null, TimeoutError)
}
util.inherits(TimeoutError, LDAPError)
module.exports.TimeoutError = TimeoutError
Object.defineProperties(TimeoutError.prototype, {
  name: {
    get: function () { return 'TimeoutError' },
    configurable: false
  }
})

},{"../messages":150,"./codes":146,"assert-plus":95,"util":190}],148:[function(require,module,exports){
// Copyright 2011 Mark Cavage, Inc.  All rights reserved.

const logger = require('./logger')

const client = require('./client')
const Attribute = require('@ldapjs/attribute')
const Change = require('@ldapjs/change')
const Protocol = require('@ldapjs/protocol')
const Server = require('./server')

const controls = require('./controls')
const persistentSearch = require('./persistent_search')
const dn = require('@ldapjs/dn')
const errors = require('./errors')
const filters = require('@ldapjs/filter')
const messages = require('./messages')
const url = require('./url')

const hasOwnProperty = (target, val) => Object.prototype.hasOwnProperty.call(target, val)

/// --- API

module.exports = {
  Client: client.Client,
  createClient: client.createClient,

  Server,
  createServer: function (options) {
    if (options === undefined) { options = {} }

    if (typeof (options) !== 'object') { throw new TypeError('options (object) required') }

    if (!options.log) {
      options.log = logger
    }

    return new Server(options)
  },

  Attribute,
  Change,

  dn,
  DN: dn.DN,
  RDN: dn.RDN,
  parseDN: dn.DN.fromString,

  persistentSearch,
  PersistentSearchCache: persistentSearch.PersistentSearchCache,

  filters,
  parseFilter: filters.parseString,

  url,
  parseURL: url.parse
}

/// --- Export all the childrenz

let k

for (k in Protocol) {
  if (hasOwnProperty(Protocol, k)) { module.exports[k] = Protocol[k] }
}

for (k in messages) {
  if (hasOwnProperty(messages, k)) { module.exports[k] = messages[k] }
}

for (k in controls) {
  if (hasOwnProperty(controls, k)) { module.exports[k] = controls[k] }
}

for (k in filters) {
  if (hasOwnProperty(filters, k)) {
    if (k !== 'parse' && k !== 'parseString') { module.exports[k] = filters[k] }
  }
}

for (k in errors) {
  if (hasOwnProperty(errors, k)) {
    module.exports[k] = errors[k]
  }
}

},{"./client":134,"./controls":144,"./errors":147,"./logger":149,"./messages":150,"./persistent_search":153,"./server":154,"./url":155,"@ldapjs/attribute":7,"@ldapjs/change":9,"@ldapjs/dn":27,"@ldapjs/filter":55,"@ldapjs/protocol":93}],149:[function(require,module,exports){
'use strict'

const logger = require('abstract-logging')
logger.child = function () { return logger }

module.exports = logger

},{"abstract-logging":94}],150:[function(require,module,exports){
// Copyright 2011 Mark Cavage, Inc.  All rights reserved.

const messages = require('@ldapjs/messages')

const Parser = require('./parser')

const SearchResponse = require('./search_response')

/// --- API

module.exports = {

  LDAPMessage: messages.LdapMessage,
  LDAPResult: messages.LdapResult,
  Parser,

  AbandonRequest: messages.AbandonRequest,
  AbandonResponse: messages.AbandonResponse,
  AddRequest: messages.AddRequest,
  AddResponse: messages.AddResponse,
  BindRequest: messages.BindRequest,
  BindResponse: messages.BindResponse,
  CompareRequest: messages.CompareRequest,
  CompareResponse: messages.CompareResponse,
  DeleteRequest: messages.DeleteRequest,
  DeleteResponse: messages.DeleteResponse,
  ExtendedRequest: messages.ExtensionRequest,
  ExtendedResponse: messages.ExtensionResponse,
  ModifyRequest: messages.ModifyRequest,
  ModifyResponse: messages.ModifyResponse,
  ModifyDNRequest: messages.ModifyDnRequest,
  ModifyDNResponse: messages.ModifyDnResponse,
  SearchRequest: messages.SearchRequest,
  SearchEntry: messages.SearchResultEntry,
  SearchReference: messages.SearchResultReference,
  SearchResponse,
  UnbindRequest: messages.UnbindRequest

}

},{"./parser":151,"./search_response":152,"@ldapjs/messages":64}],151:[function(require,module,exports){
(function (Buffer){(function (){
// Copyright 2011 Mark Cavage, Inc.  All rights reserved.

const EventEmitter = require('events').EventEmitter
const util = require('util')

const assert = require('assert-plus')
const asn1 = require('@ldapjs/asn1')
const logger = require('../logger')

const messages = require('@ldapjs/messages')
const AbandonRequest = messages.AbandonRequest
const AddRequest = messages.AddRequest
const AddResponse = messages.AddResponse
const BindRequest = messages.BindRequest
const BindResponse = messages.BindResponse
const CompareRequest = messages.CompareRequest
const CompareResponse = messages.CompareResponse
const DeleteRequest = messages.DeleteRequest
const DeleteResponse = messages.DeleteResponse
const ExtendedRequest = messages.ExtensionRequest
const ExtendedResponse = messages.ExtensionResponse
const ModifyRequest = messages.ModifyRequest
const ModifyResponse = messages.ModifyResponse
const ModifyDNRequest = messages.ModifyDnRequest
const ModifyDNResponse = messages.ModifyDnResponse
const SearchRequest = messages.SearchRequest
const SearchEntry = messages.SearchResultEntry
const SearchReference = messages.SearchResultReference
const SearchResponse = require('./search_response')
const UnbindRequest = messages.UnbindRequest
const LDAPResult = messages.LdapResult

const Protocol = require('@ldapjs/protocol')

/// --- Globals

const BerReader = asn1.BerReader

/// --- API

function Parser (options = {}) {
  assert.object(options)

  EventEmitter.call(this)

  this.buffer = null
  this.log = options.log || logger
}
util.inherits(Parser, EventEmitter)

/**
 * The LDAP server/client implementations will receive data from a stream and feed
 * it into this method. This method will collect that data into an internal
 * growing buffer. As that buffer fills with enough data to constitute a valid
 * LDAP message, the data will be parsed, emitted as a message object, and
 * reset the buffer to account for any next message in the stream.
 */
Parser.prototype.write = function (data) {
  if (!data || !Buffer.isBuffer(data)) { throw new TypeError('data (buffer) required') }

  let nextMessage = null
  const self = this

  function end () {
    if (nextMessage) { return self.write(nextMessage) }

    return true
  }

  self.buffer = self.buffer ? Buffer.concat([self.buffer, data]) : data

  let ber = new BerReader(self.buffer)

  let foundSeq = false
  try {
    foundSeq = ber.readSequence()
  } catch (e) {
    this.emit('error', e)
  }

  if (!foundSeq || ber.remain < ber.length) {
    // ENOTENOUGH
    return false
  } else if (ber.remain > ber.length) {
    // ETOOMUCH

    // This is an odd branch. Basically, it is setting `nextMessage` to
    // a buffer that represents data part of a message subsequent to the one
    // being processed. It then re-creates `ber` as a representation of
    // the message being processed and advances its offset to the value
    // position of the TLV.

    // Set `nextMessage` to the bytes subsequent to the current message's
    // value bytes. That is, slice from the byte immediately following the
    // current message's value bytes until the end of the buffer.
    nextMessage = self.buffer.slice(ber.offset + ber.length)

    const currOffset = ber.offset
    ber = new BerReader(ber.buffer.subarray(0, currOffset + ber.length))
    ber.readSequence()

    assert.equal(ber.remain, ber.length)
  }

  // If we're here, ber holds the message, and nextMessage is temporarily
  // pointing at the next sequence of data (if it exists)
  self.buffer = null

  let message
  try {
    if (Object.prototype.toString.call(ber) === '[object BerReader]') {
      // Parse the BER into a JavaScript object representation. The message
      // objects require the full sequence in order to construct the object.
      // At this point, we have already read the sequence tag and length, so
      // we need to rewind the buffer a bit. The `.sequenceToReader` method
      // does this for us.
      message = messages.LdapMessage.parse(ber.sequenceToReader())
    } else {
      // Bail here if peer isn't speaking protocol at all
      message = this.getMessage(ber)
    }

    if (!message) {
      return end()
    }

    // TODO: find a better way to handle logging now that messages and the
    // server are decoupled. ~ jsumners 2023-02-17
    message.log = this.log
  } catch (e) {
    this.emit('error', e, message)
    return false
  }

  this.emit('message', message)
  return end()
}

Parser.prototype.getMessage = function (ber) {
  assert.ok(ber)

  const self = this

  const messageId = ber.readInt()
  const type = ber.readSequence()

  let Message
  switch (type) {
    case Protocol.operations.LDAP_REQ_ABANDON:
      Message = AbandonRequest
      break

    case Protocol.operations.LDAP_REQ_ADD:
      Message = AddRequest
      break

    case Protocol.operations.LDAP_RES_ADD:
      Message = AddResponse
      break

    case Protocol.operations.LDAP_REQ_BIND:
      Message = BindRequest
      break

    case Protocol.operations.LDAP_RES_BIND:
      Message = BindResponse
      break

    case Protocol.operations.LDAP_REQ_COMPARE:
      Message = CompareRequest
      break

    case Protocol.operations.LDAP_RES_COMPARE:
      Message = CompareResponse
      break

    case Protocol.operations.LDAP_REQ_DELETE:
      Message = DeleteRequest
      break

    case Protocol.operations.LDAP_RES_DELETE:
      Message = DeleteResponse
      break

    case Protocol.operations.LDAP_REQ_EXTENSION:
      Message = ExtendedRequest
      break

    case Protocol.operations.LDAP_RES_EXTENSION:
      Message = ExtendedResponse
      break

    case Protocol.operations.LDAP_REQ_MODIFY:
      Message = ModifyRequest
      break

    case Protocol.operations.LDAP_RES_MODIFY:
      Message = ModifyResponse
      break

    case Protocol.operations.LDAP_REQ_MODRDN:
      Message = ModifyDNRequest
      break

    case Protocol.operations.LDAP_RES_MODRDN:
      Message = ModifyDNResponse
      break

    case Protocol.operations.LDAP_REQ_SEARCH:
      Message = SearchRequest
      break

    case Protocol.operations.LDAP_RES_SEARCH_ENTRY:
      Message = SearchEntry
      break

    case Protocol.operations.LDAP_RES_SEARCH_REF:
      Message = SearchReference
      break

    case Protocol.operations.LDAP_RES_SEARCH:
      Message = SearchResponse
      break

    case Protocol.operations.LDAP_REQ_UNBIND:
      Message = UnbindRequest
      break

    default:
      this.emit('error',
        new Error('Op 0x' + (type ? type.toString(16) : '??') +
                        ' not supported'),
        new LDAPResult({
          messageId,
          protocolOp: type || Protocol.operations.LDAP_RES_EXTENSION
        }))

      return false
  }

  return new Message({
    messageId,
    log: self.log
  })
}

/// --- Exports

module.exports = Parser

}).call(this)}).call(this,require("buffer").Buffer)
},{"../logger":149,"./search_response":152,"@ldapjs/asn1":2,"@ldapjs/messages":64,"@ldapjs/protocol":93,"assert-plus":95,"buffer":110,"events":114,"util":190}],152:[function(require,module,exports){
// Copyright 2011 Mark Cavage, Inc.  All rights reserved.

const assert = require('assert-plus')

const Attribute = require('@ldapjs/attribute')
const {
  SearchResultEntry: SearchEntry,
  SearchResultReference: SearchReference,
  SearchResultDone
} = require('@ldapjs/messages')

const parseDN = require('@ldapjs/dn').DN.fromString

/// --- API

class SearchResponse extends SearchResultDone {
  attributes
  notAttributes
  sentEntries

  constructor (options = {}) {
    super(options)

    this.attributes = options.attributes ? options.attributes.slice() : []
    this.notAttributes = []
    this.sentEntries = 0
  }
}

/**
 * Allows you to send a SearchEntry back to the client.
 *
 * @param {Object} entry an instance of SearchEntry.
 * @param {Boolean} nofiltering skip filtering notAttributes and '_' attributes.
 *                  Defaults to 'false'.
 */
SearchResponse.prototype.send = function (entry, nofiltering) {
  if (!entry || typeof (entry) !== 'object') { throw new TypeError('entry (SearchEntry) required') }
  if (nofiltering === undefined) { nofiltering = false }
  if (typeof (nofiltering) !== 'boolean') { throw new TypeError('noFiltering must be a boolean') }

  const self = this

  const savedAttrs = {}
  let save = null
  if (entry instanceof SearchEntry || entry instanceof SearchReference) {
    if (!entry.messageId) { entry.messageId = this.messageId }
    if (entry.messageId !== this.messageId) {
      throw new Error('SearchEntry messageId mismatch')
    }
  } else {
    if (!entry.attributes) { throw new Error('entry.attributes required') }

    const all = (self.attributes.indexOf('*') !== -1)
    // Filter attributes in a plain object according to the magic `_` prefix
    // and presence in `notAttributes`.
    Object.keys(entry.attributes).forEach(function (a) {
      const _a = a.toLowerCase()
      if (!nofiltering && _a.length && _a[0] === '_') {
        savedAttrs[a] = entry.attributes[a]
        delete entry.attributes[a]
      } else if (!nofiltering && self.notAttributes.indexOf(_a) !== -1) {
        savedAttrs[a] = entry.attributes[a]
        delete entry.attributes[a]
      } else if (all) {
        // do nothing
      } else if (self.attributes.length && self.attributes.indexOf(_a) === -1) {
        savedAttrs[a] = entry.attributes[a]
        delete entry.attributes[a]
      }
    })

    save = entry
    entry = new SearchEntry({
      objectName: typeof (save.dn) === 'string' ? parseDN(save.dn) : save.dn,
      messageId: self.messageId,
      attributes: Attribute.fromObject(entry.attributes)
    })
  }

  try {
    this.log.debug('%s: sending:  %j', this.connection.ldap.id, entry.pojo)

    this.connection.write(entry.toBer().buffer)
    this.sentEntries++

    // Restore attributes
    Object.keys(savedAttrs).forEach(function (k) {
      save.attributes[k] = savedAttrs[k]
    })
  } catch (e) {
    this.log.warn(e, '%s failure to write message %j',
      this.connection.ldap.id, this.pojo)
  }
}

SearchResponse.prototype.createSearchEntry = function (object) {
  assert.object(object)

  const entry = new SearchEntry({
    messageId: this.messageId,
    objectName: object.objectName || object.dn,
    attributes: object.attributes ?? []
  })
  return entry
}

SearchResponse.prototype.createSearchReference = function (uris) {
  if (!uris) { throw new TypeError('uris ([string]) required') }

  if (!Array.isArray(uris)) { uris = [uris] }

  const self = this
  return new SearchReference({
    messageId: self.messageId,
    uri: uris
  })
}

/// --- Exports

module.exports = SearchResponse

},{"@ldapjs/attribute":7,"@ldapjs/dn":27,"@ldapjs/messages":64,"assert-plus":95}],153:[function(require,module,exports){
/// --- Globals

// var parseDN = require('./dn').parse

const EntryChangeNotificationControl =
  require('./controls').EntryChangeNotificationControl

/// --- API

// Cache used to store connected persistent search clients
function PersistentSearch () {
  this.clientList = []
}

PersistentSearch.prototype.addClient = function (req, res, callback) {
  if (typeof (req) !== 'object') { throw new TypeError('req must be an object') }
  if (typeof (res) !== 'object') { throw new TypeError('res must be an object') }
  if (callback && typeof (callback) !== 'function') { throw new TypeError('callback must be a function') }

  const log = req.log

  const client = {}
  client.req = req
  client.res = res

  log.debug('%s storing client', req.logId)

  this.clientList.push(client)

  log.debug('%s stored client', req.logId)
  log.debug('%s total number of clients %s',
    req.logId, this.clientList.length)
  if (callback) { callback(client) }
}

PersistentSearch.prototype.removeClient = function (req, res, callback) {
  if (typeof (req) !== 'object') { throw new TypeError('req must be an object') }
  if (typeof (res) !== 'object') { throw new TypeError('res must be an object') }
  if (callback && typeof (callback) !== 'function') { throw new TypeError('callback must be a function') }

  const log = req.log
  log.debug('%s removing client', req.logId)
  const client = {}
  client.req = req
  client.res = res

  // remove the client if it exists
  this.clientList.forEach(function (element, index, array) {
    if (element.req === client.req) {
      log.debug('%s removing client from list', req.logId)
      array.splice(index, 1)
    }
  })

  log.debug('%s number of persistent search clients %s',
    req.logId, this.clientList.length)
  if (callback) { callback(client) }
}

function getOperationType (requestType) {
  switch (requestType) {
    case 'AddRequest':
    case 'add':
      return 1
    case 'DeleteRequest':
    case 'delete':
      return 2
    case 'ModifyRequest':
    case 'modify':
      return 4
    case 'ModifyDNRequest':
    case 'modrdn':
      return 8
    default:
      throw new TypeError('requestType %s, is an invalid request type',
        requestType)
  }
}

function getEntryChangeNotificationControl (req, obj) {
  // if we want to return a ECNC
  if (req.persistentSearch.value.returnECs) {
    const attrs = obj.attributes
    const value = {}
    value.changeType = getOperationType(attrs.changetype)
    // if it's a modDN request, fill in the previous DN
    if (value.changeType === 8 && attrs.previousDN) {
      value.previousDN = attrs.previousDN
    }

    value.changeNumber = attrs.changenumber
    return new EntryChangeNotificationControl({ value })
  } else {
    return false
  }
}

function checkChangeType (req, requestType) {
  return (req.persistentSearch.value.changeTypes &
          getOperationType(requestType))
}

/// --- Exports

module.exports = {
  PersistentSearchCache: PersistentSearch,
  checkChangeType,
  getEntryChangeNotificationControl
}

},{"./controls":144}],154:[function(require,module,exports){
(function (Buffer){(function (){
// Copyright 2011 Mark Cavage, Inc.  All rights reserved.

const assert = require('assert')
const EventEmitter = require('events').EventEmitter
const net = require('net')
const tls = require('tls')
const util = require('util')

// var asn1 = require('@ldapjs/asn1')
const VError = require('verror').VError

const { DN, RDN } = require('@ldapjs/dn')
const errors = require('./errors')
const Protocol = require('@ldapjs/protocol')

const messages = require('@ldapjs/messages')

const Parser = require('./messages').Parser
const LdapResult = messages.LdapResult
const AbandonResponse = messages.AbandonResponse
const AddResponse = messages.AddResponse
const BindResponse = messages.BindResponse
const CompareResponse = messages.CompareResponse
const DeleteResponse = messages.DeleteResponse
const ExtendedResponse = messages.ExtensionResponse
const ModifyResponse = messages.ModifyResponse
const ModifyDnResponse = messages.ModifyDnResponse
const SearchRequest = messages.SearchRequest
const SearchResponse = require('./messages/search_response')

/// --- Globals

// var Ber = asn1.Ber
// var BerReader = asn1.BerReader
// const DN = dn.DN

// var sprintf = util.format

/// --- Helpers

function mergeFunctionArgs (argv, start, end) {
  assert.ok(argv)

  if (!start) { start = 0 }
  if (!end) { end = argv.length }

  const handlers = []

  for (let i = start; i < end; i++) {
    if (argv[i] instanceof Array) {
      const arr = argv[i]
      for (let j = 0; j < arr.length; j++) {
        if (!(arr[j] instanceof Function)) {
          throw new TypeError('Invalid argument type: ' + typeof (arr[j]))
        }
        handlers.push(arr[j])
      }
    } else if (argv[i] instanceof Function) {
      handlers.push(argv[i])
    } else {
      throw new TypeError('Invalid argument type: ' + typeof (argv[i]))
    }
  }

  return handlers
}

function getResponse (req) {
  assert.ok(req)

  let Response

  switch (req.protocolOp) {
    case Protocol.operations.LDAP_REQ_BIND:
      Response = BindResponse
      break
    case Protocol.operations.LDAP_REQ_ABANDON:
      Response = AbandonResponse
      break
    case Protocol.operations.LDAP_REQ_ADD:
      Response = AddResponse
      break
    case Protocol.operations.LDAP_REQ_COMPARE:
      Response = CompareResponse
      break
    case Protocol.operations.LDAP_REQ_DELETE:
      Response = DeleteResponse
      break
    case Protocol.operations.LDAP_REQ_EXTENSION:
      Response = ExtendedResponse
      break
    case Protocol.operations.LDAP_REQ_MODIFY:
      Response = ModifyResponse
      break
    case Protocol.operations.LDAP_REQ_MODRDN:
      Response = ModifyDnResponse
      break
    case Protocol.operations.LDAP_REQ_SEARCH:
      Response = SearchResponse
      break
    case Protocol.operations.LDAP_REQ_UNBIND:
      // TODO: when the server receives an unbind request this made up response object was returned.
      // Instead, we need to just terminate the connection. ~ jsumners
      Response = class extends LdapResult {
        status = 0
        end () {
          req.connection.end()
        }
      }
      break
    default:
      return null
  }
  assert.ok(Response)

  const res = new Response({
    messageId: req.messageId,
    attributes: ((req instanceof SearchRequest) ? req.attributes : undefined)
  })
  res.log = req.log
  res.connection = req.connection
  res.logId = req.logId

  if (typeof res.end !== 'function') {
    // This is a hack to re-add the original tight coupling of the message
    // objects and the server connection.
    // TODO: remove this during server refactoring ~ jsumners 2023-02-16
    switch (res.protocolOp) {
      case 0: {
        res.end = abandonResponseEnd
        break
      }

      case Protocol.operations.LDAP_RES_COMPARE: {
        res.end = compareResponseEnd
        break
      }

      default: {
        res.end = defaultResponseEnd
        break
      }
    }
  }

  return res
}

/**
 * Response connection end handler for most responses.
 *
 * @param {number} status
 */
function defaultResponseEnd (status) {
  if (typeof status === 'number') { this.status = status }

  const ber = this.toBer()
  this.log.debug('%s: sending: %j', this.connection.ldap.id, this.pojo)

  try {
    this.connection.write(ber.buffer)
  } catch (error) {
    this.log.warn(
      error,
      '%s failure to write message %j',
      this.connection.ldap.id,
      this.pojo
    )
  }
}

/**
 * Response connection end handler for ABANDON responses.
 */
function abandonResponseEnd () {}

/**
 * Response connection end handler for COMPARE responses.
 *
 * @param {number | boolean} status
 */
function compareResponseEnd (status) {
  let result = 0x06
  if (typeof status === 'boolean') {
    if (status === false) {
      result = 0x05
    }
  } else {
    result = status
  }
  return defaultResponseEnd.call(this, result)
}

function defaultHandler (req, res, next) {
  assert.ok(req)
  assert.ok(res)
  assert.ok(next)

  res.matchedDN = req.dn.toString()
  res.errorMessage = 'Server method not implemented'
  res.end(errors.LDAP_OTHER)
  return next()
}

function defaultNoOpHandler (req, res, next) {
  assert.ok(req)
  assert.ok(res)
  assert.ok(next)

  res.end()
  return next()
}

function noSuffixHandler (req, res, next) {
  assert.ok(req)
  assert.ok(res)
  assert.ok(next)

  res.errorMessage = 'No tree found for: ' + req.dn.toString()
  res.end(errors.LDAP_NO_SUCH_OBJECT)
  return next()
}

function noExOpHandler (req, res, next) {
  assert.ok(req)
  assert.ok(res)
  assert.ok(next)

  res.errorMessage = req.requestName + ' not supported'
  res.end(errors.LDAP_PROTOCOL_ERROR)
  return next()
}

/// --- API

/**
 * Constructs a new server that you can call .listen() on, in the various
 * forms node supports.  You need to first assign some handlers to the various
 * LDAP operations however.
 *
 * The options object currently only takes a certificate/private key, and a
 * bunyan logger handle.
 *
 * This object exposes the following events:
 *  - 'error'
 *  - 'close'
 *
 * @param {Object} options (optional) parameterization object.
 * @throws {TypeError} on bad input.
 */
function Server (options) {
  if (options) {
    if (typeof (options) !== 'object') { throw new TypeError('options (object) required') }
    if (typeof (options.log) !== 'object') { throw new TypeError('options.log must be an object') }

    if (options.certificate || options.key) {
      if (!(options.certificate && options.key) ||
          (typeof (options.certificate) !== 'string' &&
          !Buffer.isBuffer(options.certificate)) ||
          (typeof (options.key) !== 'string' &&
          !Buffer.isBuffer(options.key))) {
        throw new TypeError('options.certificate and options.key ' +
                            '(string or buffer) are both required for TLS')
      }
    }
  } else {
    options = {}
  }
  const self = this

  EventEmitter.call(this, options)

  this._chain = []
  this.log = options.log
  const log = this.log

  function setupConnection (c) {
    assert.ok(c)

    if (c.type === 'unix') {
      c.remoteAddress = self.server.path
      c.remotePort = c.fd
    } else if (c.socket) {
      // TLS
      c.remoteAddress = c.socket.remoteAddress
      c.remotePort = c.socket.remotePort
    }

    const rdn = new RDN({ cn: 'anonymous' })

    c.ldap = {
      id: c.remoteAddress + ':' + c.remotePort,
      config: options,
      _bindDN: new DN({ rdns: [rdn] })
    }
    c.addListener('timeout', function () {
      log.trace('%s timed out', c.ldap.id)
      c.destroy()
    })
    c.addListener('end', function () {
      log.trace('%s shutdown', c.ldap.id)
    })
    c.addListener('error', function (err) {
      log.warn('%s unexpected connection error', c.ldap.id, err)
      self.emit('clientError', err)
      c.destroy()
    })
    c.addListener('close', function (closeError) {
      log.trace('%s close; had_err=%j', c.ldap.id, closeError)
      c.end()
    })

    c.ldap.__defineGetter__('bindDN', function () {
      return c.ldap._bindDN
    })
    c.ldap.__defineSetter__('bindDN', function (val) {
      if (Object.prototype.toString.call(val) !== '[object LdapDn]') {
        throw new TypeError('DN required')
      }

      c.ldap._bindDN = val
      return val
    })
    return c
  }

  self.newConnection = function (conn) {
    // TODO: make `newConnection` available on the `Server` prototype
    // https://github.com/ldapjs/node-ldapjs/pull/727/files#r636572294
    setupConnection(conn)
    log.trace('new connection from %s', conn.ldap.id)

    conn.parser = new Parser({
      log: options.log
    })
    conn.parser.on('message', function (req) {
      // TODO: this is mutating the `@ldapjs/message` objects.
      // We should avoid doing that. ~ jsumners 2023-02-16
      req.connection = conn
      req.logId = conn.ldap.id + '::' + req.messageId
      req.startTime = new Date().getTime()

      log.debug('%s: message received: req=%j', conn.ldap.id, req.pojo)

      const res = getResponse(req)
      if (!res) {
        log.warn('Unimplemented server method: %s', req.type)
        conn.destroy()
        return false
      }

      // parse string DNs for routing/etc
      try {
        switch (req.protocolOp) {
          case Protocol.operations.LDAP_REQ_BIND: {
            req.name = DN.fromString(req.name)
            break
          }

          case Protocol.operations.LDAP_REQ_ADD:
          case Protocol.operations.LDAP_REQ_COMPARE:
          case Protocol.operations.LDAP_REQ_DELETE: {
            if (typeof req.entry === 'string') {
              req.entry = DN.fromString(req.entry)
            } else if (Object.prototype.toString.call(req.entry) !== '[object LdapDn]') {
              throw Error('invalid entry object for operation')
            }
            break
          }

          case Protocol.operations.LDAP_REQ_MODIFY: {
            req.object = DN.fromString(req.object)
            break
          }

          case Protocol.operations.LDAP_REQ_MODRDN: {
            if (typeof req.entry === 'string') {
              req.entry = DN.fromString(req.entry)
            } else if (Object.prototype.toString.call(req.entry) !== '[object LdapDn]') {
              throw Error('invalid entry object for operation')
            }
            // TODO: handle newRdn/Superior
            break
          }

          case Protocol.operations.LDAP_REQ_SEARCH: {
            break
          }

          default: {
            break
          }
        }
      } catch (e) {
        return res.end(errors.LDAP_INVALID_DN_SYNTAX)
      }

      res.connection = conn
      res.logId = req.logId
      res.requestDN = req.dn

      const chain = self._getHandlerChain(req, res)

      let i = 0
      return (function messageIIFE (err) {
        function sendError (sendErr) {
          res.status = sendErr.code || errors.LDAP_OPERATIONS_ERROR
          res.matchedDN = req.suffix ? req.suffix.toString() : ''
          res.errorMessage = sendErr.message || ''
          return res.end()
        }

        function after () {
          if (!self._postChain || !self._postChain.length) { return }

          function next () {} // stub out next for the post chain

          self._postChain.forEach(function (cb) {
            cb.call(self, req, res, next)
          })
        }

        if (err) {
          log.trace('%s sending error: %s', req.logId, err.stack || err)
          self.emit('clientError', err)
          sendError(err)
          return after()
        }

        try {
          const next = messageIIFE
          if (chain.handlers[i]) { return chain.handlers[i++].call(chain.backend, req, res, next) }

          if (req.protocolOp === Protocol.operations.LDAP_REQ_BIND && res.status === 0) {
            // 0 length == anonymous bind
            if (req.dn.length === 0 && req.credentials === '') {
              conn.ldap.bindDN = new DN({ rdns: [new RDN({ cn: 'anonymous' })] })
            } else {
              conn.ldap.bindDN = DN.fromString(req.dn)
            }
          }

          // unbind clear bindDN for safety
          // conn should terminate on unbind (RFC4511 4.3)
          if (req.protocolOp === Protocol.operations.LDAP_REQ_UNBIND && res.status === 0) {
            conn.ldap.bindDN = new DN({ rdns: [new RDN({ cn: 'anonymous' })] })
          }

          return after()
        } catch (e) {
          if (!e.stack) { e.stack = e.toString() }
          log.error('%s uncaught exception: %s', req.logId, e.stack)
          return sendError(new errors.OperationsError(e.message))
        }
      }())
    })

    conn.parser.on('error', function (err, message) {
      self.emit('error', new VError(err, 'Parser error for %s', conn.ldap.id))

      if (!message) { return conn.destroy() }

      const res = getResponse(message)
      if (!res) { return conn.destroy() }

      res.status = 0x02 // protocol error
      res.errorMessage = err.toString()
      return conn.end(res.toBer())
    })

    conn.on('data', function (data) {
      log.trace('data on %s: %s', conn.ldap.id, util.inspect(data))

      conn.parser.write(data)
    })
  } // end newConnection

  this.routes = {}
  if ((options.cert || options.certificate) && options.key) {
    options.cert = options.cert || options.certificate
    this.server = tls.createServer(options, options.connectionRouter ? options.connectionRouter : self.newConnection)
  } else {
    this.server = net.createServer(options.connectionRouter ? options.connectionRouter : self.newConnection)
  }
  this.server.log = options.log
  this.server.ldap = {
    config: options
  }
  this.server.on('close', function () {
    self.emit('close')
  })
  this.server.on('error', function (err) {
    self.emit('error', err)
  })
}
util.inherits(Server, EventEmitter)
Object.defineProperties(Server.prototype, {
  maxConnections: {
    get: function getMaxConnections () {
      return this.server.maxConnections
    },
    set: function setMaxConnections (val) {
      this.server.maxConnections = val
    },
    configurable: false
  },
  connections: {
    get: function getConnections () {
      return this.server.connections
    },
    configurable: false
  },
  name: {
    get: function getName () {
      return 'LDAPServer'
    },
    configurable: false
  },
  url: {
    get: function getURL () {
      let str
      const addr = this.server.address()
      if (!addr) {
        return null
      }
      if (!addr.family) {
        str = 'ldapi://'
        str += this.host.replace(/\//g, '%2f')
        return str
      }
      if (this.server instanceof tls.Server) {
        str = 'ldaps://'
      } else {
        str = 'ldap://'
      }

      let host = this.host
      // Node 18 switched family from returning a string to returning a number
      // https://nodejs.org/api/net.html#serveraddress
      if (addr.family === 'IPv6' || addr.family === 6) {
        host = '[' + this.host + ']'
      }

      str += host + ':' + this.port
      return str
    },
    configurable: false
  }
})
module.exports = Server

/**
 * Adds a handler (chain) for the LDAP add method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name the DN to mount this handler chain at.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.add = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_ADD, name, args)
}

/**
 * Adds a handler (chain) for the LDAP bind method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name the DN to mount this handler chain at.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.bind = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_BIND, name, args)
}

/**
 * Adds a handler (chain) for the LDAP compare method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name the DN to mount this handler chain at.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.compare = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_COMPARE, name, args)
}

/**
 * Adds a handler (chain) for the LDAP delete method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name the DN to mount this handler chain at.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.del = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_DELETE, name, args)
}

/**
 * Adds a handler (chain) for the LDAP exop method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name OID to assign this handler chain to.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input.
 */
Server.prototype.exop = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_EXTENSION, name, args, true)
}

/**
 * Adds a handler (chain) for the LDAP modify method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name the DN to mount this handler chain at.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.modify = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_MODIFY, name, args)
}

/**
 * Adds a handler (chain) for the LDAP modifyDN method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name the DN to mount this handler chain at.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.modifyDN = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_MODRDN, name, args)
}

/**
 * Adds a handler (chain) for the LDAP search method.
 *
 * Note that this is of the form f(name, [function]) where the second...N
 * arguments can all either be functions or arrays of functions.
 *
 * @param {String} name the DN to mount this handler chain at.
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.search = function (name) {
  const args = Array.prototype.slice.call(arguments, 1)
  return this._mount(Protocol.operations.LDAP_REQ_SEARCH, name, args)
}

/**
 * Adds a handler (chain) for the LDAP unbind method.
 *
 * This method is different than the others and takes no mount point, as unbind
 * is a connection-wide operation, not constrianed to part of the DIT.
 *
 * @return {Server} this so you can chain calls.
 * @throws {TypeError} on bad input
 */
Server.prototype.unbind = function () {
  const args = Array.prototype.slice.call(arguments, 0)
  return this._mount(Protocol.operations.LDAP_REQ_UNBIND, 'unbind', args, true)
}

Server.prototype.use = function use () {
  const args = Array.prototype.slice.call(arguments)
  const chain = mergeFunctionArgs(args, 0, args.length)
  const self = this
  chain.forEach(function (c) {
    self._chain.push(c)
  })
}

Server.prototype.after = function () {
  if (!this._postChain) { this._postChain = [] }

  const self = this
  mergeFunctionArgs(arguments).forEach(function (h) {
    self._postChain.push(h)
  })
}

// All these just re-expose the requisite net.Server APIs
Server.prototype.listen = function (port, host, callback) {
  if (typeof (port) !== 'number' && typeof (port) !== 'string') { throw new TypeError('port (number or path) required') }

  if (typeof (host) === 'function') {
    callback = host
    host = '127.0.0.1'
  }
  if (typeof (port) === 'string' && /^[0-9]+$/.test(port)) {
    // Disambiguate between string ports and file paths
    port = parseInt(port, 10)
  }
  const self = this

  function cbListen () {
    if (typeof (port) === 'number') {
      self.host = self.address().address
      self.port = self.address().port
    } else {
      self.host = port
      self.port = self.server.fd
    }

    if (typeof (callback) === 'function') { callback() }
  }

  if (typeof (port) === 'number') {
    return this.server.listen(port, host, cbListen)
  } else {
    return this.server.listen(port, cbListen)
  }
}
Server.prototype.listenFD = function (fd) {
  this.host = 'unix-domain-socket'
  this.port = fd
  return this.server.listenFD(fd)
}
Server.prototype.close = function (callback) {
  return this.server.close(callback)
}
Server.prototype.address = function () {
  return this.server.address()
}

Server.prototype.getConnections = function (callback) {
  return this.server.getConnections(callback)
}

Server.prototype._getRoute = function (_dn, backend) {
  if (!backend) { backend = this }

  let name
  if (Object.prototype.toString.call(_dn) === '[object LdapDn]') {
    name = _dn.toString()
  } else {
    name = _dn
  }

  if (!this.routes[name]) {
    this.routes[name] = {}
    this.routes[name].backend = backend
    this.routes[name].dn = _dn
    // Force regeneration of the route key cache on next request
    this._routeKeyCache = null
  }

  return this.routes[name]
}

Server.prototype._sortedRouteKeys = function _sortedRouteKeys () {
  // The filtered/sorted route keys are cached to prevent needlessly
  // regenerating the list for every incoming request.
  if (!this._routeKeyCache) {
    const self = this
    const reversedRDNsToKeys = {}
    // Generate mapping of reversedRDNs(DN) -> routeKey
    Object.keys(this.routes).forEach(function (key) {
      const _dn = self.routes[key].dn
      // Ignore non-DN routes such as exop or unbind
      if (Object.prototype.toString.call(_dn) === '[object LdapDn]') {
        const reversed = _dn.clone()
        reversed.reverse()
        reversedRDNsToKeys[reversed.toString()] = key
      }
    })
    const output = []
    // Reverse-sort on reversedRDS(DN) in order to output routeKey list.
    // This will place more specific DNs in front of their parents:
    // 1. dc=test, dc=domain, dc=sub
    // 2. dc=test, dc=domain
    // 3. dc=other, dc=foobar
    Object.keys(reversedRDNsToKeys).sort().reverse().forEach(function (_dn) {
      output.push(reversedRDNsToKeys[_dn])
    })
    this._routeKeyCache = output
  }
  return this._routeKeyCache
}

Server.prototype._getHandlerChain = function _getHandlerChain (req) {
  assert.ok(req)

  const self = this
  const routes = this.routes
  let route

  // check anonymous bind
  if (req.protocolOp === Protocol.operations.LDAP_REQ_BIND &&
      req.dn.toString() === '' &&
      req.credentials === '') {
    return {
      backend: self,
      handlers: [defaultNoOpHandler]
    }
  }

  const op = '0x' + req.protocolOp.toString(16)

  // Special cases are exops, unbinds and abandons. Handle those first.
  if (req.protocolOp === Protocol.operations.LDAP_REQ_EXTENSION) {
    route = routes[req.requestName]
    if (route) {
      return {
        backend: route.backend,
        handlers: (route[op] ? route[op] : [noExOpHandler])
      }
    } else {
      return {
        backend: self,
        handlers: [noExOpHandler]
      }
    }
  } else if (req.protocolOp === Protocol.operations.LDAP_REQ_UNBIND) {
    route = routes.unbind
    if (route) {
      return {
        backend: route.backend,
        handlers: route[op]
      }
    } else {
      return {
        backend: self,
        handlers: [defaultNoOpHandler]
      }
    }
  } else if (req.protocolOp === Protocol.operations.LDAP_REQ_ABANDON) {
    return {
      backend: self,
      handlers: [defaultNoOpHandler]
    }
  }

  // Otherwise, match via DN rules
  assert.ok(req.dn)
  const keys = this._sortedRouteKeys()
  let fallbackHandler = [noSuffixHandler]
  // invalid DNs in non-strict mode are routed to the default handler
  const testDN = (typeof (req.dn) === 'string') ? DN.fromString(req.dn) : req.dn

  for (let i = 0; i < keys.length; i++) {
    const suffix = keys[i]
    route = routes[suffix]
    assert.ok(route.dn)
    // Match a valid route or the route wildcard ('')
    if (route.dn.equals(testDN) || route.dn.parentOf(testDN) || suffix === '') {
      if (route[op]) {
        // We should be good to go.
        req.suffix = route.dn
        return {
          backend: route.backend,
          handlers: route[op]
        }
      } else {
        if (suffix === '') {
          break
        } else {
          // We found a valid suffix but not a valid operation.
          // There might be a more generic suffix with a legitimate operation.
          fallbackHandler = [defaultHandler]
        }
      }
    }
  }
  return {
    backend: self,
    handlers: fallbackHandler
  }
}

Server.prototype._mount = function (op, name, argv, notDN) {
  assert.ok(op)
  assert.ok(name !== undefined)
  assert.ok(argv)

  if (typeof (name) !== 'string') { throw new TypeError('name (string) required') }
  if (!argv.length) { throw new Error('at least one handler required') }

  let backend = this
  let index = 0

  if (typeof (argv[0]) === 'object' && !Array.isArray(argv[0])) {
    backend = argv[0]
    index = 1
  }
  const route = this._getRoute(notDN ? name : DN.fromString(name), backend)

  const chain = this._chain.slice()
  argv.slice(index).forEach(function (a) {
    chain.push(a)
  })
  route['0x' + op.toString(16)] = mergeFunctionArgs(chain)

  return this
}

}).call(this)}).call(this,{"isBuffer":require("../../is-buffer/index.js")})
},{"../../is-buffer/index.js":128,"./errors":147,"./messages":150,"./messages/search_response":152,"@ldapjs/dn":27,"@ldapjs/messages":64,"@ldapjs/protocol":93,"assert":96,"events":114,"net":109,"tls":109,"util":190,"verror":193}],155:[function(require,module,exports){
'use strict'

const querystring = require('querystring')
const url = require('url')
const { DN } = require('@ldapjs/dn')
const filter = require('@ldapjs/filter')

module.exports = {

  parse: function (urlStr, parseDN) {
    let parsedURL
    try {
      parsedURL = new url.URL(urlStr)
    } catch (error) {
      throw new TypeError(urlStr + ' is an invalid LDAP url (scope)')
    }

    if (!parsedURL.protocol || !(parsedURL.protocol === 'ldap:' || parsedURL.protocol === 'ldaps:')) { throw new TypeError(urlStr + ' is an invalid LDAP url (protocol)') }

    const u = {
      protocol: parsedURL.protocol,
      hostname: parsedURL.hostname,
      port: parsedURL.port,
      pathname: parsedURL.pathname,
      search: parsedURL.search,
      href: parsedURL.href
    }

    u.secure = (u.protocol === 'ldaps:')

    if (!u.hostname) { u.hostname = 'localhost' }

    if (!u.port) {
      u.port = (u.secure ? 636 : 389)
    } else {
      u.port = parseInt(u.port, 10)
    }

    if (u.pathname) {
      u.pathname = querystring.unescape(u.pathname.substr(1))
      u.DN = parseDN ? DN.fromString(u.pathname) : u.pathname
    }

    if (u.search) {
      u.attributes = []
      const tmp = u.search.substr(1).split('?')
      if (tmp && tmp.length) {
        if (tmp[0]) {
          tmp[0].split(',').forEach(function (a) {
            u.attributes.push(querystring.unescape(a.trim()))
          })
        }
      }
      if (tmp[1]) {
        if (tmp[1] !== 'base' && tmp[1] !== 'one' && tmp[1] !== 'sub') { throw new TypeError(urlStr + ' is an invalid LDAP url (scope)') }
        u.scope = tmp[1]
      }
      if (tmp[2]) {
        u.filter = querystring.unescape(tmp[2])
      }
      if (tmp[3]) {
        u.extensions = querystring.unescape(tmp[3])
      }

      if (!u.scope) { u.scope = 'base' }
      if (!u.filter) { u.filter = filter.parseString('(objectclass=*)') } else { u.filter = filter.parseString(u.filter) }
    }

    return u
  }

}

},{"@ldapjs/dn":27,"@ldapjs/filter":55,"querystring":166,"url":185}],156:[function(require,module,exports){
/*
object-assign
(c) Sindre Sorhus
@license MIT
*/

'use strict';
/* eslint-disable no-unused-vars */
var getOwnPropertySymbols = Object.getOwnPropertySymbols;
var hasOwnProperty = Object.prototype.hasOwnProperty;
var propIsEnumerable = Object.prototype.propertyIsEnumerable;

function toObject(val) {
	if (val === null || val === undefined) {
		throw new TypeError('Object.assign cannot be called with null or undefined');
	}

	return Object(val);
}

function shouldUseNative() {
	try {
		if (!Object.assign) {
			return false;
		}

		// Detect buggy property enumeration order in older V8 versions.

		// https://bugs.chromium.org/p/v8/issues/detail?id=4118
		var test1 = new String('abc');  // eslint-disable-line no-new-wrappers
		test1[5] = 'de';
		if (Object.getOwnPropertyNames(test1)[0] === '5') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test2 = {};
		for (var i = 0; i < 10; i++) {
			test2['_' + String.fromCharCode(i)] = i;
		}
		var order2 = Object.getOwnPropertyNames(test2).map(function (n) {
			return test2[n];
		});
		if (order2.join('') !== '0123456789') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test3 = {};
		'abcdefghijklmnopqrst'.split('').forEach(function (letter) {
			test3[letter] = letter;
		});
		if (Object.keys(Object.assign({}, test3)).join('') !==
				'abcdefghijklmnopqrst') {
			return false;
		}

		return true;
	} catch (err) {
		// We don't expect any of the above to throw, but better to be safe.
		return false;
	}
}

module.exports = shouldUseNative() ? Object.assign : function (target, source) {
	var from;
	var to = toObject(target);
	var symbols;

	for (var s = 1; s < arguments.length; s++) {
		from = Object(arguments[s]);

		for (var key in from) {
			if (hasOwnProperty.call(from, key)) {
				to[key] = from[key];
			}
		}

		if (getOwnPropertySymbols) {
			symbols = getOwnPropertySymbols(from);
			for (var i = 0; i < symbols.length; i++) {
				if (propIsEnumerable.call(from, symbols[i])) {
					to[symbols[i]] = from[symbols[i]];
				}
			}
		}
	}

	return to;
};

},{}],157:[function(require,module,exports){
var wrappy = require('wrappy')
module.exports = wrappy(once)
module.exports.strict = wrappy(onceStrict)

once.proto = once(function () {
  Object.defineProperty(Function.prototype, 'once', {
    value: function () {
      return once(this)
    },
    configurable: true
  })

  Object.defineProperty(Function.prototype, 'onceStrict', {
    value: function () {
      return onceStrict(this)
    },
    configurable: true
  })
})

function once (fn) {
  var f = function () {
    if (f.called) return f.value
    f.called = true
    return f.value = fn.apply(this, arguments)
  }
  f.called = false
  return f
}

function onceStrict (fn) {
  var f = function () {
    if (f.called)
      throw new Error(f.onceError)
    f.called = true
    return f.value = fn.apply(this, arguments)
  }
  var name = fn.name || 'Function wrapped with `once`'
  f.onceError = name + " shouldn't be called more than once"
  f.called = false
  return f
}

},{"wrappy":195}],158:[function(require,module,exports){
/*
 * Copyright (c) 2012 Mathieu Turcotte
 * Licensed under the MIT license.
 */

module.exports = require('./lib/checks');
},{"./lib/checks":159}],159:[function(require,module,exports){
/*
 * Copyright (c) 2012 Mathieu Turcotte
 * Licensed under the MIT license.
 */

var util = require('util');

var errors = module.exports = require('./errors');

function failCheck(ExceptionConstructor, callee, messageFormat, formatArgs) {
    messageFormat = messageFormat || '';
    var message = util.format.apply(this, [messageFormat].concat(formatArgs));
    var error = new ExceptionConstructor(message);
    Error.captureStackTrace(error, callee);
    throw error;
}

function failArgumentCheck(callee, message, formatArgs) {
    failCheck(errors.IllegalArgumentError, callee, message, formatArgs);
}

function failStateCheck(callee, message, formatArgs) {
    failCheck(errors.IllegalStateError, callee, message, formatArgs);
}

module.exports.checkArgument = function(value, message) {
    if (!value) {
        failArgumentCheck(arguments.callee, message,
            Array.prototype.slice.call(arguments, 2));
    }
};

module.exports.checkState = function(value, message) {
    if (!value) {
        failStateCheck(arguments.callee, message,
            Array.prototype.slice.call(arguments, 2));
    }
};

module.exports.checkIsDef = function(value, message) {
    if (value !== undefined) {
        return value;
    }

    failArgumentCheck(arguments.callee, message ||
        'Expected value to be defined but was undefined.',
        Array.prototype.slice.call(arguments, 2));
};

module.exports.checkIsDefAndNotNull = function(value, message) {
    // Note that undefined == null.
    if (value != null) {
        return value;
    }

    failArgumentCheck(arguments.callee, message ||
        'Expected value to be defined and not null but got "' +
        typeOf(value) + '".', Array.prototype.slice.call(arguments, 2));
};

// Fixed version of the typeOf operator which returns 'null' for null values
// and 'array' for arrays.
function typeOf(value) {
    var s = typeof value;
    if (s == 'object') {
        if (!value) {
            return 'null';
        } else if (value instanceof Array) {
            return 'array';
        }
    }
    return s;
}

function typeCheck(expect) {
    return function(value, message) {
        var type = typeOf(value);

        if (type == expect) {
            return value;
        }

        failArgumentCheck(arguments.callee, message ||
            'Expected "' + expect + '" but got "' + type + '".',
            Array.prototype.slice.call(arguments, 2));
    };
}

module.exports.checkIsString = typeCheck('string');
module.exports.checkIsArray = typeCheck('array');
module.exports.checkIsNumber = typeCheck('number');
module.exports.checkIsBoolean = typeCheck('boolean');
module.exports.checkIsFunction = typeCheck('function');
module.exports.checkIsObject = typeCheck('object');

},{"./errors":160,"util":190}],160:[function(require,module,exports){
/*
 * Copyright (c) 2012 Mathieu Turcotte
 * Licensed under the MIT license.
 */

var util = require('util');

function IllegalArgumentError(message) {
    Error.call(this, message);
    this.message = message;
}
util.inherits(IllegalArgumentError, Error);

IllegalArgumentError.prototype.name = 'IllegalArgumentError';

function IllegalStateError(message) {
    Error.call(this, message);
    this.message = message;
}
util.inherits(IllegalStateError, Error);

IllegalStateError.prototype.name = 'IllegalStateError';

module.exports.IllegalStateError = IllegalStateError;
module.exports.IllegalArgumentError = IllegalArgumentError;
},{"util":190}],161:[function(require,module,exports){
(function (process){(function (){
'use strict'

const { format } = require('util')

function processWarning () {
  const codes = {}
  const emitted = new Map()

  function create (name, code, message) {
    if (!name) throw new Error('Warning name must not be empty')
    if (!code) throw new Error('Warning code must not be empty')
    if (!message) throw new Error('Warning message must not be empty')

    code = code.toUpperCase()

    if (codes[code] !== undefined) {
      throw new Error(`The code '${code}' already exist`)
    }

    function buildWarnOpts (a, b, c) {
      // more performant than spread (...) operator
      let formatted
      if (a && b && c) {
        formatted = format(message, a, b, c)
      } else if (a && b) {
        formatted = format(message, a, b)
      } else if (a) {
        formatted = format(message, a)
      } else {
        formatted = message
      }

      return {
        code,
        name,
        message: formatted
      }
    }

    emitted.set(code, false)
    codes[code] = buildWarnOpts

    return codes[code]
  }

  function emit (code, a, b, c) {
    if (emitted.get(code) === true) return
    if (codes[code] === undefined) throw new Error(`The code '${code}' does not exist`)
    emitted.set(code, true)

    const warning = codes[code](a, b, c)
    process.emitWarning(warning.message, warning.name, warning.code)
  }

  return {
    create,
    emit,
    emitted
  }
}

module.exports = processWarning
module.exports.default = processWarning
module.exports.processWarning = processWarning

}).call(this)}).call(this,require('_process'))
},{"_process":162,"util":190}],162:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],163:[function(require,module,exports){
(function (global){(function (){
/*! https://mths.be/punycode v1.4.1 by @mathias */
;(function(root) {

	/** Detect free variables */
	var freeExports = typeof exports == 'object' && exports &&
		!exports.nodeType && exports;
	var freeModule = typeof module == 'object' && module &&
		!module.nodeType && module;
	var freeGlobal = typeof global == 'object' && global;
	if (
		freeGlobal.global === freeGlobal ||
		freeGlobal.window === freeGlobal ||
		freeGlobal.self === freeGlobal
	) {
		root = freeGlobal;
	}

	/**
	 * The `punycode` object.
	 * @name punycode
	 * @type Object
	 */
	var punycode,

	/** Highest positive signed 32-bit float value */
	maxInt = 2147483647, // aka. 0x7FFFFFFF or 2^31-1

	/** Bootstring parameters */
	base = 36,
	tMin = 1,
	tMax = 26,
	skew = 38,
	damp = 700,
	initialBias = 72,
	initialN = 128, // 0x80
	delimiter = '-', // '\x2D'

	/** Regular expressions */
	regexPunycode = /^xn--/,
	regexNonASCII = /[^\x20-\x7E]/, // unprintable ASCII chars + non-ASCII chars
	regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g, // RFC 3490 separators

	/** Error messages */
	errors = {
		'overflow': 'Overflow: input needs wider integers to process',
		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
		'invalid-input': 'Invalid input'
	},

	/** Convenience shortcuts */
	baseMinusTMin = base - tMin,
	floor = Math.floor,
	stringFromCharCode = String.fromCharCode,

	/** Temporary variable */
	key;

	/*--------------------------------------------------------------------------*/

	/**
	 * A generic error utility function.
	 * @private
	 * @param {String} type The error type.
	 * @returns {Error} Throws a `RangeError` with the applicable error message.
	 */
	function error(type) {
		throw new RangeError(errors[type]);
	}

	/**
	 * A generic `Array#map` utility function.
	 * @private
	 * @param {Array} array The array to iterate over.
	 * @param {Function} callback The function that gets called for every array
	 * item.
	 * @returns {Array} A new array of values returned by the callback function.
	 */
	function map(array, fn) {
		var length = array.length;
		var result = [];
		while (length--) {
			result[length] = fn(array[length]);
		}
		return result;
	}

	/**
	 * A simple `Array#map`-like wrapper to work with domain name strings or email
	 * addresses.
	 * @private
	 * @param {String} domain The domain name or email address.
	 * @param {Function} callback The function that gets called for every
	 * character.
	 * @returns {Array} A new string of characters returned by the callback
	 * function.
	 */
	function mapDomain(string, fn) {
		var parts = string.split('@');
		var result = '';
		if (parts.length > 1) {
			// In email addresses, only the domain name should be punycoded. Leave
			// the local part (i.e. everything up to `@`) intact.
			result = parts[0] + '@';
			string = parts[1];
		}
		// Avoid `split(regex)` for IE8 compatibility. See #17.
		string = string.replace(regexSeparators, '\x2E');
		var labels = string.split('.');
		var encoded = map(labels, fn).join('.');
		return result + encoded;
	}

	/**
	 * Creates an array containing the numeric code points of each Unicode
	 * character in the string. While JavaScript uses UCS-2 internally,
	 * this function will convert a pair of surrogate halves (each of which
	 * UCS-2 exposes as separate characters) into a single code point,
	 * matching UTF-16.
	 * @see `punycode.ucs2.encode`
	 * @see <https://mathiasbynens.be/notes/javascript-encoding>
	 * @memberOf punycode.ucs2
	 * @name decode
	 * @param {String} string The Unicode input string (UCS-2).
	 * @returns {Array} The new array of code points.
	 */
	function ucs2decode(string) {
		var output = [],
		    counter = 0,
		    length = string.length,
		    value,
		    extra;
		while (counter < length) {
			value = string.charCodeAt(counter++);
			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
				// high surrogate, and there is a next character
				extra = string.charCodeAt(counter++);
				if ((extra & 0xFC00) == 0xDC00) { // low surrogate
					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
				} else {
					// unmatched surrogate; only append this code unit, in case the next
					// code unit is the high surrogate of a surrogate pair
					output.push(value);
					counter--;
				}
			} else {
				output.push(value);
			}
		}
		return output;
	}

	/**
	 * Creates a string based on an array of numeric code points.
	 * @see `punycode.ucs2.decode`
	 * @memberOf punycode.ucs2
	 * @name encode
	 * @param {Array} codePoints The array of numeric code points.
	 * @returns {String} The new Unicode string (UCS-2).
	 */
	function ucs2encode(array) {
		return map(array, function(value) {
			var output = '';
			if (value > 0xFFFF) {
				value -= 0x10000;
				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
				value = 0xDC00 | value & 0x3FF;
			}
			output += stringFromCharCode(value);
			return output;
		}).join('');
	}

	/**
	 * Converts a basic code point into a digit/integer.
	 * @see `digitToBasic()`
	 * @private
	 * @param {Number} codePoint The basic numeric code point value.
	 * @returns {Number} The numeric value of a basic code point (for use in
	 * representing integers) in the range `0` to `base - 1`, or `base` if
	 * the code point does not represent a value.
	 */
	function basicToDigit(codePoint) {
		if (codePoint - 48 < 10) {
			return codePoint - 22;
		}
		if (codePoint - 65 < 26) {
			return codePoint - 65;
		}
		if (codePoint - 97 < 26) {
			return codePoint - 97;
		}
		return base;
	}

	/**
	 * Converts a digit/integer into a basic code point.
	 * @see `basicToDigit()`
	 * @private
	 * @param {Number} digit The numeric value of a basic code point.
	 * @returns {Number} The basic code point whose value (when used for
	 * representing integers) is `digit`, which needs to be in the range
	 * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
	 * used; else, the lowercase form is used. The behavior is undefined
	 * if `flag` is non-zero and `digit` has no uppercase form.
	 */
	function digitToBasic(digit, flag) {
		//  0..25 map to ASCII a..z or A..Z
		// 26..35 map to ASCII 0..9
		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
	}

	/**
	 * Bias adaptation function as per section 3.4 of RFC 3492.
	 * https://tools.ietf.org/html/rfc3492#section-3.4
	 * @private
	 */
	function adapt(delta, numPoints, firstTime) {
		var k = 0;
		delta = firstTime ? floor(delta / damp) : delta >> 1;
		delta += floor(delta / numPoints);
		for (/* no initialization */; delta > baseMinusTMin * tMax >> 1; k += base) {
			delta = floor(delta / baseMinusTMin);
		}
		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
	}

	/**
	 * Converts a Punycode string of ASCII-only symbols to a string of Unicode
	 * symbols.
	 * @memberOf punycode
	 * @param {String} input The Punycode string of ASCII-only symbols.
	 * @returns {String} The resulting string of Unicode symbols.
	 */
	function decode(input) {
		// Don't use UCS-2
		var output = [],
		    inputLength = input.length,
		    out,
		    i = 0,
		    n = initialN,
		    bias = initialBias,
		    basic,
		    j,
		    index,
		    oldi,
		    w,
		    k,
		    digit,
		    t,
		    /** Cached calculation results */
		    baseMinusT;

		// Handle the basic code points: let `basic` be the number of input code
		// points before the last delimiter, or `0` if there is none, then copy
		// the first basic code points to the output.

		basic = input.lastIndexOf(delimiter);
		if (basic < 0) {
			basic = 0;
		}

		for (j = 0; j < basic; ++j) {
			// if it's not a basic code point
			if (input.charCodeAt(j) >= 0x80) {
				error('not-basic');
			}
			output.push(input.charCodeAt(j));
		}

		// Main decoding loop: start just after the last delimiter if any basic code
		// points were copied; start at the beginning otherwise.

		for (index = basic > 0 ? basic + 1 : 0; index < inputLength; /* no final expression */) {

			// `index` is the index of the next character to be consumed.
			// Decode a generalized variable-length integer into `delta`,
			// which gets added to `i`. The overflow checking is easier
			// if we increase `i` as we go, then subtract off its starting
			// value at the end to obtain `delta`.
			for (oldi = i, w = 1, k = base; /* no condition */; k += base) {

				if (index >= inputLength) {
					error('invalid-input');
				}

				digit = basicToDigit(input.charCodeAt(index++));

				if (digit >= base || digit > floor((maxInt - i) / w)) {
					error('overflow');
				}

				i += digit * w;
				t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);

				if (digit < t) {
					break;
				}

				baseMinusT = base - t;
				if (w > floor(maxInt / baseMinusT)) {
					error('overflow');
				}

				w *= baseMinusT;

			}

			out = output.length + 1;
			bias = adapt(i - oldi, out, oldi == 0);

			// `i` was supposed to wrap around from `out` to `0`,
			// incrementing `n` each time, so we'll fix that now:
			if (floor(i / out) > maxInt - n) {
				error('overflow');
			}

			n += floor(i / out);
			i %= out;

			// Insert `n` at position `i` of the output
			output.splice(i++, 0, n);

		}

		return ucs2encode(output);
	}

	/**
	 * Converts a string of Unicode symbols (e.g. a domain name label) to a
	 * Punycode string of ASCII-only symbols.
	 * @memberOf punycode
	 * @param {String} input The string of Unicode symbols.
	 * @returns {String} The resulting Punycode string of ASCII-only symbols.
	 */
	function encode(input) {
		var n,
		    delta,
		    handledCPCount,
		    basicLength,
		    bias,
		    j,
		    m,
		    q,
		    k,
		    t,
		    currentValue,
		    output = [],
		    /** `inputLength` will hold the number of code points in `input`. */
		    inputLength,
		    /** Cached calculation results */
		    handledCPCountPlusOne,
		    baseMinusT,
		    qMinusT;

		// Convert the input in UCS-2 to Unicode
		input = ucs2decode(input);

		// Cache the length
		inputLength = input.length;

		// Initialize the state
		n = initialN;
		delta = 0;
		bias = initialBias;

		// Handle the basic code points
		for (j = 0; j < inputLength; ++j) {
			currentValue = input[j];
			if (currentValue < 0x80) {
				output.push(stringFromCharCode(currentValue));
			}
		}

		handledCPCount = basicLength = output.length;

		// `handledCPCount` is the number of code points that have been handled;
		// `basicLength` is the number of basic code points.

		// Finish the basic string - if it is not empty - with a delimiter
		if (basicLength) {
			output.push(delimiter);
		}

		// Main encoding loop:
		while (handledCPCount < inputLength) {

			// All non-basic code points < n have been handled already. Find the next
			// larger one:
			for (m = maxInt, j = 0; j < inputLength; ++j) {
				currentValue = input[j];
				if (currentValue >= n && currentValue < m) {
					m = currentValue;
				}
			}

			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
			// but guard against overflow
			handledCPCountPlusOne = handledCPCount + 1;
			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
				error('overflow');
			}

			delta += (m - n) * handledCPCountPlusOne;
			n = m;

			for (j = 0; j < inputLength; ++j) {
				currentValue = input[j];

				if (currentValue < n && ++delta > maxInt) {
					error('overflow');
				}

				if (currentValue == n) {
					// Represent delta as a generalized variable-length integer
					for (q = delta, k = base; /* no condition */; k += base) {
						t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
						if (q < t) {
							break;
						}
						qMinusT = q - t;
						baseMinusT = base - t;
						output.push(
							stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0))
						);
						q = floor(qMinusT / baseMinusT);
					}

					output.push(stringFromCharCode(digitToBasic(q, 0)));
					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
					delta = 0;
					++handledCPCount;
				}
			}

			++delta;
			++n;

		}
		return output.join('');
	}

	/**
	 * Converts a Punycode string representing a domain name or an email address
	 * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
	 * it doesn't matter if you call it on a string that has already been
	 * converted to Unicode.
	 * @memberOf punycode
	 * @param {String} input The Punycoded domain name or email address to
	 * convert to Unicode.
	 * @returns {String} The Unicode representation of the given Punycode
	 * string.
	 */
	function toUnicode(input) {
		return mapDomain(input, function(string) {
			return regexPunycode.test(string)
				? decode(string.slice(4).toLowerCase())
				: string;
		});
	}

	/**
	 * Converts a Unicode string representing a domain name or an email address to
	 * Punycode. Only the non-ASCII parts of the domain name will be converted,
	 * i.e. it doesn't matter if you call it with a domain that's already in
	 * ASCII.
	 * @memberOf punycode
	 * @param {String} input The domain name or email address to convert, as a
	 * Unicode string.
	 * @returns {String} The Punycode representation of the given domain name or
	 * email address.
	 */
	function toASCII(input) {
		return mapDomain(input, function(string) {
			return regexNonASCII.test(string)
				? 'xn--' + encode(string)
				: string;
		});
	}

	/*--------------------------------------------------------------------------*/

	/** Define the public API */
	punycode = {
		/**
		 * A string representing the current Punycode.js version number.
		 * @memberOf punycode
		 * @type String
		 */
		'version': '1.4.1',
		/**
		 * An object of methods to convert from JavaScript's internal character
		 * representation (UCS-2) to Unicode code points, and back.
		 * @see <https://mathiasbynens.be/notes/javascript-encoding>
		 * @memberOf punycode
		 * @type Object
		 */
		'ucs2': {
			'decode': ucs2decode,
			'encode': ucs2encode
		},
		'decode': decode,
		'encode': encode,
		'toASCII': toASCII,
		'toUnicode': toUnicode
	};

	/** Expose `punycode` */
	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (
		typeof define == 'function' &&
		typeof define.amd == 'object' &&
		define.amd
	) {
		define('punycode', function() {
			return punycode;
		});
	} else if (freeExports && freeModule) {
		if (module.exports == freeExports) {
			// in Node.js, io.js, or RingoJS v0.8.0+
			freeModule.exports = punycode;
		} else {
			// in Narwhal or RingoJS v0.7.0-
			for (key in punycode) {
				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
			}
		}
	} else {
		// in Rhino or a web browser
		root.punycode = punycode;
	}

}(this));

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],164:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707
function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = function(qs, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var obj = {};

  if (typeof qs !== 'string' || qs.length === 0) {
    return obj;
  }

  var regexp = /\+/g;
  qs = qs.split(sep);

  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }

  var len = qs.length;
  // maxKeys <= 0 means that we should not limit keys count
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; ++i) {
    var x = qs[i].replace(regexp, '%20'),
        idx = x.indexOf(eq),
        kstr, vstr, k, v;

    if (idx >= 0) {
      kstr = x.substr(0, idx);
      vstr = x.substr(idx + 1);
    } else {
      kstr = x;
      vstr = '';
    }

    k = decodeURIComponent(kstr);
    v = decodeURIComponent(vstr);

    if (!hasOwnProperty(obj, k)) {
      obj[k] = v;
    } else if (isArray(obj[k])) {
      obj[k].push(v);
    } else {
      obj[k] = [obj[k], v];
    }
  }

  return obj;
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

},{}],165:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var stringifyPrimitive = function(v) {
  switch (typeof v) {
    case 'string':
      return v;

    case 'boolean':
      return v ? 'true' : 'false';

    case 'number':
      return isFinite(v) ? v : '';

    default:
      return '';
  }
};

module.exports = function(obj, sep, eq, name) {
  sep = sep || '&';
  eq = eq || '=';
  if (obj === null) {
    obj = undefined;
  }

  if (typeof obj === 'object') {
    return map(objectKeys(obj), function(k) {
      var ks = encodeURIComponent(stringifyPrimitive(k)) + eq;
      if (isArray(obj[k])) {
        return map(obj[k], function(v) {
          return ks + encodeURIComponent(stringifyPrimitive(v));
        }).join(sep);
      } else {
        return ks + encodeURIComponent(stringifyPrimitive(obj[k]));
      }
    }).join(sep);

  }

  if (!name) return '';
  return encodeURIComponent(stringifyPrimitive(name)) + eq +
         encodeURIComponent(stringifyPrimitive(obj));
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

function map (xs, f) {
  if (xs.map) return xs.map(f);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    res.push(f(xs[i], i));
  }
  return res;
}

var objectKeys = Object.keys || function (obj) {
  var res = [];
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) res.push(key);
  }
  return res;
};

},{}],166:[function(require,module,exports){
'use strict';

exports.decode = exports.parse = require('./decode');
exports.encode = exports.stringify = require('./encode');

},{"./decode":164,"./encode":165}],167:[function(require,module,exports){
/*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
/* eslint-disable node/no-deprecated-api */
var buffer = require('buffer')
var Buffer = buffer.Buffer

// alternative to using Object.keys for old browsers
function copyProps (src, dst) {
  for (var key in src) {
    dst[key] = src[key]
  }
}
if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
  module.exports = buffer
} else {
  // Copy properties from require('buffer')
  copyProps(buffer, exports)
  exports.Buffer = SafeBuffer
}

function SafeBuffer (arg, encodingOrOffset, length) {
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.prototype = Object.create(Buffer.prototype)

// Copy static methods from Buffer
copyProps(Buffer, SafeBuffer)

SafeBuffer.from = function (arg, encodingOrOffset, length) {
  if (typeof arg === 'number') {
    throw new TypeError('Argument must not be a number')
  }
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.alloc = function (size, fill, encoding) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  var buf = Buffer(size)
  if (fill !== undefined) {
    if (typeof encoding === 'string') {
      buf.fill(fill, encoding)
    } else {
      buf.fill(fill)
    }
  } else {
    buf.fill(0)
  }
  return buf
}

SafeBuffer.allocUnsafe = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return Buffer(size)
}

SafeBuffer.allocUnsafeSlow = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return buffer.SlowBuffer(size)
}

},{"buffer":110}],168:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

module.exports = Stream;

var EE = require('events').EventEmitter;
var inherits = require('inherits');

inherits(Stream, EE);
Stream.Readable = require('readable-stream/lib/_stream_readable.js');
Stream.Writable = require('readable-stream/lib/_stream_writable.js');
Stream.Duplex = require('readable-stream/lib/_stream_duplex.js');
Stream.Transform = require('readable-stream/lib/_stream_transform.js');
Stream.PassThrough = require('readable-stream/lib/_stream_passthrough.js');
Stream.finished = require('readable-stream/lib/internal/streams/end-of-stream.js')
Stream.pipeline = require('readable-stream/lib/internal/streams/pipeline.js')

// Backwards-compat with node 0.4.x
Stream.Stream = Stream;



// old-style streams.  Note that the pipe method (the only relevant
// part of this class) is overridden in the Readable class.

function Stream() {
  EE.call(this);
}

Stream.prototype.pipe = function(dest, options) {
  var source = this;

  function ondata(chunk) {
    if (dest.writable) {
      if (false === dest.write(chunk) && source.pause) {
        source.pause();
      }
    }
  }

  source.on('data', ondata);

  function ondrain() {
    if (source.readable && source.resume) {
      source.resume();
    }
  }

  dest.on('drain', ondrain);

  // If the 'end' option is not supplied, dest.end() will be called when
  // source gets the 'end' or 'close' events.  Only dest.end() once.
  if (!dest._isStdio && (!options || options.end !== false)) {
    source.on('end', onend);
    source.on('close', onclose);
  }

  var didOnEnd = false;
  function onend() {
    if (didOnEnd) return;
    didOnEnd = true;

    dest.end();
  }


  function onclose() {
    if (didOnEnd) return;
    didOnEnd = true;

    if (typeof dest.destroy === 'function') dest.destroy();
  }

  // don't leave dangling pipes when there are errors.
  function onerror(er) {
    cleanup();
    if (EE.listenerCount(this, 'error') === 0) {
      throw er; // Unhandled stream error in pipe.
    }
  }

  source.on('error', onerror);
  dest.on('error', onerror);

  // remove all the event listeners that were added.
  function cleanup() {
    source.removeListener('data', ondata);
    dest.removeListener('drain', ondrain);

    source.removeListener('end', onend);
    source.removeListener('close', onclose);

    source.removeListener('error', onerror);
    dest.removeListener('error', onerror);

    source.removeListener('end', cleanup);
    source.removeListener('close', cleanup);

    dest.removeListener('close', cleanup);
  }

  source.on('end', cleanup);
  source.on('close', cleanup);

  dest.on('close', cleanup);

  dest.emit('pipe', source);

  // Allow for unix-like usage: A.pipe(B).pipe(C)
  return dest;
};

},{"events":114,"inherits":126,"readable-stream/lib/_stream_duplex.js":170,"readable-stream/lib/_stream_passthrough.js":171,"readable-stream/lib/_stream_readable.js":172,"readable-stream/lib/_stream_transform.js":173,"readable-stream/lib/_stream_writable.js":174,"readable-stream/lib/internal/streams/end-of-stream.js":178,"readable-stream/lib/internal/streams/pipeline.js":180}],169:[function(require,module,exports){
'use strict';

function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

var codes = {};

function createErrorType(code, message, Base) {
  if (!Base) {
    Base = Error;
  }

  function getMessage(arg1, arg2, arg3) {
    if (typeof message === 'string') {
      return message;
    } else {
      return message(arg1, arg2, arg3);
    }
  }

  var NodeError =
  /*#__PURE__*/
  function (_Base) {
    _inheritsLoose(NodeError, _Base);

    function NodeError(arg1, arg2, arg3) {
      return _Base.call(this, getMessage(arg1, arg2, arg3)) || this;
    }

    return NodeError;
  }(Base);

  NodeError.prototype.name = Base.name;
  NodeError.prototype.code = code;
  codes[code] = NodeError;
} // https://github.com/nodejs/node/blob/v10.8.0/lib/internal/errors.js


function oneOf(expected, thing) {
  if (Array.isArray(expected)) {
    var len = expected.length;
    expected = expected.map(function (i) {
      return String(i);
    });

    if (len > 2) {
      return "one of ".concat(thing, " ").concat(expected.slice(0, len - 1).join(', '), ", or ") + expected[len - 1];
    } else if (len === 2) {
      return "one of ".concat(thing, " ").concat(expected[0], " or ").concat(expected[1]);
    } else {
      return "of ".concat(thing, " ").concat(expected[0]);
    }
  } else {
    return "of ".concat(thing, " ").concat(String(expected));
  }
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/startsWith


function startsWith(str, search, pos) {
  return str.substr(!pos || pos < 0 ? 0 : +pos, search.length) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/endsWith


function endsWith(str, search, this_len) {
  if (this_len === undefined || this_len > str.length) {
    this_len = str.length;
  }

  return str.substring(this_len - search.length, this_len) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/includes


function includes(str, search, start) {
  if (typeof start !== 'number') {
    start = 0;
  }

  if (start + search.length > str.length) {
    return false;
  } else {
    return str.indexOf(search, start) !== -1;
  }
}

createErrorType('ERR_INVALID_OPT_VALUE', function (name, value) {
  return 'The value "' + value + '" is invalid for option "' + name + '"';
}, TypeError);
createErrorType('ERR_INVALID_ARG_TYPE', function (name, expected, actual) {
  // determiner: 'must be' or 'must not be'
  var determiner;

  if (typeof expected === 'string' && startsWith(expected, 'not ')) {
    determiner = 'must not be';
    expected = expected.replace(/^not /, '');
  } else {
    determiner = 'must be';
  }

  var msg;

  if (endsWith(name, ' argument')) {
    // For cases like 'first argument'
    msg = "The ".concat(name, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  } else {
    var type = includes(name, '.') ? 'property' : 'argument';
    msg = "The \"".concat(name, "\" ").concat(type, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  }

  msg += ". Received type ".concat(typeof actual);
  return msg;
}, TypeError);
createErrorType('ERR_STREAM_PUSH_AFTER_EOF', 'stream.push() after EOF');
createErrorType('ERR_METHOD_NOT_IMPLEMENTED', function (name) {
  return 'The ' + name + ' method is not implemented';
});
createErrorType('ERR_STREAM_PREMATURE_CLOSE', 'Premature close');
createErrorType('ERR_STREAM_DESTROYED', function (name) {
  return 'Cannot call ' + name + ' after a stream was destroyed';
});
createErrorType('ERR_MULTIPLE_CALLBACK', 'Callback called multiple times');
createErrorType('ERR_STREAM_CANNOT_PIPE', 'Cannot pipe, not readable');
createErrorType('ERR_STREAM_WRITE_AFTER_END', 'write after end');
createErrorType('ERR_STREAM_NULL_VALUES', 'May not write null values to stream', TypeError);
createErrorType('ERR_UNKNOWN_ENCODING', function (arg) {
  return 'Unknown encoding: ' + arg;
}, TypeError);
createErrorType('ERR_STREAM_UNSHIFT_AFTER_END_EVENT', 'stream.unshift() after end event');
module.exports.codes = codes;

},{}],170:[function(require,module,exports){
(function (process){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.

'use strict';

/*<replacement>*/
var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) keys.push(key);
  return keys;
};
/*</replacement>*/

module.exports = Duplex;
var Readable = require('./_stream_readable');
var Writable = require('./_stream_writable');
require('inherits')(Duplex, Readable);
{
  // Allow the keys array to be GC'ed.
  var keys = objectKeys(Writable.prototype);
  for (var v = 0; v < keys.length; v++) {
    var method = keys[v];
    if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
  }
}
function Duplex(options) {
  if (!(this instanceof Duplex)) return new Duplex(options);
  Readable.call(this, options);
  Writable.call(this, options);
  this.allowHalfOpen = true;
  if (options) {
    if (options.readable === false) this.readable = false;
    if (options.writable === false) this.writable = false;
    if (options.allowHalfOpen === false) {
      this.allowHalfOpen = false;
      this.once('end', onend);
    }
  }
}
Object.defineProperty(Duplex.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
});
Object.defineProperty(Duplex.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});
Object.defineProperty(Duplex.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
});

// the no-half-open enforcer
function onend() {
  // If the writable side ended, then we're ok.
  if (this._writableState.ended) return;

  // no more data can be written.
  // But allow more writes to happen in this tick.
  process.nextTick(onEndNT, this);
}
function onEndNT(self) {
  self.end();
}
Object.defineProperty(Duplex.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined || this._writableState === undefined) {
      return false;
    }
    return this._readableState.destroyed && this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (this._readableState === undefined || this._writableState === undefined) {
      return;
    }

    // backward compatibility, the user is explicitly
    // managing destroyed
    this._readableState.destroyed = value;
    this._writableState.destroyed = value;
  }
});
}).call(this)}).call(this,require('_process'))
},{"./_stream_readable":172,"./_stream_writable":174,"_process":162,"inherits":126}],171:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.

'use strict';

module.exports = PassThrough;
var Transform = require('./_stream_transform');
require('inherits')(PassThrough, Transform);
function PassThrough(options) {
  if (!(this instanceof PassThrough)) return new PassThrough(options);
  Transform.call(this, options);
}
PassThrough.prototype._transform = function (chunk, encoding, cb) {
  cb(null, chunk);
};
},{"./_stream_transform":173,"inherits":126}],172:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

module.exports = Readable;

/*<replacement>*/
var Duplex;
/*</replacement>*/

Readable.ReadableState = ReadableState;

/*<replacement>*/
var EE = require('events').EventEmitter;
var EElistenerCount = function EElistenerCount(emitter, type) {
  return emitter.listeners(type).length;
};
/*</replacement>*/

/*<replacement>*/
var Stream = require('./internal/streams/stream');
/*</replacement>*/

var Buffer = require('buffer').Buffer;
var OurUint8Array = (typeof global !== 'undefined' ? global : typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : {}).Uint8Array || function () {};
function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}
function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}

/*<replacement>*/
var debugUtil = require('util');
var debug;
if (debugUtil && debugUtil.debuglog) {
  debug = debugUtil.debuglog('stream');
} else {
  debug = function debug() {};
}
/*</replacement>*/

var BufferList = require('./internal/streams/buffer_list');
var destroyImpl = require('./internal/streams/destroy');
var _require = require('./internal/streams/state'),
  getHighWaterMark = _require.getHighWaterMark;
var _require$codes = require('../errors').codes,
  ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
  ERR_STREAM_PUSH_AFTER_EOF = _require$codes.ERR_STREAM_PUSH_AFTER_EOF,
  ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
  ERR_STREAM_UNSHIFT_AFTER_END_EVENT = _require$codes.ERR_STREAM_UNSHIFT_AFTER_END_EVENT;

// Lazy loaded to improve the startup performance.
var StringDecoder;
var createReadableStreamAsyncIterator;
var from;
require('inherits')(Readable, Stream);
var errorOrDestroy = destroyImpl.errorOrDestroy;
var kProxyEvents = ['error', 'close', 'destroy', 'pause', 'resume'];
function prependListener(emitter, event, fn) {
  // Sadly this is not cacheable as some libraries bundle their own
  // event emitter implementation with them.
  if (typeof emitter.prependListener === 'function') return emitter.prependListener(event, fn);

  // This is a hack to make sure that our error handler is attached before any
  // userland ones.  NEVER DO THIS. This is here only because this code needs
  // to continue to work with older versions of Node.js that do not include
  // the prependListener() method. The goal is to eventually remove this hack.
  if (!emitter._events || !emitter._events[event]) emitter.on(event, fn);else if (Array.isArray(emitter._events[event])) emitter._events[event].unshift(fn);else emitter._events[event] = [fn, emitter._events[event]];
}
function ReadableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {};

  // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream.
  // These options can be provided separately as readableXXX and writableXXX.
  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex;

  // object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away
  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.readableObjectMode;

  // the point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"
  this.highWaterMark = getHighWaterMark(this, options, 'readableHighWaterMark', isDuplex);

  // A linked list is used to store data chunks instead of an array because the
  // linked list can remove elements from the beginning faster than
  // array.shift()
  this.buffer = new BufferList();
  this.length = 0;
  this.pipes = null;
  this.pipesCount = 0;
  this.flowing = null;
  this.ended = false;
  this.endEmitted = false;
  this.reading = false;

  // a flag to be able to tell if the event 'readable'/'data' is emitted
  // immediately, or on a later tick.  We set this to true at first, because
  // any actions that shouldn't happen until "later" should generally also
  // not happen before the first read call.
  this.sync = true;

  // whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.
  this.needReadable = false;
  this.emittedReadable = false;
  this.readableListening = false;
  this.resumeScheduled = false;
  this.paused = true;

  // Should close be emitted on destroy. Defaults to true.
  this.emitClose = options.emitClose !== false;

  // Should .destroy() be called after 'end' (and potentially 'finish')
  this.autoDestroy = !!options.autoDestroy;

  // has it been destroyed
  this.destroyed = false;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // the number of writers that are awaiting a drain event in .pipe()s
  this.awaitDrain = 0;

  // if true, a maybeReadMore has been scheduled
  this.readingMore = false;
  this.decoder = null;
  this.encoding = null;
  if (options.encoding) {
    if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }
}
function Readable(options) {
  Duplex = Duplex || require('./_stream_duplex');
  if (!(this instanceof Readable)) return new Readable(options);

  // Checking for a Stream.Duplex instance is faster here instead of inside
  // the ReadableState constructor, at least with V8 6.5
  var isDuplex = this instanceof Duplex;
  this._readableState = new ReadableState(options, this, isDuplex);

  // legacy
  this.readable = true;
  if (options) {
    if (typeof options.read === 'function') this._read = options.read;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
  }
  Stream.call(this);
}
Object.defineProperty(Readable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined) {
      return false;
    }
    return this._readableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._readableState) {
      return;
    }

    // backward compatibility, the user is explicitly
    // managing destroyed
    this._readableState.destroyed = value;
  }
});
Readable.prototype.destroy = destroyImpl.destroy;
Readable.prototype._undestroy = destroyImpl.undestroy;
Readable.prototype._destroy = function (err, cb) {
  cb(err);
};

// Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.
Readable.prototype.push = function (chunk, encoding) {
  var state = this._readableState;
  var skipChunkCheck;
  if (!state.objectMode) {
    if (typeof chunk === 'string') {
      encoding = encoding || state.defaultEncoding;
      if (encoding !== state.encoding) {
        chunk = Buffer.from(chunk, encoding);
        encoding = '';
      }
      skipChunkCheck = true;
    }
  } else {
    skipChunkCheck = true;
  }
  return readableAddChunk(this, chunk, encoding, false, skipChunkCheck);
};

// Unshift should *always* be something directly out of read()
Readable.prototype.unshift = function (chunk) {
  return readableAddChunk(this, chunk, null, true, false);
};
function readableAddChunk(stream, chunk, encoding, addToFront, skipChunkCheck) {
  debug('readableAddChunk', chunk);
  var state = stream._readableState;
  if (chunk === null) {
    state.reading = false;
    onEofChunk(stream, state);
  } else {
    var er;
    if (!skipChunkCheck) er = chunkInvalid(state, chunk);
    if (er) {
      errorOrDestroy(stream, er);
    } else if (state.objectMode || chunk && chunk.length > 0) {
      if (typeof chunk !== 'string' && !state.objectMode && Object.getPrototypeOf(chunk) !== Buffer.prototype) {
        chunk = _uint8ArrayToBuffer(chunk);
      }
      if (addToFront) {
        if (state.endEmitted) errorOrDestroy(stream, new ERR_STREAM_UNSHIFT_AFTER_END_EVENT());else addChunk(stream, state, chunk, true);
      } else if (state.ended) {
        errorOrDestroy(stream, new ERR_STREAM_PUSH_AFTER_EOF());
      } else if (state.destroyed) {
        return false;
      } else {
        state.reading = false;
        if (state.decoder && !encoding) {
          chunk = state.decoder.write(chunk);
          if (state.objectMode || chunk.length !== 0) addChunk(stream, state, chunk, false);else maybeReadMore(stream, state);
        } else {
          addChunk(stream, state, chunk, false);
        }
      }
    } else if (!addToFront) {
      state.reading = false;
      maybeReadMore(stream, state);
    }
  }

  // We can push more data if we are below the highWaterMark.
  // Also, if we have no data yet, we can stand some more bytes.
  // This is to work around cases where hwm=0, such as the repl.
  return !state.ended && (state.length < state.highWaterMark || state.length === 0);
}
function addChunk(stream, state, chunk, addToFront) {
  if (state.flowing && state.length === 0 && !state.sync) {
    state.awaitDrain = 0;
    stream.emit('data', chunk);
  } else {
    // update the buffer info.
    state.length += state.objectMode ? 1 : chunk.length;
    if (addToFront) state.buffer.unshift(chunk);else state.buffer.push(chunk);
    if (state.needReadable) emitReadable(stream);
  }
  maybeReadMore(stream, state);
}
function chunkInvalid(state, chunk) {
  var er;
  if (!_isUint8Array(chunk) && typeof chunk !== 'string' && chunk !== undefined && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer', 'Uint8Array'], chunk);
  }
  return er;
}
Readable.prototype.isPaused = function () {
  return this._readableState.flowing === false;
};

// backwards compatibility.
Readable.prototype.setEncoding = function (enc) {
  if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
  var decoder = new StringDecoder(enc);
  this._readableState.decoder = decoder;
  // If setEncoding(null), decoder.encoding equals utf8
  this._readableState.encoding = this._readableState.decoder.encoding;

  // Iterate over current buffer to convert already stored Buffers:
  var p = this._readableState.buffer.head;
  var content = '';
  while (p !== null) {
    content += decoder.write(p.data);
    p = p.next;
  }
  this._readableState.buffer.clear();
  if (content !== '') this._readableState.buffer.push(content);
  this._readableState.length = content.length;
  return this;
};

// Don't raise the hwm > 1GB
var MAX_HWM = 0x40000000;
function computeNewHighWaterMark(n) {
  if (n >= MAX_HWM) {
    // TODO(ronag): Throw ERR_VALUE_OUT_OF_RANGE.
    n = MAX_HWM;
  } else {
    // Get the next highest power of 2 to prevent increasing hwm excessively in
    // tiny amounts
    n--;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    n++;
  }
  return n;
}

// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function howMuchToRead(n, state) {
  if (n <= 0 || state.length === 0 && state.ended) return 0;
  if (state.objectMode) return 1;
  if (n !== n) {
    // Only flow one buffer at a time
    if (state.flowing && state.length) return state.buffer.head.data.length;else return state.length;
  }
  // If we're asking for more than the current hwm, then raise the hwm.
  if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);
  if (n <= state.length) return n;
  // Don't have enough
  if (!state.ended) {
    state.needReadable = true;
    return 0;
  }
  return state.length;
}

// you can override either this method, or the async _read(n) below.
Readable.prototype.read = function (n) {
  debug('read', n);
  n = parseInt(n, 10);
  var state = this._readableState;
  var nOrig = n;
  if (n !== 0) state.emittedReadable = false;

  // if we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.
  if (n === 0 && state.needReadable && ((state.highWaterMark !== 0 ? state.length >= state.highWaterMark : state.length > 0) || state.ended)) {
    debug('read: emitReadable', state.length, state.ended);
    if (state.length === 0 && state.ended) endReadable(this);else emitReadable(this);
    return null;
  }
  n = howMuchToRead(n, state);

  // if we've ended, and we're now clear, then finish it up.
  if (n === 0 && state.ended) {
    if (state.length === 0) endReadable(this);
    return null;
  }

  // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.

  // if we need a readable event, then we need to do some reading.
  var doRead = state.needReadable;
  debug('need readable', doRead);

  // if we currently have less than the highWaterMark, then also read some
  if (state.length === 0 || state.length - n < state.highWaterMark) {
    doRead = true;
    debug('length less than watermark', doRead);
  }

  // however, if we've ended, then there's no point, and if we're already
  // reading, then it's unnecessary.
  if (state.ended || state.reading) {
    doRead = false;
    debug('reading or ended', doRead);
  } else if (doRead) {
    debug('do read');
    state.reading = true;
    state.sync = true;
    // if the length is currently zero, then we *need* a readable event.
    if (state.length === 0) state.needReadable = true;
    // call internal read method
    this._read(state.highWaterMark);
    state.sync = false;
    // If _read pushed data synchronously, then `reading` will be false,
    // and we need to re-evaluate how much data we can return to the user.
    if (!state.reading) n = howMuchToRead(nOrig, state);
  }
  var ret;
  if (n > 0) ret = fromList(n, state);else ret = null;
  if (ret === null) {
    state.needReadable = state.length <= state.highWaterMark;
    n = 0;
  } else {
    state.length -= n;
    state.awaitDrain = 0;
  }
  if (state.length === 0) {
    // If we have nothing in the buffer, then we want to know
    // as soon as we *do* get something into the buffer.
    if (!state.ended) state.needReadable = true;

    // If we tried to read() past the EOF, then emit end on the next tick.
    if (nOrig !== n && state.ended) endReadable(this);
  }
  if (ret !== null) this.emit('data', ret);
  return ret;
};
function onEofChunk(stream, state) {
  debug('onEofChunk');
  if (state.ended) return;
  if (state.decoder) {
    var chunk = state.decoder.end();
    if (chunk && chunk.length) {
      state.buffer.push(chunk);
      state.length += state.objectMode ? 1 : chunk.length;
    }
  }
  state.ended = true;
  if (state.sync) {
    // if we are sync, wait until next tick to emit the data.
    // Otherwise we risk emitting data in the flow()
    // the readable code triggers during a read() call
    emitReadable(stream);
  } else {
    // emit 'readable' now to make sure it gets picked up.
    state.needReadable = false;
    if (!state.emittedReadable) {
      state.emittedReadable = true;
      emitReadable_(stream);
    }
  }
}

// Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.
function emitReadable(stream) {
  var state = stream._readableState;
  debug('emitReadable', state.needReadable, state.emittedReadable);
  state.needReadable = false;
  if (!state.emittedReadable) {
    debug('emitReadable', state.flowing);
    state.emittedReadable = true;
    process.nextTick(emitReadable_, stream);
  }
}
function emitReadable_(stream) {
  var state = stream._readableState;
  debug('emitReadable_', state.destroyed, state.length, state.ended);
  if (!state.destroyed && (state.length || state.ended)) {
    stream.emit('readable');
    state.emittedReadable = false;
  }

  // The stream needs another readable event if
  // 1. It is not flowing, as the flow mechanism will take
  //    care of it.
  // 2. It is not ended.
  // 3. It is below the highWaterMark, so we can schedule
  //    another readable later.
  state.needReadable = !state.flowing && !state.ended && state.length <= state.highWaterMark;
  flow(stream);
}

// at this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.
function maybeReadMore(stream, state) {
  if (!state.readingMore) {
    state.readingMore = true;
    process.nextTick(maybeReadMore_, stream, state);
  }
}
function maybeReadMore_(stream, state) {
  // Attempt to read more data if we should.
  //
  // The conditions for reading more data are (one of):
  // - Not enough data buffered (state.length < state.highWaterMark). The loop
  //   is responsible for filling the buffer with enough data if such data
  //   is available. If highWaterMark is 0 and we are not in the flowing mode
  //   we should _not_ attempt to buffer any extra data. We'll get more data
  //   when the stream consumer calls read() instead.
  // - No data in the buffer, and the stream is in flowing mode. In this mode
  //   the loop below is responsible for ensuring read() is called. Failing to
  //   call read here would abort the flow and there's no other mechanism for
  //   continuing the flow if the stream consumer has just subscribed to the
  //   'data' event.
  //
  // In addition to the above conditions to keep reading data, the following
  // conditions prevent the data from being read:
  // - The stream has ended (state.ended).
  // - There is already a pending 'read' operation (state.reading). This is a
  //   case where the the stream has called the implementation defined _read()
  //   method, but they are processing the call asynchronously and have _not_
  //   called push() with new data. In this case we skip performing more
  //   read()s. The execution ends in this method again after the _read() ends
  //   up calling push() with more data.
  while (!state.reading && !state.ended && (state.length < state.highWaterMark || state.flowing && state.length === 0)) {
    var len = state.length;
    debug('maybeReadMore read 0');
    stream.read(0);
    if (len === state.length)
      // didn't get any data, stop spinning.
      break;
  }
  state.readingMore = false;
}

// abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.
Readable.prototype._read = function (n) {
  errorOrDestroy(this, new ERR_METHOD_NOT_IMPLEMENTED('_read()'));
};
Readable.prototype.pipe = function (dest, pipeOpts) {
  var src = this;
  var state = this._readableState;
  switch (state.pipesCount) {
    case 0:
      state.pipes = dest;
      break;
    case 1:
      state.pipes = [state.pipes, dest];
      break;
    default:
      state.pipes.push(dest);
      break;
  }
  state.pipesCount += 1;
  debug('pipe count=%d opts=%j', state.pipesCount, pipeOpts);
  var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process.stdout && dest !== process.stderr;
  var endFn = doEnd ? onend : unpipe;
  if (state.endEmitted) process.nextTick(endFn);else src.once('end', endFn);
  dest.on('unpipe', onunpipe);
  function onunpipe(readable, unpipeInfo) {
    debug('onunpipe');
    if (readable === src) {
      if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
        unpipeInfo.hasUnpiped = true;
        cleanup();
      }
    }
  }
  function onend() {
    debug('onend');
    dest.end();
  }

  // when the dest drains, it reduces the awaitDrain counter
  // on the source.  This would be more elegant with a .once()
  // handler in flow(), but adding and removing repeatedly is
  // too slow.
  var ondrain = pipeOnDrain(src);
  dest.on('drain', ondrain);
  var cleanedUp = false;
  function cleanup() {
    debug('cleanup');
    // cleanup event handlers once the pipe is broken
    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('drain', ondrain);
    dest.removeListener('error', onerror);
    dest.removeListener('unpipe', onunpipe);
    src.removeListener('end', onend);
    src.removeListener('end', unpipe);
    src.removeListener('data', ondata);
    cleanedUp = true;

    // if the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.
    if (state.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
  }
  src.on('data', ondata);
  function ondata(chunk) {
    debug('ondata');
    var ret = dest.write(chunk);
    debug('dest.write', ret);
    if (ret === false) {
      // If the user unpiped during `dest.write()`, it is possible
      // to get stuck in a permanently paused state if that write
      // also returned false.
      // => Check whether `dest` is still a piping destination.
      if ((state.pipesCount === 1 && state.pipes === dest || state.pipesCount > 1 && indexOf(state.pipes, dest) !== -1) && !cleanedUp) {
        debug('false write response, pause', state.awaitDrain);
        state.awaitDrain++;
      }
      src.pause();
    }
  }

  // if the dest has an error, then stop piping into it.
  // however, don't suppress the throwing behavior for this.
  function onerror(er) {
    debug('onerror', er);
    unpipe();
    dest.removeListener('error', onerror);
    if (EElistenerCount(dest, 'error') === 0) errorOrDestroy(dest, er);
  }

  // Make sure our error handler is attached before userland ones.
  prependListener(dest, 'error', onerror);

  // Both close and finish should trigger unpipe, but only once.
  function onclose() {
    dest.removeListener('finish', onfinish);
    unpipe();
  }
  dest.once('close', onclose);
  function onfinish() {
    debug('onfinish');
    dest.removeListener('close', onclose);
    unpipe();
  }
  dest.once('finish', onfinish);
  function unpipe() {
    debug('unpipe');
    src.unpipe(dest);
  }

  // tell the dest that it's being piped to
  dest.emit('pipe', src);

  // start the flow if it hasn't been started already.
  if (!state.flowing) {
    debug('pipe resume');
    src.resume();
  }
  return dest;
};
function pipeOnDrain(src) {
  return function pipeOnDrainFunctionResult() {
    var state = src._readableState;
    debug('pipeOnDrain', state.awaitDrain);
    if (state.awaitDrain) state.awaitDrain--;
    if (state.awaitDrain === 0 && EElistenerCount(src, 'data')) {
      state.flowing = true;
      flow(src);
    }
  };
}
Readable.prototype.unpipe = function (dest) {
  var state = this._readableState;
  var unpipeInfo = {
    hasUnpiped: false
  };

  // if we're not piping anywhere, then do nothing.
  if (state.pipesCount === 0) return this;

  // just one destination.  most common case.
  if (state.pipesCount === 1) {
    // passed in one, but it's not the right one.
    if (dest && dest !== state.pipes) return this;
    if (!dest) dest = state.pipes;

    // got a match.
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;
    if (dest) dest.emit('unpipe', this, unpipeInfo);
    return this;
  }

  // slow case. multiple pipe destinations.

  if (!dest) {
    // remove all.
    var dests = state.pipes;
    var len = state.pipesCount;
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;
    for (var i = 0; i < len; i++) dests[i].emit('unpipe', this, {
      hasUnpiped: false
    });
    return this;
  }

  // try to find the right one.
  var index = indexOf(state.pipes, dest);
  if (index === -1) return this;
  state.pipes.splice(index, 1);
  state.pipesCount -= 1;
  if (state.pipesCount === 1) state.pipes = state.pipes[0];
  dest.emit('unpipe', this, unpipeInfo);
  return this;
};

// set up data events if they are asked for
// Ensure readable listeners eventually get something
Readable.prototype.on = function (ev, fn) {
  var res = Stream.prototype.on.call(this, ev, fn);
  var state = this._readableState;
  if (ev === 'data') {
    // update readableListening so that resume() may be a no-op
    // a few lines down. This is needed to support once('readable').
    state.readableListening = this.listenerCount('readable') > 0;

    // Try start flowing on next tick if stream isn't explicitly paused
    if (state.flowing !== false) this.resume();
  } else if (ev === 'readable') {
    if (!state.endEmitted && !state.readableListening) {
      state.readableListening = state.needReadable = true;
      state.flowing = false;
      state.emittedReadable = false;
      debug('on readable', state.length, state.reading);
      if (state.length) {
        emitReadable(this);
      } else if (!state.reading) {
        process.nextTick(nReadingNextTick, this);
      }
    }
  }
  return res;
};
Readable.prototype.addListener = Readable.prototype.on;
Readable.prototype.removeListener = function (ev, fn) {
  var res = Stream.prototype.removeListener.call(this, ev, fn);
  if (ev === 'readable') {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }
  return res;
};
Readable.prototype.removeAllListeners = function (ev) {
  var res = Stream.prototype.removeAllListeners.apply(this, arguments);
  if (ev === 'readable' || ev === undefined) {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }
  return res;
};
function updateReadableListening(self) {
  var state = self._readableState;
  state.readableListening = self.listenerCount('readable') > 0;
  if (state.resumeScheduled && !state.paused) {
    // flowing needs to be set to true now, otherwise
    // the upcoming resume will not flow.
    state.flowing = true;

    // crude way to check if we should resume
  } else if (self.listenerCount('data') > 0) {
    self.resume();
  }
}
function nReadingNextTick(self) {
  debug('readable nexttick read 0');
  self.read(0);
}

// pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.
Readable.prototype.resume = function () {
  var state = this._readableState;
  if (!state.flowing) {
    debug('resume');
    // we flow only if there is no one listening
    // for readable, but we still have to call
    // resume()
    state.flowing = !state.readableListening;
    resume(this, state);
  }
  state.paused = false;
  return this;
};
function resume(stream, state) {
  if (!state.resumeScheduled) {
    state.resumeScheduled = true;
    process.nextTick(resume_, stream, state);
  }
}
function resume_(stream, state) {
  debug('resume', state.reading);
  if (!state.reading) {
    stream.read(0);
  }
  state.resumeScheduled = false;
  stream.emit('resume');
  flow(stream);
  if (state.flowing && !state.reading) stream.read(0);
}
Readable.prototype.pause = function () {
  debug('call pause flowing=%j', this._readableState.flowing);
  if (this._readableState.flowing !== false) {
    debug('pause');
    this._readableState.flowing = false;
    this.emit('pause');
  }
  this._readableState.paused = true;
  return this;
};
function flow(stream) {
  var state = stream._readableState;
  debug('flow', state.flowing);
  while (state.flowing && stream.read() !== null);
}

// wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.
Readable.prototype.wrap = function (stream) {
  var _this = this;
  var state = this._readableState;
  var paused = false;
  stream.on('end', function () {
    debug('wrapped end');
    if (state.decoder && !state.ended) {
      var chunk = state.decoder.end();
      if (chunk && chunk.length) _this.push(chunk);
    }
    _this.push(null);
  });
  stream.on('data', function (chunk) {
    debug('wrapped data');
    if (state.decoder) chunk = state.decoder.write(chunk);

    // don't skip over falsy values in objectMode
    if (state.objectMode && (chunk === null || chunk === undefined)) return;else if (!state.objectMode && (!chunk || !chunk.length)) return;
    var ret = _this.push(chunk);
    if (!ret) {
      paused = true;
      stream.pause();
    }
  });

  // proxy all the other methods.
  // important when wrapping filters and duplexes.
  for (var i in stream) {
    if (this[i] === undefined && typeof stream[i] === 'function') {
      this[i] = function methodWrap(method) {
        return function methodWrapReturnFunction() {
          return stream[method].apply(stream, arguments);
        };
      }(i);
    }
  }

  // proxy certain important events.
  for (var n = 0; n < kProxyEvents.length; n++) {
    stream.on(kProxyEvents[n], this.emit.bind(this, kProxyEvents[n]));
  }

  // when we try to consume some more bytes, simply unpause the
  // underlying stream.
  this._read = function (n) {
    debug('wrapped _read', n);
    if (paused) {
      paused = false;
      stream.resume();
    }
  };
  return this;
};
if (typeof Symbol === 'function') {
  Readable.prototype[Symbol.asyncIterator] = function () {
    if (createReadableStreamAsyncIterator === undefined) {
      createReadableStreamAsyncIterator = require('./internal/streams/async_iterator');
    }
    return createReadableStreamAsyncIterator(this);
  };
}
Object.defineProperty(Readable.prototype, 'readableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.highWaterMark;
  }
});
Object.defineProperty(Readable.prototype, 'readableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState && this._readableState.buffer;
  }
});
Object.defineProperty(Readable.prototype, 'readableFlowing', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.flowing;
  },
  set: function set(state) {
    if (this._readableState) {
      this._readableState.flowing = state;
    }
  }
});

// exposed for testing purposes only.
Readable._fromList = fromList;
Object.defineProperty(Readable.prototype, 'readableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.length;
  }
});

// Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function fromList(n, state) {
  // nothing buffered
  if (state.length === 0) return null;
  var ret;
  if (state.objectMode) ret = state.buffer.shift();else if (!n || n >= state.length) {
    // read it all, truncate the list
    if (state.decoder) ret = state.buffer.join('');else if (state.buffer.length === 1) ret = state.buffer.first();else ret = state.buffer.concat(state.length);
    state.buffer.clear();
  } else {
    // read part of list
    ret = state.buffer.consume(n, state.decoder);
  }
  return ret;
}
function endReadable(stream) {
  var state = stream._readableState;
  debug('endReadable', state.endEmitted);
  if (!state.endEmitted) {
    state.ended = true;
    process.nextTick(endReadableNT, state, stream);
  }
}
function endReadableNT(state, stream) {
  debug('endReadableNT', state.endEmitted, state.length);

  // Check that we didn't get one last unshift.
  if (!state.endEmitted && state.length === 0) {
    state.endEmitted = true;
    stream.readable = false;
    stream.emit('end');
    if (state.autoDestroy) {
      // In case of duplex streams we need a way to detect
      // if the writable side is ready for autoDestroy as well
      var wState = stream._writableState;
      if (!wState || wState.autoDestroy && wState.finished) {
        stream.destroy();
      }
    }
  }
}
if (typeof Symbol === 'function') {
  Readable.from = function (iterable, opts) {
    if (from === undefined) {
      from = require('./internal/streams/from');
    }
    return from(Readable, iterable, opts);
  };
}
function indexOf(xs, x) {
  for (var i = 0, l = xs.length; i < l; i++) {
    if (xs[i] === x) return i;
  }
  return -1;
}
}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../errors":169,"./_stream_duplex":170,"./internal/streams/async_iterator":175,"./internal/streams/buffer_list":176,"./internal/streams/destroy":177,"./internal/streams/from":179,"./internal/streams/state":181,"./internal/streams/stream":182,"_process":162,"buffer":110,"events":114,"inherits":126,"string_decoder/":183,"util":108}],173:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.

'use strict';

module.exports = Transform;
var _require$codes = require('../errors').codes,
  ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
  ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
  ERR_TRANSFORM_ALREADY_TRANSFORMING = _require$codes.ERR_TRANSFORM_ALREADY_TRANSFORMING,
  ERR_TRANSFORM_WITH_LENGTH_0 = _require$codes.ERR_TRANSFORM_WITH_LENGTH_0;
var Duplex = require('./_stream_duplex');
require('inherits')(Transform, Duplex);
function afterTransform(er, data) {
  var ts = this._transformState;
  ts.transforming = false;
  var cb = ts.writecb;
  if (cb === null) {
    return this.emit('error', new ERR_MULTIPLE_CALLBACK());
  }
  ts.writechunk = null;
  ts.writecb = null;
  if (data != null)
    // single equals check for both `null` and `undefined`
    this.push(data);
  cb(er);
  var rs = this._readableState;
  rs.reading = false;
  if (rs.needReadable || rs.length < rs.highWaterMark) {
    this._read(rs.highWaterMark);
  }
}
function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);
  Duplex.call(this, options);
  this._transformState = {
    afterTransform: afterTransform.bind(this),
    needTransform: false,
    transforming: false,
    writecb: null,
    writechunk: null,
    writeencoding: null
  };

  // start out asking for a readable event once data is transformed.
  this._readableState.needReadable = true;

  // we have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.
  this._readableState.sync = false;
  if (options) {
    if (typeof options.transform === 'function') this._transform = options.transform;
    if (typeof options.flush === 'function') this._flush = options.flush;
  }

  // When the writable side finishes, then flush out anything remaining.
  this.on('prefinish', prefinish);
}
function prefinish() {
  var _this = this;
  if (typeof this._flush === 'function' && !this._readableState.destroyed) {
    this._flush(function (er, data) {
      done(_this, er, data);
    });
  } else {
    done(this, null, null);
  }
}
Transform.prototype.push = function (chunk, encoding) {
  this._transformState.needTransform = false;
  return Duplex.prototype.push.call(this, chunk, encoding);
};

// This is the part where you do stuff!
// override this function in implementation classes.
// 'chunk' is an input chunk.
//
// Call `push(newChunk)` to pass along transformed output
// to the readable side.  You may call 'push' zero or more times.
//
// Call `cb(err)` when you are done with this chunk.  If you pass
// an error, then that'll put the hurt on the whole operation.  If you
// never call cb(), then you'll never get another chunk.
Transform.prototype._transform = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_transform()'));
};
Transform.prototype._write = function (chunk, encoding, cb) {
  var ts = this._transformState;
  ts.writecb = cb;
  ts.writechunk = chunk;
  ts.writeencoding = encoding;
  if (!ts.transforming) {
    var rs = this._readableState;
    if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
  }
};

// Doesn't matter what the args are here.
// _transform does all the work.
// That we got here means that the readable side wants more data.
Transform.prototype._read = function (n) {
  var ts = this._transformState;
  if (ts.writechunk !== null && !ts.transforming) {
    ts.transforming = true;
    this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
  } else {
    // mark that we need a transform, so that any data that comes in
    // will get processed, now that we've asked for it.
    ts.needTransform = true;
  }
};
Transform.prototype._destroy = function (err, cb) {
  Duplex.prototype._destroy.call(this, err, function (err2) {
    cb(err2);
  });
};
function done(stream, er, data) {
  if (er) return stream.emit('error', er);
  if (data != null)
    // single equals check for both `null` and `undefined`
    stream.push(data);

  // TODO(BridgeAR): Write a test for these two error cases
  // if there's nothing in the write buffer, then that means
  // that nothing more will ever be provided
  if (stream._writableState.length) throw new ERR_TRANSFORM_WITH_LENGTH_0();
  if (stream._transformState.transforming) throw new ERR_TRANSFORM_ALREADY_TRANSFORMING();
  return stream.push(null);
}
},{"../errors":169,"./_stream_duplex":170,"inherits":126}],174:[function(require,module,exports){
(function (process,global){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// A bit simpler than readable streams.
// Implement an async ._write(chunk, encoding, cb), and it'll handle all
// the drain event emission and buffering.

'use strict';

module.exports = Writable;

/* <replacement> */
function WriteReq(chunk, encoding, cb) {
  this.chunk = chunk;
  this.encoding = encoding;
  this.callback = cb;
  this.next = null;
}

// It seems a linked list but it is not
// there will be only 2 of these for each stream
function CorkedRequest(state) {
  var _this = this;
  this.next = null;
  this.entry = null;
  this.finish = function () {
    onCorkedFinish(_this, state);
  };
}
/* </replacement> */

/*<replacement>*/
var Duplex;
/*</replacement>*/

Writable.WritableState = WritableState;

/*<replacement>*/
var internalUtil = {
  deprecate: require('util-deprecate')
};
/*</replacement>*/

/*<replacement>*/
var Stream = require('./internal/streams/stream');
/*</replacement>*/

var Buffer = require('buffer').Buffer;
var OurUint8Array = (typeof global !== 'undefined' ? global : typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : {}).Uint8Array || function () {};
function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}
function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}
var destroyImpl = require('./internal/streams/destroy');
var _require = require('./internal/streams/state'),
  getHighWaterMark = _require.getHighWaterMark;
var _require$codes = require('../errors').codes,
  ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
  ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
  ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
  ERR_STREAM_CANNOT_PIPE = _require$codes.ERR_STREAM_CANNOT_PIPE,
  ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED,
  ERR_STREAM_NULL_VALUES = _require$codes.ERR_STREAM_NULL_VALUES,
  ERR_STREAM_WRITE_AFTER_END = _require$codes.ERR_STREAM_WRITE_AFTER_END,
  ERR_UNKNOWN_ENCODING = _require$codes.ERR_UNKNOWN_ENCODING;
var errorOrDestroy = destroyImpl.errorOrDestroy;
require('inherits')(Writable, Stream);
function nop() {}
function WritableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {};

  // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream,
  // e.g. options.readableObjectMode vs. options.writableObjectMode, etc.
  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex;

  // object stream flag to indicate whether or not this stream
  // contains buffers or objects.
  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.writableObjectMode;

  // the point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write()
  this.highWaterMark = getHighWaterMark(this, options, 'writableHighWaterMark', isDuplex);

  // if _final has been called
  this.finalCalled = false;

  // drain event flag.
  this.needDrain = false;
  // at the start of calling end()
  this.ending = false;
  // when end() has been called, and returned
  this.ended = false;
  // when 'finish' is emitted
  this.finished = false;

  // has it been destroyed
  this.destroyed = false;

  // should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.
  var noDecode = options.decodeStrings === false;
  this.decodeStrings = !noDecode;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.
  this.length = 0;

  // a flag to see when we're in the middle of a write.
  this.writing = false;

  // when true all writes will be buffered until .uncork() call
  this.corked = 0;

  // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.
  this.sync = true;

  // a flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.
  this.bufferProcessing = false;

  // the callback that's passed to _write(chunk,cb)
  this.onwrite = function (er) {
    onwrite(stream, er);
  };

  // the callback that the user supplies to write(chunk,encoding,cb)
  this.writecb = null;

  // the amount that is being written when _write is called.
  this.writelen = 0;
  this.bufferedRequest = null;
  this.lastBufferedRequest = null;

  // number of pending user-supplied write callbacks
  // this must be 0 before 'finish' can be emitted
  this.pendingcb = 0;

  // emit prefinish if the only thing we're waiting for is _write cbs
  // This is relevant for synchronous Transform streams
  this.prefinished = false;

  // True if the error was already emitted and should not be thrown again
  this.errorEmitted = false;

  // Should close be emitted on destroy. Defaults to true.
  this.emitClose = options.emitClose !== false;

  // Should .destroy() be called after 'finish' (and potentially 'end')
  this.autoDestroy = !!options.autoDestroy;

  // count buffered requests
  this.bufferedRequestCount = 0;

  // allocate the first CorkedRequest, there is always
  // one allocated and free to use, and we maintain at most two
  this.corkedRequestsFree = new CorkedRequest(this);
}
WritableState.prototype.getBuffer = function getBuffer() {
  var current = this.bufferedRequest;
  var out = [];
  while (current) {
    out.push(current);
    current = current.next;
  }
  return out;
};
(function () {
  try {
    Object.defineProperty(WritableState.prototype, 'buffer', {
      get: internalUtil.deprecate(function writableStateBufferGetter() {
        return this.getBuffer();
      }, '_writableState.buffer is deprecated. Use _writableState.getBuffer ' + 'instead.', 'DEP0003')
    });
  } catch (_) {}
})();

// Test _writableState for inheritance to account for Duplex streams,
// whose prototype chain only points to Readable.
var realHasInstance;
if (typeof Symbol === 'function' && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === 'function') {
  realHasInstance = Function.prototype[Symbol.hasInstance];
  Object.defineProperty(Writable, Symbol.hasInstance, {
    value: function value(object) {
      if (realHasInstance.call(this, object)) return true;
      if (this !== Writable) return false;
      return object && object._writableState instanceof WritableState;
    }
  });
} else {
  realHasInstance = function realHasInstance(object) {
    return object instanceof this;
  };
}
function Writable(options) {
  Duplex = Duplex || require('./_stream_duplex');

  // Writable ctor is applied to Duplexes, too.
  // `realHasInstance` is necessary because using plain `instanceof`
  // would return false, as no `_writableState` property is attached.

  // Trying to use the custom `instanceof` for Writable here will also break the
  // Node.js LazyTransform implementation, which has a non-trivial getter for
  // `_writableState` that would lead to infinite recursion.

  // Checking for a Stream.Duplex instance is faster here instead of inside
  // the WritableState constructor, at least with V8 6.5
  var isDuplex = this instanceof Duplex;
  if (!isDuplex && !realHasInstance.call(Writable, this)) return new Writable(options);
  this._writableState = new WritableState(options, this, isDuplex);

  // legacy.
  this.writable = true;
  if (options) {
    if (typeof options.write === 'function') this._write = options.write;
    if (typeof options.writev === 'function') this._writev = options.writev;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
    if (typeof options.final === 'function') this._final = options.final;
  }
  Stream.call(this);
}

// Otherwise people can pipe Writable streams, which is just wrong.
Writable.prototype.pipe = function () {
  errorOrDestroy(this, new ERR_STREAM_CANNOT_PIPE());
};
function writeAfterEnd(stream, cb) {
  var er = new ERR_STREAM_WRITE_AFTER_END();
  // TODO: defer error events consistently everywhere, not just the cb
  errorOrDestroy(stream, er);
  process.nextTick(cb, er);
}

// Checks that a user-supplied chunk is valid, especially for the particular
// mode the stream is in. Currently this means that `null` is never accepted
// and undefined/non-string values are only allowed in object mode.
function validChunk(stream, state, chunk, cb) {
  var er;
  if (chunk === null) {
    er = new ERR_STREAM_NULL_VALUES();
  } else if (typeof chunk !== 'string' && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer'], chunk);
  }
  if (er) {
    errorOrDestroy(stream, er);
    process.nextTick(cb, er);
    return false;
  }
  return true;
}
Writable.prototype.write = function (chunk, encoding, cb) {
  var state = this._writableState;
  var ret = false;
  var isBuf = !state.objectMode && _isUint8Array(chunk);
  if (isBuf && !Buffer.isBuffer(chunk)) {
    chunk = _uint8ArrayToBuffer(chunk);
  }
  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }
  if (isBuf) encoding = 'buffer';else if (!encoding) encoding = state.defaultEncoding;
  if (typeof cb !== 'function') cb = nop;
  if (state.ending) writeAfterEnd(this, cb);else if (isBuf || validChunk(this, state, chunk, cb)) {
    state.pendingcb++;
    ret = writeOrBuffer(this, state, isBuf, chunk, encoding, cb);
  }
  return ret;
};
Writable.prototype.cork = function () {
  this._writableState.corked++;
};
Writable.prototype.uncork = function () {
  var state = this._writableState;
  if (state.corked) {
    state.corked--;
    if (!state.writing && !state.corked && !state.bufferProcessing && state.bufferedRequest) clearBuffer(this, state);
  }
};
Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
  // node::ParseEncoding() requires lower case.
  if (typeof encoding === 'string') encoding = encoding.toLowerCase();
  if (!(['hex', 'utf8', 'utf-8', 'ascii', 'binary', 'base64', 'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'raw'].indexOf((encoding + '').toLowerCase()) > -1)) throw new ERR_UNKNOWN_ENCODING(encoding);
  this._writableState.defaultEncoding = encoding;
  return this;
};
Object.defineProperty(Writable.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});
function decodeChunk(state, chunk, encoding) {
  if (!state.objectMode && state.decodeStrings !== false && typeof chunk === 'string') {
    chunk = Buffer.from(chunk, encoding);
  }
  return chunk;
}
Object.defineProperty(Writable.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
});

// if we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.
function writeOrBuffer(stream, state, isBuf, chunk, encoding, cb) {
  if (!isBuf) {
    var newChunk = decodeChunk(state, chunk, encoding);
    if (chunk !== newChunk) {
      isBuf = true;
      encoding = 'buffer';
      chunk = newChunk;
    }
  }
  var len = state.objectMode ? 1 : chunk.length;
  state.length += len;
  var ret = state.length < state.highWaterMark;
  // we must ensure that previous needDrain will not be reset to false.
  if (!ret) state.needDrain = true;
  if (state.writing || state.corked) {
    var last = state.lastBufferedRequest;
    state.lastBufferedRequest = {
      chunk: chunk,
      encoding: encoding,
      isBuf: isBuf,
      callback: cb,
      next: null
    };
    if (last) {
      last.next = state.lastBufferedRequest;
    } else {
      state.bufferedRequest = state.lastBufferedRequest;
    }
    state.bufferedRequestCount += 1;
  } else {
    doWrite(stream, state, false, len, chunk, encoding, cb);
  }
  return ret;
}
function doWrite(stream, state, writev, len, chunk, encoding, cb) {
  state.writelen = len;
  state.writecb = cb;
  state.writing = true;
  state.sync = true;
  if (state.destroyed) state.onwrite(new ERR_STREAM_DESTROYED('write'));else if (writev) stream._writev(chunk, state.onwrite);else stream._write(chunk, encoding, state.onwrite);
  state.sync = false;
}
function onwriteError(stream, state, sync, er, cb) {
  --state.pendingcb;
  if (sync) {
    // defer the callback if we are being called synchronously
    // to avoid piling up things on the stack
    process.nextTick(cb, er);
    // this can emit finish, and it will always happen
    // after error
    process.nextTick(finishMaybe, stream, state);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er);
  } else {
    // the caller expect this to happen before if
    // it is async
    cb(er);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er);
    // this can emit finish, but finish must
    // always follow error
    finishMaybe(stream, state);
  }
}
function onwriteStateUpdate(state) {
  state.writing = false;
  state.writecb = null;
  state.length -= state.writelen;
  state.writelen = 0;
}
function onwrite(stream, er) {
  var state = stream._writableState;
  var sync = state.sync;
  var cb = state.writecb;
  if (typeof cb !== 'function') throw new ERR_MULTIPLE_CALLBACK();
  onwriteStateUpdate(state);
  if (er) onwriteError(stream, state, sync, er, cb);else {
    // Check if we're actually ready to finish, but don't emit yet
    var finished = needFinish(state) || stream.destroyed;
    if (!finished && !state.corked && !state.bufferProcessing && state.bufferedRequest) {
      clearBuffer(stream, state);
    }
    if (sync) {
      process.nextTick(afterWrite, stream, state, finished, cb);
    } else {
      afterWrite(stream, state, finished, cb);
    }
  }
}
function afterWrite(stream, state, finished, cb) {
  if (!finished) onwriteDrain(stream, state);
  state.pendingcb--;
  cb();
  finishMaybe(stream, state);
}

// Must force callback to be called on nextTick, so that we don't
// emit 'drain' before the write() consumer gets the 'false' return
// value, and has a chance to attach a 'drain' listener.
function onwriteDrain(stream, state) {
  if (state.length === 0 && state.needDrain) {
    state.needDrain = false;
    stream.emit('drain');
  }
}

// if there's something in the buffer waiting, then process it
function clearBuffer(stream, state) {
  state.bufferProcessing = true;
  var entry = state.bufferedRequest;
  if (stream._writev && entry && entry.next) {
    // Fast case, write everything using _writev()
    var l = state.bufferedRequestCount;
    var buffer = new Array(l);
    var holder = state.corkedRequestsFree;
    holder.entry = entry;
    var count = 0;
    var allBuffers = true;
    while (entry) {
      buffer[count] = entry;
      if (!entry.isBuf) allBuffers = false;
      entry = entry.next;
      count += 1;
    }
    buffer.allBuffers = allBuffers;
    doWrite(stream, state, true, state.length, buffer, '', holder.finish);

    // doWrite is almost always async, defer these to save a bit of time
    // as the hot path ends with doWrite
    state.pendingcb++;
    state.lastBufferedRequest = null;
    if (holder.next) {
      state.corkedRequestsFree = holder.next;
      holder.next = null;
    } else {
      state.corkedRequestsFree = new CorkedRequest(state);
    }
    state.bufferedRequestCount = 0;
  } else {
    // Slow case, write chunks one-by-one
    while (entry) {
      var chunk = entry.chunk;
      var encoding = entry.encoding;
      var cb = entry.callback;
      var len = state.objectMode ? 1 : chunk.length;
      doWrite(stream, state, false, len, chunk, encoding, cb);
      entry = entry.next;
      state.bufferedRequestCount--;
      // if we didn't call the onwrite immediately, then
      // it means that we need to wait until it does.
      // also, that means that the chunk and cb are currently
      // being processed, so move the buffer counter past them.
      if (state.writing) {
        break;
      }
    }
    if (entry === null) state.lastBufferedRequest = null;
  }
  state.bufferedRequest = entry;
  state.bufferProcessing = false;
}
Writable.prototype._write = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_write()'));
};
Writable.prototype._writev = null;
Writable.prototype.end = function (chunk, encoding, cb) {
  var state = this._writableState;
  if (typeof chunk === 'function') {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }
  if (chunk !== null && chunk !== undefined) this.write(chunk, encoding);

  // .end() fully uncorks
  if (state.corked) {
    state.corked = 1;
    this.uncork();
  }

  // ignore unnecessary end() calls.
  if (!state.ending) endWritable(this, state, cb);
  return this;
};
Object.defineProperty(Writable.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
});
function needFinish(state) {
  return state.ending && state.length === 0 && state.bufferedRequest === null && !state.finished && !state.writing;
}
function callFinal(stream, state) {
  stream._final(function (err) {
    state.pendingcb--;
    if (err) {
      errorOrDestroy(stream, err);
    }
    state.prefinished = true;
    stream.emit('prefinish');
    finishMaybe(stream, state);
  });
}
function prefinish(stream, state) {
  if (!state.prefinished && !state.finalCalled) {
    if (typeof stream._final === 'function' && !state.destroyed) {
      state.pendingcb++;
      state.finalCalled = true;
      process.nextTick(callFinal, stream, state);
    } else {
      state.prefinished = true;
      stream.emit('prefinish');
    }
  }
}
function finishMaybe(stream, state) {
  var need = needFinish(state);
  if (need) {
    prefinish(stream, state);
    if (state.pendingcb === 0) {
      state.finished = true;
      stream.emit('finish');
      if (state.autoDestroy) {
        // In case of duplex streams we need a way to detect
        // if the readable side is ready for autoDestroy as well
        var rState = stream._readableState;
        if (!rState || rState.autoDestroy && rState.endEmitted) {
          stream.destroy();
        }
      }
    }
  }
  return need;
}
function endWritable(stream, state, cb) {
  state.ending = true;
  finishMaybe(stream, state);
  if (cb) {
    if (state.finished) process.nextTick(cb);else stream.once('finish', cb);
  }
  state.ended = true;
  stream.writable = false;
}
function onCorkedFinish(corkReq, state, err) {
  var entry = corkReq.entry;
  corkReq.entry = null;
  while (entry) {
    var cb = entry.callback;
    state.pendingcb--;
    cb(err);
    entry = entry.next;
  }

  // reuse the free corkReq.
  state.corkedRequestsFree.next = corkReq;
}
Object.defineProperty(Writable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._writableState === undefined) {
      return false;
    }
    return this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._writableState) {
      return;
    }

    // backward compatibility, the user is explicitly
    // managing destroyed
    this._writableState.destroyed = value;
  }
});
Writable.prototype.destroy = destroyImpl.destroy;
Writable.prototype._undestroy = destroyImpl.undestroy;
Writable.prototype._destroy = function (err, cb) {
  cb(err);
};
}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../errors":169,"./_stream_duplex":170,"./internal/streams/destroy":177,"./internal/streams/state":181,"./internal/streams/stream":182,"_process":162,"buffer":110,"inherits":126,"util-deprecate":187}],175:[function(require,module,exports){
(function (process){(function (){
'use strict';

var _Object$setPrototypeO;
function _defineProperty(obj, key, value) { key = _toPropertyKey(key); if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }
function _toPropertyKey(arg) { var key = _toPrimitive(arg, "string"); return typeof key === "symbol" ? key : String(key); }
function _toPrimitive(input, hint) { if (typeof input !== "object" || input === null) return input; var prim = input[Symbol.toPrimitive]; if (prim !== undefined) { var res = prim.call(input, hint || "default"); if (typeof res !== "object") return res; throw new TypeError("@@toPrimitive must return a primitive value."); } return (hint === "string" ? String : Number)(input); }
var finished = require('./end-of-stream');
var kLastResolve = Symbol('lastResolve');
var kLastReject = Symbol('lastReject');
var kError = Symbol('error');
var kEnded = Symbol('ended');
var kLastPromise = Symbol('lastPromise');
var kHandlePromise = Symbol('handlePromise');
var kStream = Symbol('stream');
function createIterResult(value, done) {
  return {
    value: value,
    done: done
  };
}
function readAndResolve(iter) {
  var resolve = iter[kLastResolve];
  if (resolve !== null) {
    var data = iter[kStream].read();
    // we defer if data is null
    // we can be expecting either 'end' or
    // 'error'
    if (data !== null) {
      iter[kLastPromise] = null;
      iter[kLastResolve] = null;
      iter[kLastReject] = null;
      resolve(createIterResult(data, false));
    }
  }
}
function onReadable(iter) {
  // we wait for the next tick, because it might
  // emit an error with process.nextTick
  process.nextTick(readAndResolve, iter);
}
function wrapForNext(lastPromise, iter) {
  return function (resolve, reject) {
    lastPromise.then(function () {
      if (iter[kEnded]) {
        resolve(createIterResult(undefined, true));
        return;
      }
      iter[kHandlePromise](resolve, reject);
    }, reject);
  };
}
var AsyncIteratorPrototype = Object.getPrototypeOf(function () {});
var ReadableStreamAsyncIteratorPrototype = Object.setPrototypeOf((_Object$setPrototypeO = {
  get stream() {
    return this[kStream];
  },
  next: function next() {
    var _this = this;
    // if we have detected an error in the meanwhile
    // reject straight away
    var error = this[kError];
    if (error !== null) {
      return Promise.reject(error);
    }
    if (this[kEnded]) {
      return Promise.resolve(createIterResult(undefined, true));
    }
    if (this[kStream].destroyed) {
      // We need to defer via nextTick because if .destroy(err) is
      // called, the error will be emitted via nextTick, and
      // we cannot guarantee that there is no error lingering around
      // waiting to be emitted.
      return new Promise(function (resolve, reject) {
        process.nextTick(function () {
          if (_this[kError]) {
            reject(_this[kError]);
          } else {
            resolve(createIterResult(undefined, true));
          }
        });
      });
    }

    // if we have multiple next() calls
    // we will wait for the previous Promise to finish
    // this logic is optimized to support for await loops,
    // where next() is only called once at a time
    var lastPromise = this[kLastPromise];
    var promise;
    if (lastPromise) {
      promise = new Promise(wrapForNext(lastPromise, this));
    } else {
      // fast path needed to support multiple this.push()
      // without triggering the next() queue
      var data = this[kStream].read();
      if (data !== null) {
        return Promise.resolve(createIterResult(data, false));
      }
      promise = new Promise(this[kHandlePromise]);
    }
    this[kLastPromise] = promise;
    return promise;
  }
}, _defineProperty(_Object$setPrototypeO, Symbol.asyncIterator, function () {
  return this;
}), _defineProperty(_Object$setPrototypeO, "return", function _return() {
  var _this2 = this;
  // destroy(err, cb) is a private API
  // we can guarantee we have that here, because we control the
  // Readable class this is attached to
  return new Promise(function (resolve, reject) {
    _this2[kStream].destroy(null, function (err) {
      if (err) {
        reject(err);
        return;
      }
      resolve(createIterResult(undefined, true));
    });
  });
}), _Object$setPrototypeO), AsyncIteratorPrototype);
var createReadableStreamAsyncIterator = function createReadableStreamAsyncIterator(stream) {
  var _Object$create;
  var iterator = Object.create(ReadableStreamAsyncIteratorPrototype, (_Object$create = {}, _defineProperty(_Object$create, kStream, {
    value: stream,
    writable: true
  }), _defineProperty(_Object$create, kLastResolve, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kLastReject, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kError, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kEnded, {
    value: stream._readableState.endEmitted,
    writable: true
  }), _defineProperty(_Object$create, kHandlePromise, {
    value: function value(resolve, reject) {
      var data = iterator[kStream].read();
      if (data) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        resolve(createIterResult(data, false));
      } else {
        iterator[kLastResolve] = resolve;
        iterator[kLastReject] = reject;
      }
    },
    writable: true
  }), _Object$create));
  iterator[kLastPromise] = null;
  finished(stream, function (err) {
    if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
      var reject = iterator[kLastReject];
      // reject if we are waiting for data in the Promise
      // returned by next() and store the error
      if (reject !== null) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        reject(err);
      }
      iterator[kError] = err;
      return;
    }
    var resolve = iterator[kLastResolve];
    if (resolve !== null) {
      iterator[kLastPromise] = null;
      iterator[kLastResolve] = null;
      iterator[kLastReject] = null;
      resolve(createIterResult(undefined, true));
    }
    iterator[kEnded] = true;
  });
  stream.on('readable', onReadable.bind(null, iterator));
  return iterator;
};
module.exports = createReadableStreamAsyncIterator;
}).call(this)}).call(this,require('_process'))
},{"./end-of-stream":178,"_process":162}],176:[function(require,module,exports){
'use strict';

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); enumerableOnly && (symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; })), keys.push.apply(keys, symbols); } return keys; }
function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = null != arguments[i] ? arguments[i] : {}; i % 2 ? ownKeys(Object(source), !0).forEach(function (key) { _defineProperty(target, key, source[key]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)) : ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } return target; }
function _defineProperty(obj, key, value) { key = _toPropertyKey(key); if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }
function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor); } }
function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); Object.defineProperty(Constructor, "prototype", { writable: false }); return Constructor; }
function _toPropertyKey(arg) { var key = _toPrimitive(arg, "string"); return typeof key === "symbol" ? key : String(key); }
function _toPrimitive(input, hint) { if (typeof input !== "object" || input === null) return input; var prim = input[Symbol.toPrimitive]; if (prim !== undefined) { var res = prim.call(input, hint || "default"); if (typeof res !== "object") return res; throw new TypeError("@@toPrimitive must return a primitive value."); } return (hint === "string" ? String : Number)(input); }
var _require = require('buffer'),
  Buffer = _require.Buffer;
var _require2 = require('util'),
  inspect = _require2.inspect;
var custom = inspect && inspect.custom || 'inspect';
function copyBuffer(src, target, offset) {
  Buffer.prototype.copy.call(src, target, offset);
}
module.exports = /*#__PURE__*/function () {
  function BufferList() {
    _classCallCheck(this, BufferList);
    this.head = null;
    this.tail = null;
    this.length = 0;
  }
  _createClass(BufferList, [{
    key: "push",
    value: function push(v) {
      var entry = {
        data: v,
        next: null
      };
      if (this.length > 0) this.tail.next = entry;else this.head = entry;
      this.tail = entry;
      ++this.length;
    }
  }, {
    key: "unshift",
    value: function unshift(v) {
      var entry = {
        data: v,
        next: this.head
      };
      if (this.length === 0) this.tail = entry;
      this.head = entry;
      ++this.length;
    }
  }, {
    key: "shift",
    value: function shift() {
      if (this.length === 0) return;
      var ret = this.head.data;
      if (this.length === 1) this.head = this.tail = null;else this.head = this.head.next;
      --this.length;
      return ret;
    }
  }, {
    key: "clear",
    value: function clear() {
      this.head = this.tail = null;
      this.length = 0;
    }
  }, {
    key: "join",
    value: function join(s) {
      if (this.length === 0) return '';
      var p = this.head;
      var ret = '' + p.data;
      while (p = p.next) ret += s + p.data;
      return ret;
    }
  }, {
    key: "concat",
    value: function concat(n) {
      if (this.length === 0) return Buffer.alloc(0);
      var ret = Buffer.allocUnsafe(n >>> 0);
      var p = this.head;
      var i = 0;
      while (p) {
        copyBuffer(p.data, ret, i);
        i += p.data.length;
        p = p.next;
      }
      return ret;
    }

    // Consumes a specified amount of bytes or characters from the buffered data.
  }, {
    key: "consume",
    value: function consume(n, hasStrings) {
      var ret;
      if (n < this.head.data.length) {
        // `slice` is the same for buffers and strings.
        ret = this.head.data.slice(0, n);
        this.head.data = this.head.data.slice(n);
      } else if (n === this.head.data.length) {
        // First chunk is a perfect match.
        ret = this.shift();
      } else {
        // Result spans more than one buffer.
        ret = hasStrings ? this._getString(n) : this._getBuffer(n);
      }
      return ret;
    }
  }, {
    key: "first",
    value: function first() {
      return this.head.data;
    }

    // Consumes a specified amount of characters from the buffered data.
  }, {
    key: "_getString",
    value: function _getString(n) {
      var p = this.head;
      var c = 1;
      var ret = p.data;
      n -= ret.length;
      while (p = p.next) {
        var str = p.data;
        var nb = n > str.length ? str.length : n;
        if (nb === str.length) ret += str;else ret += str.slice(0, n);
        n -= nb;
        if (n === 0) {
          if (nb === str.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = str.slice(nb);
          }
          break;
        }
        ++c;
      }
      this.length -= c;
      return ret;
    }

    // Consumes a specified amount of bytes from the buffered data.
  }, {
    key: "_getBuffer",
    value: function _getBuffer(n) {
      var ret = Buffer.allocUnsafe(n);
      var p = this.head;
      var c = 1;
      p.data.copy(ret);
      n -= p.data.length;
      while (p = p.next) {
        var buf = p.data;
        var nb = n > buf.length ? buf.length : n;
        buf.copy(ret, ret.length - n, 0, nb);
        n -= nb;
        if (n === 0) {
          if (nb === buf.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = buf.slice(nb);
          }
          break;
        }
        ++c;
      }
      this.length -= c;
      return ret;
    }

    // Make sure the linked list only shows the minimal necessary information.
  }, {
    key: custom,
    value: function value(_, options) {
      return inspect(this, _objectSpread(_objectSpread({}, options), {}, {
        // Only inspect one level.
        depth: 0,
        // It should not recurse.
        customInspect: false
      }));
    }
  }]);
  return BufferList;
}();
},{"buffer":110,"util":108}],177:[function(require,module,exports){
(function (process){(function (){
'use strict';

// undocumented cb() API, needed for core, not for public API
function destroy(err, cb) {
  var _this = this;
  var readableDestroyed = this._readableState && this._readableState.destroyed;
  var writableDestroyed = this._writableState && this._writableState.destroyed;
  if (readableDestroyed || writableDestroyed) {
    if (cb) {
      cb(err);
    } else if (err) {
      if (!this._writableState) {
        process.nextTick(emitErrorNT, this, err);
      } else if (!this._writableState.errorEmitted) {
        this._writableState.errorEmitted = true;
        process.nextTick(emitErrorNT, this, err);
      }
    }
    return this;
  }

  // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case destroy() is called within callbacks

  if (this._readableState) {
    this._readableState.destroyed = true;
  }

  // if this is a duplex stream mark the writable part as destroyed as well
  if (this._writableState) {
    this._writableState.destroyed = true;
  }
  this._destroy(err || null, function (err) {
    if (!cb && err) {
      if (!_this._writableState) {
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else if (!_this._writableState.errorEmitted) {
        _this._writableState.errorEmitted = true;
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else {
        process.nextTick(emitCloseNT, _this);
      }
    } else if (cb) {
      process.nextTick(emitCloseNT, _this);
      cb(err);
    } else {
      process.nextTick(emitCloseNT, _this);
    }
  });
  return this;
}
function emitErrorAndCloseNT(self, err) {
  emitErrorNT(self, err);
  emitCloseNT(self);
}
function emitCloseNT(self) {
  if (self._writableState && !self._writableState.emitClose) return;
  if (self._readableState && !self._readableState.emitClose) return;
  self.emit('close');
}
function undestroy() {
  if (this._readableState) {
    this._readableState.destroyed = false;
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
  }
  if (this._writableState) {
    this._writableState.destroyed = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finalCalled = false;
    this._writableState.prefinished = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
  }
}
function emitErrorNT(self, err) {
  self.emit('error', err);
}
function errorOrDestroy(stream, err) {
  // We have tests that rely on errors being emitted
  // in the same tick, so changing this is semver major.
  // For now when you opt-in to autoDestroy we allow
  // the error to be emitted nextTick. In a future
  // semver major update we should change the default to this.

  var rState = stream._readableState;
  var wState = stream._writableState;
  if (rState && rState.autoDestroy || wState && wState.autoDestroy) stream.destroy(err);else stream.emit('error', err);
}
module.exports = {
  destroy: destroy,
  undestroy: undestroy,
  errorOrDestroy: errorOrDestroy
};
}).call(this)}).call(this,require('_process'))
},{"_process":162}],178:[function(require,module,exports){
// Ported from https://github.com/mafintosh/end-of-stream with
// permission from the author, Mathias Buus (@mafintosh).

'use strict';

var ERR_STREAM_PREMATURE_CLOSE = require('../../../errors').codes.ERR_STREAM_PREMATURE_CLOSE;
function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    callback.apply(this, args);
  };
}
function noop() {}
function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}
function eos(stream, opts, callback) {
  if (typeof opts === 'function') return eos(stream, null, opts);
  if (!opts) opts = {};
  callback = once(callback || noop);
  var readable = opts.readable || opts.readable !== false && stream.readable;
  var writable = opts.writable || opts.writable !== false && stream.writable;
  var onlegacyfinish = function onlegacyfinish() {
    if (!stream.writable) onfinish();
  };
  var writableEnded = stream._writableState && stream._writableState.finished;
  var onfinish = function onfinish() {
    writable = false;
    writableEnded = true;
    if (!readable) callback.call(stream);
  };
  var readableEnded = stream._readableState && stream._readableState.endEmitted;
  var onend = function onend() {
    readable = false;
    readableEnded = true;
    if (!writable) callback.call(stream);
  };
  var onerror = function onerror(err) {
    callback.call(stream, err);
  };
  var onclose = function onclose() {
    var err;
    if (readable && !readableEnded) {
      if (!stream._readableState || !stream._readableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }
    if (writable && !writableEnded) {
      if (!stream._writableState || !stream._writableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }
  };
  var onrequest = function onrequest() {
    stream.req.on('finish', onfinish);
  };
  if (isRequest(stream)) {
    stream.on('complete', onfinish);
    stream.on('abort', onclose);
    if (stream.req) onrequest();else stream.on('request', onrequest);
  } else if (writable && !stream._writableState) {
    // legacy streams
    stream.on('end', onlegacyfinish);
    stream.on('close', onlegacyfinish);
  }
  stream.on('end', onend);
  stream.on('finish', onfinish);
  if (opts.error !== false) stream.on('error', onerror);
  stream.on('close', onclose);
  return function () {
    stream.removeListener('complete', onfinish);
    stream.removeListener('abort', onclose);
    stream.removeListener('request', onrequest);
    if (stream.req) stream.req.removeListener('finish', onfinish);
    stream.removeListener('end', onlegacyfinish);
    stream.removeListener('close', onlegacyfinish);
    stream.removeListener('finish', onfinish);
    stream.removeListener('end', onend);
    stream.removeListener('error', onerror);
    stream.removeListener('close', onclose);
  };
}
module.exports = eos;
},{"../../../errors":169}],179:[function(require,module,exports){
module.exports = function () {
  throw new Error('Readable.from is not available in the browser')
};

},{}],180:[function(require,module,exports){
// Ported from https://github.com/mafintosh/pump with
// permission from the author, Mathias Buus (@mafintosh).

'use strict';

var eos;
function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;
    callback.apply(void 0, arguments);
  };
}
var _require$codes = require('../../../errors').codes,
  ERR_MISSING_ARGS = _require$codes.ERR_MISSING_ARGS,
  ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED;
function noop(err) {
  // Rethrow the error if it exists to avoid swallowing it
  if (err) throw err;
}
function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}
function destroyer(stream, reading, writing, callback) {
  callback = once(callback);
  var closed = false;
  stream.on('close', function () {
    closed = true;
  });
  if (eos === undefined) eos = require('./end-of-stream');
  eos(stream, {
    readable: reading,
    writable: writing
  }, function (err) {
    if (err) return callback(err);
    closed = true;
    callback();
  });
  var destroyed = false;
  return function (err) {
    if (closed) return;
    if (destroyed) return;
    destroyed = true;

    // request.destroy just do .end - .abort is what we want
    if (isRequest(stream)) return stream.abort();
    if (typeof stream.destroy === 'function') return stream.destroy();
    callback(err || new ERR_STREAM_DESTROYED('pipe'));
  };
}
function call(fn) {
  fn();
}
function pipe(from, to) {
  return from.pipe(to);
}
function popCallback(streams) {
  if (!streams.length) return noop;
  if (typeof streams[streams.length - 1] !== 'function') return noop;
  return streams.pop();
}
function pipeline() {
  for (var _len = arguments.length, streams = new Array(_len), _key = 0; _key < _len; _key++) {
    streams[_key] = arguments[_key];
  }
  var callback = popCallback(streams);
  if (Array.isArray(streams[0])) streams = streams[0];
  if (streams.length < 2) {
    throw new ERR_MISSING_ARGS('streams');
  }
  var error;
  var destroys = streams.map(function (stream, i) {
    var reading = i < streams.length - 1;
    var writing = i > 0;
    return destroyer(stream, reading, writing, function (err) {
      if (!error) error = err;
      if (err) destroys.forEach(call);
      if (reading) return;
      destroys.forEach(call);
      callback(error);
    });
  });
  return streams.reduce(pipe);
}
module.exports = pipeline;
},{"../../../errors":169,"./end-of-stream":178}],181:[function(require,module,exports){
'use strict';

var ERR_INVALID_OPT_VALUE = require('../../../errors').codes.ERR_INVALID_OPT_VALUE;
function highWaterMarkFrom(options, isDuplex, duplexKey) {
  return options.highWaterMark != null ? options.highWaterMark : isDuplex ? options[duplexKey] : null;
}
function getHighWaterMark(state, options, duplexKey, isDuplex) {
  var hwm = highWaterMarkFrom(options, isDuplex, duplexKey);
  if (hwm != null) {
    if (!(isFinite(hwm) && Math.floor(hwm) === hwm) || hwm < 0) {
      var name = isDuplex ? duplexKey : 'highWaterMark';
      throw new ERR_INVALID_OPT_VALUE(name, hwm);
    }
    return Math.floor(hwm);
  }

  // Default value
  return state.objectMode ? 16 : 16 * 1024;
}
module.exports = {
  getHighWaterMark: getHighWaterMark
};
},{"../../../errors":169}],182:[function(require,module,exports){
module.exports = require('events').EventEmitter;

},{"events":114}],183:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

/*<replacement>*/

var Buffer = require('safe-buffer').Buffer;
/*</replacement>*/

var isEncoding = Buffer.isEncoding || function (encoding) {
  encoding = '' + encoding;
  switch (encoding && encoding.toLowerCase()) {
    case 'hex':case 'utf8':case 'utf-8':case 'ascii':case 'binary':case 'base64':case 'ucs2':case 'ucs-2':case 'utf16le':case 'utf-16le':case 'raw':
      return true;
    default:
      return false;
  }
};

function _normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
};

// Do not cache `Buffer.isEncoding` when checking encoding names as some
// modules monkey-patch it to support additional encodings
function normalizeEncoding(enc) {
  var nenc = _normalizeEncoding(enc);
  if (typeof nenc !== 'string' && (Buffer.isEncoding === isEncoding || !isEncoding(enc))) throw new Error('Unknown encoding: ' + enc);
  return nenc || enc;
}

// StringDecoder provides an interface for efficiently splitting a series of
// buffers into a series of JS strings without breaking apart multi-byte
// characters.
exports.StringDecoder = StringDecoder;
function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  var nb;
  switch (this.encoding) {
    case 'utf16le':
      this.text = utf16Text;
      this.end = utf16End;
      nb = 4;
      break;
    case 'utf8':
      this.fillLast = utf8FillLast;
      nb = 4;
      break;
    case 'base64':
      this.text = base64Text;
      this.end = base64End;
      nb = 3;
      break;
    default:
      this.write = simpleWrite;
      this.end = simpleEnd;
      return;
  }
  this.lastNeed = 0;
  this.lastTotal = 0;
  this.lastChar = Buffer.allocUnsafe(nb);
}

StringDecoder.prototype.write = function (buf) {
  if (buf.length === 0) return '';
  var r;
  var i;
  if (this.lastNeed) {
    r = this.fillLast(buf);
    if (r === undefined) return '';
    i = this.lastNeed;
    this.lastNeed = 0;
  } else {
    i = 0;
  }
  if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
  return r || '';
};

StringDecoder.prototype.end = utf8End;

// Returns only complete characters in a Buffer
StringDecoder.prototype.text = utf8Text;

// Attempts to complete a partial non-UTF-8 character using bytes from a Buffer
StringDecoder.prototype.fillLast = function (buf) {
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
  this.lastNeed -= buf.length;
};

// Checks the type of a UTF-8 byte, whether it's ASCII, a leading byte, or a
// continuation byte. If an invalid byte is detected, -2 is returned.
function utf8CheckByte(byte) {
  if (byte <= 0x7F) return 0;else if (byte >> 5 === 0x06) return 2;else if (byte >> 4 === 0x0E) return 3;else if (byte >> 3 === 0x1E) return 4;
  return byte >> 6 === 0x02 ? -1 : -2;
}

// Checks at most 3 bytes at the end of a Buffer in order to detect an
// incomplete multi-byte UTF-8 character. The total number of bytes (2, 3, or 4)
// needed to complete the UTF-8 character (if applicable) are returned.
function utf8CheckIncomplete(self, buf, i) {
  var j = buf.length - 1;
  if (j < i) return 0;
  var nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 1;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 2;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) {
      if (nb === 2) nb = 0;else self.lastNeed = nb - 3;
    }
    return nb;
  }
  return 0;
}

// Validates as many continuation bytes for a multi-byte UTF-8 character as
// needed or are available. If we see a non-continuation byte where we expect
// one, we "replace" the validated continuation bytes we've seen so far with
// a single UTF-8 replacement character ('\ufffd'), to match v8's UTF-8 decoding
// behavior. The continuation byte check is included three times in the case
// where all of the continuation bytes for a character exist in the same buffer.
// It is also done this way as a slight performance increase instead of using a
// loop.
function utf8CheckExtraBytes(self, buf, p) {
  if ((buf[0] & 0xC0) !== 0x80) {
    self.lastNeed = 0;
    return '\ufffd';
  }
  if (self.lastNeed > 1 && buf.length > 1) {
    if ((buf[1] & 0xC0) !== 0x80) {
      self.lastNeed = 1;
      return '\ufffd';
    }
    if (self.lastNeed > 2 && buf.length > 2) {
      if ((buf[2] & 0xC0) !== 0x80) {
        self.lastNeed = 2;
        return '\ufffd';
      }
    }
  }
}

// Attempts to complete a multi-byte UTF-8 character using bytes from a Buffer.
function utf8FillLast(buf) {
  var p = this.lastTotal - this.lastNeed;
  var r = utf8CheckExtraBytes(this, buf, p);
  if (r !== undefined) return r;
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, p, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, p, 0, buf.length);
  this.lastNeed -= buf.length;
}

// Returns all complete UTF-8 characters in a Buffer. If the Buffer ended on a
// partial character, the character's bytes are buffered until the required
// number of bytes are available.
function utf8Text(buf, i) {
  var total = utf8CheckIncomplete(this, buf, i);
  if (!this.lastNeed) return buf.toString('utf8', i);
  this.lastTotal = total;
  var end = buf.length - (total - this.lastNeed);
  buf.copy(this.lastChar, 0, end);
  return buf.toString('utf8', i, end);
}

// For UTF-8, a replacement character is added when ending on a partial
// character.
function utf8End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + '\ufffd';
  return r;
}

// UTF-16LE typically needs two bytes per character, but even if we have an even
// number of bytes available, we need to check if we end on a leading/high
// surrogate. In that case, we need to wait for the next two bytes in order to
// decode the last character properly.
function utf16Text(buf, i) {
  if ((buf.length - i) % 2 === 0) {
    var r = buf.toString('utf16le', i);
    if (r) {
      var c = r.charCodeAt(r.length - 1);
      if (c >= 0xD800 && c <= 0xDBFF) {
        this.lastNeed = 2;
        this.lastTotal = 4;
        this.lastChar[0] = buf[buf.length - 2];
        this.lastChar[1] = buf[buf.length - 1];
        return r.slice(0, -1);
      }
    }
    return r;
  }
  this.lastNeed = 1;
  this.lastTotal = 2;
  this.lastChar[0] = buf[buf.length - 1];
  return buf.toString('utf16le', i, buf.length - 1);
}

// For UTF-16LE we do not explicitly append special replacement characters if we
// end on a partial character, we simply let v8 handle that.
function utf16End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = this.lastTotal - this.lastNeed;
    return r + this.lastChar.toString('utf16le', 0, end);
  }
  return r;
}

function base64Text(buf, i) {
  var n = (buf.length - i) % 3;
  if (n === 0) return buf.toString('base64', i);
  this.lastNeed = 3 - n;
  this.lastTotal = 3;
  if (n === 1) {
    this.lastChar[0] = buf[buf.length - 1];
  } else {
    this.lastChar[0] = buf[buf.length - 2];
    this.lastChar[1] = buf[buf.length - 1];
  }
  return buf.toString('base64', i, buf.length - n);
}

function base64End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + this.lastChar.toString('base64', 0, 3 - this.lastNeed);
  return r;
}

// Pass bytes on through for single-byte encodings (e.g. ascii, latin1, hex)
function simpleWrite(buf) {
  return buf.toString(this.encoding);
}

function simpleEnd(buf) {
  return buf && buf.length ? this.write(buf) : '';
}
},{"safe-buffer":167}],184:[function(require,module,exports){
(function (setImmediate,clearImmediate){(function (){
var nextTick = require('process/browser.js').nextTick;
var apply = Function.prototype.apply;
var slice = Array.prototype.slice;
var immediateIds = {};
var nextImmediateId = 0;

// DOM APIs, for completeness

exports.setTimeout = function() {
  return new Timeout(apply.call(setTimeout, window, arguments), clearTimeout);
};
exports.setInterval = function() {
  return new Timeout(apply.call(setInterval, window, arguments), clearInterval);
};
exports.clearTimeout =
exports.clearInterval = function(timeout) { timeout.close(); };

function Timeout(id, clearFn) {
  this._id = id;
  this._clearFn = clearFn;
}
Timeout.prototype.unref = Timeout.prototype.ref = function() {};
Timeout.prototype.close = function() {
  this._clearFn.call(window, this._id);
};

// Does not start the time, just sets up the members needed.
exports.enroll = function(item, msecs) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = msecs;
};

exports.unenroll = function(item) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = -1;
};

exports._unrefActive = exports.active = function(item) {
  clearTimeout(item._idleTimeoutId);

  var msecs = item._idleTimeout;
  if (msecs >= 0) {
    item._idleTimeoutId = setTimeout(function onTimeout() {
      if (item._onTimeout)
        item._onTimeout();
    }, msecs);
  }
};

// That's not how node.js implements it but the exposed api is the same.
exports.setImmediate = typeof setImmediate === "function" ? setImmediate : function(fn) {
  var id = nextImmediateId++;
  var args = arguments.length < 2 ? false : slice.call(arguments, 1);

  immediateIds[id] = true;

  nextTick(function onNextTick() {
    if (immediateIds[id]) {
      // fn.call() is faster so we optimize for the common use-case
      // @see http://jsperf.com/call-apply-segu
      if (args) {
        fn.apply(null, args);
      } else {
        fn.call(null);
      }
      // Prevent ids from leaking
      exports.clearImmediate(id);
    }
  });

  return id;
};

exports.clearImmediate = typeof clearImmediate === "function" ? clearImmediate : function(id) {
  delete immediateIds[id];
};
}).call(this)}).call(this,require("timers").setImmediate,require("timers").clearImmediate)
},{"process/browser.js":162,"timers":184}],185:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var punycode = require('punycode');
var util = require('./util');

exports.parse = urlParse;
exports.resolve = urlResolve;
exports.resolveObject = urlResolveObject;
exports.format = urlFormat;

exports.Url = Url;

function Url() {
  this.protocol = null;
  this.slashes = null;
  this.auth = null;
  this.host = null;
  this.port = null;
  this.hostname = null;
  this.hash = null;
  this.search = null;
  this.query = null;
  this.pathname = null;
  this.path = null;
  this.href = null;
}

// Reference: RFC 3986, RFC 1808, RFC 2396

// define these here so at least they only have to be
// compiled once on the first module load.
var protocolPattern = /^([a-z0-9.+-]+:)/i,
    portPattern = /:[0-9]*$/,

    // Special case for a simple path URL
    simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/,

    // RFC 2396: characters reserved for delimiting URLs.
    // We actually just auto-escape these.
    delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t'],

    // RFC 2396: characters not allowed for various reasons.
    unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),

    // Allowed by RFCs, but cause of XSS attacks.  Always escape these.
    autoEscape = ['\''].concat(unwise),
    // Characters that are never ever allowed in a hostname.
    // Note that any invalid chars are also handled, but these
    // are the ones that are *expected* to be seen, so we fast-path
    // them.
    nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
    hostEndingChars = ['/', '?', '#'],
    hostnameMaxLen = 255,
    hostnamePartPattern = /^[+a-z0-9A-Z_-]{0,63}$/,
    hostnamePartStart = /^([+a-z0-9A-Z_-]{0,63})(.*)$/,
    // protocols that can allow "unsafe" and "unwise" chars.
    unsafeProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that never have a hostname.
    hostlessProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that always contain a // bit.
    slashedProtocol = {
      'http': true,
      'https': true,
      'ftp': true,
      'gopher': true,
      'file': true,
      'http:': true,
      'https:': true,
      'ftp:': true,
      'gopher:': true,
      'file:': true
    },
    querystring = require('querystring');

function urlParse(url, parseQueryString, slashesDenoteHost) {
  if (url && util.isObject(url) && url instanceof Url) return url;

  var u = new Url;
  u.parse(url, parseQueryString, slashesDenoteHost);
  return u;
}

Url.prototype.parse = function(url, parseQueryString, slashesDenoteHost) {
  if (!util.isString(url)) {
    throw new TypeError("Parameter 'url' must be a string, not " + typeof url);
  }

  // Copy chrome, IE, opera backslash-handling behavior.
  // Back slashes before the query string get converted to forward slashes
  // See: https://code.google.com/p/chromium/issues/detail?id=25916
  var queryIndex = url.indexOf('?'),
      splitter =
          (queryIndex !== -1 && queryIndex < url.indexOf('#')) ? '?' : '#',
      uSplit = url.split(splitter),
      slashRegex = /\\/g;
  uSplit[0] = uSplit[0].replace(slashRegex, '/');
  url = uSplit.join(splitter);

  var rest = url;

  // trim before proceeding.
  // This is to support parse stuff like "  http://foo.com  \n"
  rest = rest.trim();

  if (!slashesDenoteHost && url.split('#').length === 1) {
    // Try fast path regexp
    var simplePath = simplePathPattern.exec(rest);
    if (simplePath) {
      this.path = rest;
      this.href = rest;
      this.pathname = simplePath[1];
      if (simplePath[2]) {
        this.search = simplePath[2];
        if (parseQueryString) {
          this.query = querystring.parse(this.search.substr(1));
        } else {
          this.query = this.search.substr(1);
        }
      } else if (parseQueryString) {
        this.search = '';
        this.query = {};
      }
      return this;
    }
  }

  var proto = protocolPattern.exec(rest);
  if (proto) {
    proto = proto[0];
    var lowerProto = proto.toLowerCase();
    this.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    var slashes = rest.substr(0, 2) === '//';
    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      this.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] &&
      (slashes || (proto && !slashedProtocol[proto]))) {

    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    //
    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the last @ sign, unless some host-ending character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    //
    // ex:
    // http://a@b@c/ => user:a@b host:c
    // http://a@b?@c => user:a host:c path:/?@c

    // v0.12 TODO(isaacs): This is not quite how Chrome does things.
    // Review our test case against browsers more comprehensively.

    // find the first instance of any hostEndingChars
    var hostEnd = -1;
    for (var i = 0; i < hostEndingChars.length; i++) {
      var hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }

    // at this point, either we have an explicit point where the
    // auth portion cannot go past, or the last @ char is the decider.
    var auth, atSign;
    if (hostEnd === -1) {
      // atSign can be anywhere.
      atSign = rest.lastIndexOf('@');
    } else {
      // atSign must be in auth portion.
      // http://a@b/c@d => host:b auth:a path:/c@d
      atSign = rest.lastIndexOf('@', hostEnd);
    }

    // Now we have a portion which is definitely the auth.
    // Pull that off.
    if (atSign !== -1) {
      auth = rest.slice(0, atSign);
      rest = rest.slice(atSign + 1);
      this.auth = decodeURIComponent(auth);
    }

    // the host is the remaining to the left of the first non-host char
    hostEnd = -1;
    for (var i = 0; i < nonHostChars.length; i++) {
      var hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }
    // if we still have not hit it, then the entire thing is a host.
    if (hostEnd === -1)
      hostEnd = rest.length;

    this.host = rest.slice(0, hostEnd);
    rest = rest.slice(hostEnd);

    // pull out port.
    this.parseHost();

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    this.hostname = this.hostname || '';

    // if hostname begins with [ and ends with ]
    // assume that it's an IPv6 address.
    var ipv6Hostname = this.hostname[0] === '[' &&
        this.hostname[this.hostname.length - 1] === ']';

    // validate a little.
    if (!ipv6Hostname) {
      var hostparts = this.hostname.split(/\./);
      for (var i = 0, l = hostparts.length; i < l; i++) {
        var part = hostparts[i];
        if (!part) continue;
        if (!part.match(hostnamePartPattern)) {
          var newpart = '';
          for (var j = 0, k = part.length; j < k; j++) {
            if (part.charCodeAt(j) > 127) {
              // we replace non-ASCII char with a temporary placeholder
              // we need this to make sure size of hostname is not
              // broken by replacing non-ASCII by nothing
              newpart += 'x';
            } else {
              newpart += part[j];
            }
          }
          // we test again with ASCII char only
          if (!newpart.match(hostnamePartPattern)) {
            var validParts = hostparts.slice(0, i);
            var notHost = hostparts.slice(i + 1);
            var bit = part.match(hostnamePartStart);
            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }
            if (notHost.length) {
              rest = '/' + notHost.join('.') + rest;
            }
            this.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    if (this.hostname.length > hostnameMaxLen) {
      this.hostname = '';
    } else {
      // hostnames are always lower case.
      this.hostname = this.hostname.toLowerCase();
    }

    if (!ipv6Hostname) {
      // IDNA Support: Returns a punycoded representation of "domain".
      // It only converts parts of the domain name that
      // have non-ASCII characters, i.e. it doesn't matter if
      // you call it with a domain that already is ASCII-only.
      this.hostname = punycode.toASCII(this.hostname);
    }

    var p = this.port ? ':' + this.port : '';
    var h = this.hostname || '';
    this.host = h + p;
    this.href += this.host;

    // strip [ and ] from the hostname
    // the host field still retains them, though
    if (ipv6Hostname) {
      this.hostname = this.hostname.substr(1, this.hostname.length - 2);
      if (rest[0] !== '/') {
        rest = '/' + rest;
      }
    }
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  if (!unsafeProtocol[lowerProto]) {

    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (var i = 0, l = autoEscape.length; i < l; i++) {
      var ae = autoEscape[i];
      if (rest.indexOf(ae) === -1)
        continue;
      var esc = encodeURIComponent(ae);
      if (esc === ae) {
        esc = escape(ae);
      }
      rest = rest.split(ae).join(esc);
    }
  }


  // chop off from the tail first.
  var hash = rest.indexOf('#');
  if (hash !== -1) {
    // got a fragment string.
    this.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }
  var qm = rest.indexOf('?');
  if (qm !== -1) {
    this.search = rest.substr(qm);
    this.query = rest.substr(qm + 1);
    if (parseQueryString) {
      this.query = querystring.parse(this.query);
    }
    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    this.search = '';
    this.query = {};
  }
  if (rest) this.pathname = rest;
  if (slashedProtocol[lowerProto] &&
      this.hostname && !this.pathname) {
    this.pathname = '/';
  }

  //to support http.request
  if (this.pathname || this.search) {
    var p = this.pathname || '';
    var s = this.search || '';
    this.path = p + s;
  }

  // finally, reconstruct the href based on what has been validated.
  this.href = this.format();
  return this;
};

// format a parsed object into a url string
function urlFormat(obj) {
  // ensure it's an object, and not a string url.
  // If it's an obj, this is a no-op.
  // this way, you can call url_format() on strings
  // to clean up potentially wonky urls.
  if (util.isString(obj)) obj = urlParse(obj);
  if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
  return obj.format();
}

Url.prototype.format = function() {
  var auth = this.auth || '';
  if (auth) {
    auth = encodeURIComponent(auth);
    auth = auth.replace(/%3A/i, ':');
    auth += '@';
  }

  var protocol = this.protocol || '',
      pathname = this.pathname || '',
      hash = this.hash || '',
      host = false,
      query = '';

  if (this.host) {
    host = auth + this.host;
  } else if (this.hostname) {
    host = auth + (this.hostname.indexOf(':') === -1 ?
        this.hostname :
        '[' + this.hostname + ']');
    if (this.port) {
      host += ':' + this.port;
    }
  }

  if (this.query &&
      util.isObject(this.query) &&
      Object.keys(this.query).length) {
    query = querystring.stringify(this.query);
  }

  var search = this.search || (query && ('?' + query)) || '';

  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (this.slashes ||
      (!protocol || slashedProtocol[protocol]) && host !== false) {
    host = '//' + (host || '');
    if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
  if (search && search.charAt(0) !== '?') search = '?' + search;

  pathname = pathname.replace(/[?#]/g, function(match) {
    return encodeURIComponent(match);
  });
  search = search.replace('#', '%23');

  return protocol + host + pathname + search + hash;
};

function urlResolve(source, relative) {
  return urlParse(source, false, true).resolve(relative);
}

Url.prototype.resolve = function(relative) {
  return this.resolveObject(urlParse(relative, false, true)).format();
};

function urlResolveObject(source, relative) {
  if (!source) return relative;
  return urlParse(source, false, true).resolveObject(relative);
}

Url.prototype.resolveObject = function(relative) {
  if (util.isString(relative)) {
    var rel = new Url();
    rel.parse(relative, false, true);
    relative = rel;
  }

  var result = new Url();
  var tkeys = Object.keys(this);
  for (var tk = 0; tk < tkeys.length; tk++) {
    var tkey = tkeys[tk];
    result[tkey] = this[tkey];
  }

  // hash is always overridden, no matter what.
  // even href="" will remove it.
  result.hash = relative.hash;

  // if the relative url is empty, then there's nothing left to do here.
  if (relative.href === '') {
    result.href = result.format();
    return result;
  }

  // hrefs like //foo/bar always cut to the protocol.
  if (relative.slashes && !relative.protocol) {
    // take everything except the protocol from relative
    var rkeys = Object.keys(relative);
    for (var rk = 0; rk < rkeys.length; rk++) {
      var rkey = rkeys[rk];
      if (rkey !== 'protocol')
        result[rkey] = relative[rkey];
    }

    //urlParse appends trailing / to urls like http://www.example.com
    if (slashedProtocol[result.protocol] &&
        result.hostname && !result.pathname) {
      result.path = result.pathname = '/';
    }

    result.href = result.format();
    return result;
  }

  if (relative.protocol && relative.protocol !== result.protocol) {
    // if it's a known url protocol, then changing
    // the protocol does weird things
    // first, if it's not file:, then we MUST have a host,
    // and if there was a path
    // to begin with, then we MUST have a path.
    // if it is file:, then the host is dropped,
    // because that's known to be hostless.
    // anything else is assumed to be absolute.
    if (!slashedProtocol[relative.protocol]) {
      var keys = Object.keys(relative);
      for (var v = 0; v < keys.length; v++) {
        var k = keys[v];
        result[k] = relative[k];
      }
      result.href = result.format();
      return result;
    }

    result.protocol = relative.protocol;
    if (!relative.host && !hostlessProtocol[relative.protocol]) {
      var relPath = (relative.pathname || '').split('/');
      while (relPath.length && !(relative.host = relPath.shift()));
      if (!relative.host) relative.host = '';
      if (!relative.hostname) relative.hostname = '';
      if (relPath[0] !== '') relPath.unshift('');
      if (relPath.length < 2) relPath.unshift('');
      result.pathname = relPath.join('/');
    } else {
      result.pathname = relative.pathname;
    }
    result.search = relative.search;
    result.query = relative.query;
    result.host = relative.host || '';
    result.auth = relative.auth;
    result.hostname = relative.hostname || relative.host;
    result.port = relative.port;
    // to support http.request
    if (result.pathname || result.search) {
      var p = result.pathname || '';
      var s = result.search || '';
      result.path = p + s;
    }
    result.slashes = result.slashes || relative.slashes;
    result.href = result.format();
    return result;
  }

  var isSourceAbs = (result.pathname && result.pathname.charAt(0) === '/'),
      isRelAbs = (
          relative.host ||
          relative.pathname && relative.pathname.charAt(0) === '/'
      ),
      mustEndAbs = (isRelAbs || isSourceAbs ||
                    (result.host && relative.pathname)),
      removeAllDots = mustEndAbs,
      srcPath = result.pathname && result.pathname.split('/') || [],
      relPath = relative.pathname && relative.pathname.split('/') || [],
      psychotic = result.protocol && !slashedProtocol[result.protocol];

  // if the url is a non-slashed url, then relative
  // links like ../.. should be able
  // to crawl up to the hostname, as well.  This is strange.
  // result.protocol has already been set by now.
  // Later on, put the first path part into the host field.
  if (psychotic) {
    result.hostname = '';
    result.port = null;
    if (result.host) {
      if (srcPath[0] === '') srcPath[0] = result.host;
      else srcPath.unshift(result.host);
    }
    result.host = '';
    if (relative.protocol) {
      relative.hostname = null;
      relative.port = null;
      if (relative.host) {
        if (relPath[0] === '') relPath[0] = relative.host;
        else relPath.unshift(relative.host);
      }
      relative.host = null;
    }
    mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
  }

  if (isRelAbs) {
    // it's absolute.
    result.host = (relative.host || relative.host === '') ?
                  relative.host : result.host;
    result.hostname = (relative.hostname || relative.hostname === '') ?
                      relative.hostname : result.hostname;
    result.search = relative.search;
    result.query = relative.query;
    srcPath = relPath;
    // fall through to the dot-handling below.
  } else if (relPath.length) {
    // it's relative
    // throw away the existing file, and take the new path instead.
    if (!srcPath) srcPath = [];
    srcPath.pop();
    srcPath = srcPath.concat(relPath);
    result.search = relative.search;
    result.query = relative.query;
  } else if (!util.isNullOrUndefined(relative.search)) {
    // just pull out the search.
    // like href='?foo'.
    // Put this after the other two cases because it simplifies the booleans
    if (psychotic) {
      result.hostname = result.host = srcPath.shift();
      //occationaly the auth can get stuck only in host
      //this especially happens in cases like
      //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      var authInHost = result.host && result.host.indexOf('@') > 0 ?
                       result.host.split('@') : false;
      if (authInHost) {
        result.auth = authInHost.shift();
        result.host = result.hostname = authInHost.shift();
      }
    }
    result.search = relative.search;
    result.query = relative.query;
    //to support http.request
    if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
      result.path = (result.pathname ? result.pathname : '') +
                    (result.search ? result.search : '');
    }
    result.href = result.format();
    return result;
  }

  if (!srcPath.length) {
    // no path at all.  easy.
    // we've already handled the other stuff above.
    result.pathname = null;
    //to support http.request
    if (result.search) {
      result.path = '/' + result.search;
    } else {
      result.path = null;
    }
    result.href = result.format();
    return result;
  }

  // if a url ENDs in . or .., then it must get a trailing slash.
  // however, if it ends in anything else non-slashy,
  // then it must NOT get a trailing slash.
  var last = srcPath.slice(-1)[0];
  var hasTrailingSlash = (
      (result.host || relative.host || srcPath.length > 1) &&
      (last === '.' || last === '..') || last === '');

  // strip single dots, resolve double dots to parent dir
  // if the path tries to go above the root, `up` ends up > 0
  var up = 0;
  for (var i = srcPath.length; i >= 0; i--) {
    last = srcPath[i];
    if (last === '.') {
      srcPath.splice(i, 1);
    } else if (last === '..') {
      srcPath.splice(i, 1);
      up++;
    } else if (up) {
      srcPath.splice(i, 1);
      up--;
    }
  }

  // if the path is allowed to go above the root, restore leading ..s
  if (!mustEndAbs && !removeAllDots) {
    for (; up--; up) {
      srcPath.unshift('..');
    }
  }

  if (mustEndAbs && srcPath[0] !== '' &&
      (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
    srcPath.unshift('');
  }

  if (hasTrailingSlash && (srcPath.join('/').substr(-1) !== '/')) {
    srcPath.push('');
  }

  var isAbsolute = srcPath[0] === '' ||
      (srcPath[0] && srcPath[0].charAt(0) === '/');

  // put the host back
  if (psychotic) {
    result.hostname = result.host = isAbsolute ? '' :
                                    srcPath.length ? srcPath.shift() : '';
    //occationaly the auth can get stuck only in host
    //this especially happens in cases like
    //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
    var authInHost = result.host && result.host.indexOf('@') > 0 ?
                     result.host.split('@') : false;
    if (authInHost) {
      result.auth = authInHost.shift();
      result.host = result.hostname = authInHost.shift();
    }
  }

  mustEndAbs = mustEndAbs || (result.host && srcPath.length);

  if (mustEndAbs && !isAbsolute) {
    srcPath.unshift('');
  }

  if (!srcPath.length) {
    result.pathname = null;
    result.path = null;
  } else {
    result.pathname = srcPath.join('/');
  }

  //to support request.http
  if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
    result.path = (result.pathname ? result.pathname : '') +
                  (result.search ? result.search : '');
  }
  result.auth = relative.auth || result.auth;
  result.slashes = result.slashes || relative.slashes;
  result.href = result.format();
  return result;
};

Url.prototype.parseHost = function() {
  var host = this.host;
  var port = portPattern.exec(host);
  if (port) {
    port = port[0];
    if (port !== ':') {
      this.port = port.substr(1);
    }
    host = host.substr(0, host.length - port.length);
  }
  if (host) this.hostname = host;
};

},{"./util":186,"punycode":163,"querystring":166}],186:[function(require,module,exports){
'use strict';

module.exports = {
  isString: function(arg) {
    return typeof(arg) === 'string';
  },
  isObject: function(arg) {
    return typeof(arg) === 'object' && arg !== null;
  },
  isNull: function(arg) {
    return arg === null;
  },
  isNullOrUndefined: function(arg) {
    return arg == null;
  }
};

},{}],187:[function(require,module,exports){
(function (global){(function (){

/**
 * Module exports.
 */

module.exports = deprecate;

/**
 * Mark that a method should not be used.
 * Returns a modified function which warns once by default.
 *
 * If `localStorage.noDeprecation = true` is set, then it is a no-op.
 *
 * If `localStorage.throwDeprecation = true` is set, then deprecated functions
 * will throw an Error when invoked.
 *
 * If `localStorage.traceDeprecation = true` is set, then deprecated functions
 * will invoke `console.trace()` instead of `console.error()`.
 *
 * @param {Function} fn - the function to deprecate
 * @param {String} msg - the string to print to the console when `fn` is invoked
 * @returns {Function} a new "deprecated" version of `fn`
 * @api public
 */

function deprecate (fn, msg) {
  if (config('noDeprecation')) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (config('throwDeprecation')) {
        throw new Error(msg);
      } else if (config('traceDeprecation')) {
        console.trace(msg);
      } else {
        console.warn(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
}

/**
 * Checks `localStorage` for boolean values for the given `name`.
 *
 * @param {String} name
 * @returns {Boolean}
 * @api private
 */

function config (name) {
  // accessing global.localStorage can trigger a DOMException in sandboxed iframes
  try {
    if (!global.localStorage) return false;
  } catch (_) {
    return false;
  }
  var val = global.localStorage[name];
  if (null == val) return false;
  return String(val).toLowerCase() === 'true';
}

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],188:[function(require,module,exports){
arguments[4][98][0].apply(exports,arguments)
},{"dup":98}],189:[function(require,module,exports){
// Currently in sync with Node.js lib/internal/util/types.js
// https://github.com/nodejs/node/commit/112cc7c27551254aa2b17098fb774867f05ed0d9

'use strict';

var isArgumentsObject = require('is-arguments');
var isGeneratorFunction = require('is-generator-function');
var whichTypedArray = require('which-typed-array');
var isTypedArray = require('is-typed-array');

function uncurryThis(f) {
  return f.call.bind(f);
}

var BigIntSupported = typeof BigInt !== 'undefined';
var SymbolSupported = typeof Symbol !== 'undefined';

var ObjectToString = uncurryThis(Object.prototype.toString);

var numberValue = uncurryThis(Number.prototype.valueOf);
var stringValue = uncurryThis(String.prototype.valueOf);
var booleanValue = uncurryThis(Boolean.prototype.valueOf);

if (BigIntSupported) {
  var bigIntValue = uncurryThis(BigInt.prototype.valueOf);
}

if (SymbolSupported) {
  var symbolValue = uncurryThis(Symbol.prototype.valueOf);
}

function checkBoxedPrimitive(value, prototypeValueOf) {
  if (typeof value !== 'object') {
    return false;
  }
  try {
    prototypeValueOf(value);
    return true;
  } catch(e) {
    return false;
  }
}

exports.isArgumentsObject = isArgumentsObject;
exports.isGeneratorFunction = isGeneratorFunction;
exports.isTypedArray = isTypedArray;

// Taken from here and modified for better browser support
// https://github.com/sindresorhus/p-is-promise/blob/cda35a513bda03f977ad5cde3a079d237e82d7ef/index.js
function isPromise(input) {
	return (
		(
			typeof Promise !== 'undefined' &&
			input instanceof Promise
		) ||
		(
			input !== null &&
			typeof input === 'object' &&
			typeof input.then === 'function' &&
			typeof input.catch === 'function'
		)
	);
}
exports.isPromise = isPromise;

function isArrayBufferView(value) {
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView) {
    return ArrayBuffer.isView(value);
  }

  return (
    isTypedArray(value) ||
    isDataView(value)
  );
}
exports.isArrayBufferView = isArrayBufferView;


function isUint8Array(value) {
  return whichTypedArray(value) === 'Uint8Array';
}
exports.isUint8Array = isUint8Array;

function isUint8ClampedArray(value) {
  return whichTypedArray(value) === 'Uint8ClampedArray';
}
exports.isUint8ClampedArray = isUint8ClampedArray;

function isUint16Array(value) {
  return whichTypedArray(value) === 'Uint16Array';
}
exports.isUint16Array = isUint16Array;

function isUint32Array(value) {
  return whichTypedArray(value) === 'Uint32Array';
}
exports.isUint32Array = isUint32Array;

function isInt8Array(value) {
  return whichTypedArray(value) === 'Int8Array';
}
exports.isInt8Array = isInt8Array;

function isInt16Array(value) {
  return whichTypedArray(value) === 'Int16Array';
}
exports.isInt16Array = isInt16Array;

function isInt32Array(value) {
  return whichTypedArray(value) === 'Int32Array';
}
exports.isInt32Array = isInt32Array;

function isFloat32Array(value) {
  return whichTypedArray(value) === 'Float32Array';
}
exports.isFloat32Array = isFloat32Array;

function isFloat64Array(value) {
  return whichTypedArray(value) === 'Float64Array';
}
exports.isFloat64Array = isFloat64Array;

function isBigInt64Array(value) {
  return whichTypedArray(value) === 'BigInt64Array';
}
exports.isBigInt64Array = isBigInt64Array;

function isBigUint64Array(value) {
  return whichTypedArray(value) === 'BigUint64Array';
}
exports.isBigUint64Array = isBigUint64Array;

function isMapToString(value) {
  return ObjectToString(value) === '[object Map]';
}
isMapToString.working = (
  typeof Map !== 'undefined' &&
  isMapToString(new Map())
);

function isMap(value) {
  if (typeof Map === 'undefined') {
    return false;
  }

  return isMapToString.working
    ? isMapToString(value)
    : value instanceof Map;
}
exports.isMap = isMap;

function isSetToString(value) {
  return ObjectToString(value) === '[object Set]';
}
isSetToString.working = (
  typeof Set !== 'undefined' &&
  isSetToString(new Set())
);
function isSet(value) {
  if (typeof Set === 'undefined') {
    return false;
  }

  return isSetToString.working
    ? isSetToString(value)
    : value instanceof Set;
}
exports.isSet = isSet;

function isWeakMapToString(value) {
  return ObjectToString(value) === '[object WeakMap]';
}
isWeakMapToString.working = (
  typeof WeakMap !== 'undefined' &&
  isWeakMapToString(new WeakMap())
);
function isWeakMap(value) {
  if (typeof WeakMap === 'undefined') {
    return false;
  }

  return isWeakMapToString.working
    ? isWeakMapToString(value)
    : value instanceof WeakMap;
}
exports.isWeakMap = isWeakMap;

function isWeakSetToString(value) {
  return ObjectToString(value) === '[object WeakSet]';
}
isWeakSetToString.working = (
  typeof WeakSet !== 'undefined' &&
  isWeakSetToString(new WeakSet())
);
function isWeakSet(value) {
  return isWeakSetToString(value);
}
exports.isWeakSet = isWeakSet;

function isArrayBufferToString(value) {
  return ObjectToString(value) === '[object ArrayBuffer]';
}
isArrayBufferToString.working = (
  typeof ArrayBuffer !== 'undefined' &&
  isArrayBufferToString(new ArrayBuffer())
);
function isArrayBuffer(value) {
  if (typeof ArrayBuffer === 'undefined') {
    return false;
  }

  return isArrayBufferToString.working
    ? isArrayBufferToString(value)
    : value instanceof ArrayBuffer;
}
exports.isArrayBuffer = isArrayBuffer;

function isDataViewToString(value) {
  return ObjectToString(value) === '[object DataView]';
}
isDataViewToString.working = (
  typeof ArrayBuffer !== 'undefined' &&
  typeof DataView !== 'undefined' &&
  isDataViewToString(new DataView(new ArrayBuffer(1), 0, 1))
);
function isDataView(value) {
  if (typeof DataView === 'undefined') {
    return false;
  }

  return isDataViewToString.working
    ? isDataViewToString(value)
    : value instanceof DataView;
}
exports.isDataView = isDataView;

// Store a copy of SharedArrayBuffer in case it's deleted elsewhere
var SharedArrayBufferCopy = typeof SharedArrayBuffer !== 'undefined' ? SharedArrayBuffer : undefined;
function isSharedArrayBufferToString(value) {
  return ObjectToString(value) === '[object SharedArrayBuffer]';
}
function isSharedArrayBuffer(value) {
  if (typeof SharedArrayBufferCopy === 'undefined') {
    return false;
  }

  if (typeof isSharedArrayBufferToString.working === 'undefined') {
    isSharedArrayBufferToString.working = isSharedArrayBufferToString(new SharedArrayBufferCopy());
  }

  return isSharedArrayBufferToString.working
    ? isSharedArrayBufferToString(value)
    : value instanceof SharedArrayBufferCopy;
}
exports.isSharedArrayBuffer = isSharedArrayBuffer;

function isAsyncFunction(value) {
  return ObjectToString(value) === '[object AsyncFunction]';
}
exports.isAsyncFunction = isAsyncFunction;

function isMapIterator(value) {
  return ObjectToString(value) === '[object Map Iterator]';
}
exports.isMapIterator = isMapIterator;

function isSetIterator(value) {
  return ObjectToString(value) === '[object Set Iterator]';
}
exports.isSetIterator = isSetIterator;

function isGeneratorObject(value) {
  return ObjectToString(value) === '[object Generator]';
}
exports.isGeneratorObject = isGeneratorObject;

function isWebAssemblyCompiledModule(value) {
  return ObjectToString(value) === '[object WebAssembly.Module]';
}
exports.isWebAssemblyCompiledModule = isWebAssemblyCompiledModule;

function isNumberObject(value) {
  return checkBoxedPrimitive(value, numberValue);
}
exports.isNumberObject = isNumberObject;

function isStringObject(value) {
  return checkBoxedPrimitive(value, stringValue);
}
exports.isStringObject = isStringObject;

function isBooleanObject(value) {
  return checkBoxedPrimitive(value, booleanValue);
}
exports.isBooleanObject = isBooleanObject;

function isBigIntObject(value) {
  return BigIntSupported && checkBoxedPrimitive(value, bigIntValue);
}
exports.isBigIntObject = isBigIntObject;

function isSymbolObject(value) {
  return SymbolSupported && checkBoxedPrimitive(value, symbolValue);
}
exports.isSymbolObject = isSymbolObject;

function isBoxedPrimitive(value) {
  return (
    isNumberObject(value) ||
    isStringObject(value) ||
    isBooleanObject(value) ||
    isBigIntObject(value) ||
    isSymbolObject(value)
  );
}
exports.isBoxedPrimitive = isBoxedPrimitive;

function isAnyArrayBuffer(value) {
  return typeof Uint8Array !== 'undefined' && (
    isArrayBuffer(value) ||
    isSharedArrayBuffer(value)
  );
}
exports.isAnyArrayBuffer = isAnyArrayBuffer;

['isProxy', 'isExternal', 'isModuleNamespaceObject'].forEach(function(method) {
  Object.defineProperty(exports, method, {
    enumerable: false,
    value: function() {
      throw new Error(method + ' is not supported in userland');
    }
  });
});

},{"is-arguments":127,"is-generator-function":130,"is-typed-array":131,"which-typed-array":194}],190:[function(require,module,exports){
(function (process){(function (){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors ||
  function getOwnPropertyDescriptors(obj) {
    var keys = Object.keys(obj);
    var descriptors = {};
    for (var i = 0; i < keys.length; i++) {
      descriptors[keys[i]] = Object.getOwnPropertyDescriptor(obj, keys[i]);
    }
    return descriptors;
  };

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  if (typeof process !== 'undefined' && process.noDeprecation === true) {
    return fn;
  }

  // Allow for deprecating things in the process of starting up.
  if (typeof process === 'undefined') {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnvRegex = /^$/;

if (process.env.NODE_DEBUG) {
  var debugEnv = process.env.NODE_DEBUG;
  debugEnv = debugEnv.replace(/[|\\{}()[\]^$+?.]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/,/g, '$|^')
    .toUpperCase();
  debugEnvRegex = new RegExp('^' + debugEnv + '$', 'i');
}
exports.debuglog = function(set) {
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (debugEnvRegex.test(set)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').slice(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.slice(1, -1);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
exports.types = require('./support/types');

function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;
exports.types.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;
exports.types.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;
exports.types.isNativeError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = require('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = require('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

var kCustomPromisifiedSymbol = typeof Symbol !== 'undefined' ? Symbol('util.promisify.custom') : undefined;

exports.promisify = function promisify(original) {
  if (typeof original !== 'function')
    throw new TypeError('The "original" argument must be of type Function');

  if (kCustomPromisifiedSymbol && original[kCustomPromisifiedSymbol]) {
    var fn = original[kCustomPromisifiedSymbol];
    if (typeof fn !== 'function') {
      throw new TypeError('The "util.promisify.custom" argument must be of type Function');
    }
    Object.defineProperty(fn, kCustomPromisifiedSymbol, {
      value: fn, enumerable: false, writable: false, configurable: true
    });
    return fn;
  }

  function fn() {
    var promiseResolve, promiseReject;
    var promise = new Promise(function (resolve, reject) {
      promiseResolve = resolve;
      promiseReject = reject;
    });

    var args = [];
    for (var i = 0; i < arguments.length; i++) {
      args.push(arguments[i]);
    }
    args.push(function (err, value) {
      if (err) {
        promiseReject(err);
      } else {
        promiseResolve(value);
      }
    });

    try {
      original.apply(this, args);
    } catch (err) {
      promiseReject(err);
    }

    return promise;
  }

  Object.setPrototypeOf(fn, Object.getPrototypeOf(original));

  if (kCustomPromisifiedSymbol) Object.defineProperty(fn, kCustomPromisifiedSymbol, {
    value: fn, enumerable: false, writable: false, configurable: true
  });
  return Object.defineProperties(
    fn,
    getOwnPropertyDescriptors(original)
  );
}

exports.promisify.custom = kCustomPromisifiedSymbol

function callbackifyOnRejected(reason, cb) {
  // `!reason` guard inspired by bluebird (Ref: https://goo.gl/t5IS6M).
  // Because `null` is a special error value in callbacks which means "no error
  // occurred", we error-wrap so the callback consumer can distinguish between
  // "the promise rejected with null" or "the promise fulfilled with undefined".
  if (!reason) {
    var newReason = new Error('Promise was rejected with a falsy value');
    newReason.reason = reason;
    reason = newReason;
  }
  return cb(reason);
}

function callbackify(original) {
  if (typeof original !== 'function') {
    throw new TypeError('The "original" argument must be of type Function');
  }

  // We DO NOT return the promise as it gives the user a false sense that
  // the promise is actually somehow related to the callback's execution
  // and that the callback throwing will reject the promise.
  function callbackified() {
    var args = [];
    for (var i = 0; i < arguments.length; i++) {
      args.push(arguments[i]);
    }

    var maybeCb = args.pop();
    if (typeof maybeCb !== 'function') {
      throw new TypeError('The last argument must be of type Function');
    }
    var self = this;
    var cb = function() {
      return maybeCb.apply(self, arguments);
    };
    // In true node style we process the callback on `nextTick` with all the
    // implications (stack, `uncaughtException`, `async_hooks`)
    original.apply(this, args)
      .then(function(ret) { process.nextTick(cb.bind(null, null, ret)) },
            function(rej) { process.nextTick(callbackifyOnRejected.bind(null, rej, cb)) });
  }

  Object.setPrototypeOf(callbackified, Object.getPrototypeOf(original));
  Object.defineProperties(callbackified,
                          getOwnPropertyDescriptors(original));
  return callbackified;
}
exports.callbackify = callbackify;

}).call(this)}).call(this,require('_process'))
},{"./support/isBuffer":188,"./support/types":189,"_process":162,"inherits":126}],191:[function(require,module,exports){
(function (global,setImmediate){(function (){
/*
 * vasync.js: utilities for observable asynchronous control flow
 */

var mod_assert = require('assert');
var mod_events = require('events');
var mod_util = require('util');
var mod_verror = require('verror');

/*
 * Public interface
 */
exports.parallel = parallel;
exports.forEachParallel = forEachParallel;
exports.pipeline = pipeline;
exports.tryEach = tryEach;
exports.forEachPipeline = forEachPipeline;
exports.filter = filter;
exports.filterLimit = filterLimit;
exports.filterSeries = filterSeries;
exports.whilst = whilst;
exports.queue = queue;
exports.queuev = queuev;
exports.barrier = barrier;
exports.waterfall = waterfall;

if (!global.setImmediate) {
	global.setImmediate = function (func) {
		var args = Array.prototype.slice.call(arguments, 1);
		args.unshift(0);
		args.unshift(func);
		setTimeout.apply(this, args);
	};
}

/*
 * This is incorporated here from jsprim because jsprim ends up pulling in a lot
 * of dependencies.  If we end up needing more from jsprim, though, we should
 * add it back and rip out this function.
 */
function isEmpty(obj)
{
	var key;
	for (key in obj)
		return (false);
	return (true);
}

/*
 * Given a set of functions that complete asynchronously using the standard
 * callback(err, result) pattern, invoke them all and merge the results.  See
 * README.md for details.
 */
function parallel(args, callback)
{
	var funcs, rv, doneOne, i;

	mod_assert.equal(typeof (args), 'object', '"args" must be an object');
	mod_assert.ok(Array.isArray(args['funcs']),
	    '"args.funcs" must be specified and must be an array');
	mod_assert.equal(typeof (callback), 'function',
	    'callback argument must be specified and must be a function');

	funcs = args['funcs'].slice(0);

	rv = {
	    'operations': new Array(funcs.length),
	    'successes': [],
	    'ndone': 0,
	    'nerrors': 0
	};

	if (funcs.length === 0) {
		setImmediate(function () { callback(null, rv); });
		return (rv);
	}

	doneOne = function (entry) {
		return (function (err, result) {
			mod_assert.equal(entry['status'], 'pending');

			entry['err'] = err;
			entry['result'] = result;
			entry['status'] = err ? 'fail' : 'ok';

			if (err)
				rv['nerrors']++;
			else
				rv['successes'].push(result);

			if (++rv['ndone'] < funcs.length)
				return;

			var errors = rv['operations'].filter(function (ent) {
				return (ent['status'] == 'fail');
			}).map(function (ent) { return (ent['err']); });

			if (errors.length > 0)
				callback(new mod_verror.MultiError(errors), rv);
			else
				callback(null, rv);
		});
	};

	for (i = 0; i < funcs.length; i++) {
		rv['operations'][i] = {
			'func': funcs[i],
			'funcname': funcs[i].name || '(anon)',
			'status': 'pending'
		};

		funcs[i](doneOne(rv['operations'][i]));
	}

	return (rv);
}

/*
 * Exactly like parallel, except that the input is specified as a single
 * function to invoke on N different inputs (rather than N functions).  "args"
 * must have the following fields:
 *
 *	func		asynchronous function to invoke on each input value
 *
 *	inputs		array of input values
 */
function forEachParallel(args, callback)
{
	var func, funcs;

	mod_assert.equal(typeof (args), 'object', '"args" must be an object');
	mod_assert.equal(typeof (args['func']), 'function',
	    '"args.func" must be specified and must be a function');
	mod_assert.ok(Array.isArray(args['inputs']),
	    '"args.inputs" must be specified and must be an array');

	func = args['func'];
	funcs = args['inputs'].map(function (input) {
		return (function (subcallback) {
			return (func(input, subcallback));
		});
	});

	return (parallel({ 'funcs': funcs }, callback));
}

/*
 * Like parallel, but invokes functions in sequence rather than in parallel
 * and aborts if any function exits with failure.  Arguments include:
 *
 *    funcs	invoke the functions in parallel
 *
 *    arg	first argument to each pipeline function
 */
function pipeline(args, callback)
{
	mod_assert.equal(typeof (args), 'object', '"args" must be an object');
	mod_assert.ok(Array.isArray(args['funcs']),
	    '"args.funcs" must be specified and must be an array');

	var opts = {
	    'funcs': args['funcs'].slice(0),
	    'callback': callback,
	    'args': { impl: 'pipeline', uarg: args['arg'] },
	    'stop_when': 'error',
	    'res_type': 'rv'
	};
	return (waterfall_impl(opts));
}

function tryEach(funcs, callback)
{
	mod_assert.ok(Array.isArray(funcs),
	    '"funcs" must be specified and must be an array');
	mod_assert.ok(arguments.length == 1 || typeof (callback) == 'function',
	    '"callback" must be a function');
	var opts = {
	    'funcs': funcs.slice(0),
	    'callback': callback,
	    'args': { impl: 'tryEach' },
	    'stop_when': 'success',
	    'res_type': 'array'
	};
	return (waterfall_impl(opts));
}

/*
 * Exactly like pipeline, except that the input is specified as a single
 * function to invoke on N different inputs (rather than N functions).  "args"
 * must have the following fields:
 *
 *	func		asynchronous function to invoke on each input value
 *
 *	inputs		array of input values
 */
function forEachPipeline(args, callback) {
	mod_assert.equal(typeof (args), 'object', '"args" must be an object');
	mod_assert.equal(typeof (args['func']), 'function',
	    '"args.func" must be specified and must be a function');
	mod_assert.ok(Array.isArray(args['inputs']),
	    '"args.inputs" must be specified and must be an array');
	mod_assert.equal(typeof (callback), 'function',
	    'callback argument must be specified and must be a function');

	var func = args['func'];

	var funcs = args['inputs'].map(function (input) {
		return (function (_, subcallback) {
				return (func(input, subcallback));
			});
	});

	return (pipeline({'funcs': funcs}, callback));
}

/*
 * async.js compatible filter, filterLimit, and filterSeries.  Takes an input
 * array, optionally a limit, and a single function to filter an array and will
 * callback with a new filtered array. This is effectively an asynchronous
 * version of Array.prototype.filter.
 */
function filter(inputs, filterFunc, callback) {
	return (filterLimit(inputs, Infinity, filterFunc, callback));
}

function filterSeries(inputs, filterFunc, callback) {
	return (filterLimit(inputs, 1, filterFunc, callback));
}

function filterLimit(inputs, limit, filterFunc, callback) {
	mod_assert.ok(Array.isArray(inputs),
	    '"inputs" must be specified and must be an array');
	mod_assert.equal(typeof (limit), 'number',
	    '"limit" must be a number');
	mod_assert.equal(isNaN(limit), false,
	    '"limit" must be a number');
	mod_assert.equal(typeof (filterFunc), 'function',
	    '"filterFunc" must be specified and must be a function');
	mod_assert.equal(typeof (callback), 'function',
	    '"callback" argument must be specified as a function');

	var errors = [];
	var q = queue(processInput, limit);
	var results = [];

	function processInput(input, cb) {
		/*
		 * If the errors array has any members, an error was
		 * encountered in a previous invocation of filterFunc, so all
		 * future filtering will be skipped.
		 */
		if (errors.length > 0) {
			cb();
			return;
		}

		filterFunc(input.elem, function inputFiltered(err, ans) {
			/*
			 * We ensure here that a filterFunc callback is only
			 * ever invoked once.
			 */
			if (results.hasOwnProperty(input.idx)) {
				throw (new mod_verror.VError(
				    'vasync.filter*: filterFunc idx %d ' +
				    'invoked its callback twice', input.idx));
			}

			/*
			 * The original element, as well as the answer "ans"
			 * (truth value) is stored to later be filtered when
			 * all outstanding jobs are finished.
			 */
			results[input.idx] = {
				elem: input.elem,
				ans: !!ans
			};

			/*
			 * Any error encountered while filtering will result in
			 * all future operations being skipped, and the error
			 * object being returned in the users callback.
			 */
			if (err) {
				errors.push(err);
				cb();
				return;
			}

			cb();
		});
	}

	q.once('end', function queueDrained() {
		if (errors.length > 0) {
			callback(mod_verror.errorFromList(errors));
			return;
		}

		/*
		 * results is now an array of objects in the same order of the
		 * inputs array, where each object looks like:
		 *
		 * {
		 *     "ans": <true|false>,
		 *     "elem": <original input element>
		 * }
		 *
		 * we filter out elements that have a false "ans" value, and
		 * then map the array to contain only the input elements.
		 */
		results = results.filter(function filterFalseInputs(input) {
			return (input.ans);
		}).map(function mapInputElements(input) {
			return (input.elem);
		});
		callback(null, results);
	});

	inputs.forEach(function iterateInput(elem, idx) {
		/*
		 * We retain the array index to ensure that order is
		 * maintained.
		 */
		q.push({
			elem: elem,
			idx: idx
		});
	});

	q.close();

	return (q);
}

/*
 * async-compatible "whilst" function, with a few notable exceptions/addons.
 *
 * 1. More strict typing of arguments (functions *must* be supplied).
 * 2. A callback function is required, not optional.
 * 3. An object is returned, not undefined.
 */
function whilst(testFunc, iterateFunc, callback) {
	mod_assert.equal(typeof (testFunc), 'function',
	    '"testFunc" must be specified and must be a function');
	mod_assert.equal(typeof (iterateFunc), 'function',
	    '"iterateFunc" must be specified and must be a function');
	mod_assert.equal(typeof (callback), 'function',
	    '"callback" argument must be specified as a function');

	/*
	 * The object returned to the caller that provides a read-only
	 * interface to introspect this specific invocation of "whilst".
	 */
	var o = {
	    'finished': false,
	    'iterations': 0
	};

	/*
	 * Store the last set of arguments from the final call to "iterateFunc".
	 * The arguments will be passed to the final callback when an error is
	 * encountered or when the testFunc returns false.
	 */
	var args = [];

	function iterate() {
		var shouldContinue = testFunc();

		if (!shouldContinue) {
			/*
			 * The test condition is false - break out of the loop.
			 */
			done();
			return;
		}

		/* Bump iterations after testFunc but before iterateFunc. */
		o.iterations++;

		iterateFunc(function whilstIteration(err) {
			/* Store the latest set of arguments seen. */
			args = Array.prototype.slice.call(arguments);

			/* Any error with iterateFunc will break the loop. */
			if (err) {
				done();
				return;
			}

			/* Try again. */
			setImmediate(iterate);
		});
	}

	function done() {
		mod_assert.ok(!o.finished, 'whilst already finished');
		o.finished = true;
		callback.apply(this, args);
	}

	setImmediate(iterate);

	return (o);
}

/*
 * async-compatible "queue" function.
 */
function queue(worker, concurrency)
{
	return (new WorkQueue({
	    'worker': worker,
	    'concurrency': concurrency
	}));
}

function queuev(args)
{
	return (new WorkQueue(args));
}

function WorkQueue(args)
{
	mod_assert.ok(args.hasOwnProperty('worker'));
	mod_assert.equal(typeof (args['worker']), 'function');
	mod_assert.ok(args.hasOwnProperty('concurrency'));
	mod_assert.equal(typeof (args['concurrency']), 'number');
	mod_assert.equal(Math.floor(args['concurrency']), args['concurrency']);
	mod_assert.ok(args['concurrency'] > 0);

	mod_events.EventEmitter.call(this);

	this.nextid = 0;
	this.worker = args['worker'];
	this.worker_name = args['worker'].name || 'anon';
	this.npending = 0;
	this.pending = {};
	this.queued = [];
	this.closed = false;
	this.ended = false;

	/* user-settable fields inherited from "async" interface */
	this.concurrency = args['concurrency'];
	this.saturated = undefined;
	this.empty = undefined;
	this.drain = undefined;
}

mod_util.inherits(WorkQueue, mod_events.EventEmitter);

WorkQueue.prototype.push = function (tasks, callback)
{
	if (!Array.isArray(tasks))
		return (this.pushOne(tasks, callback));

	var wq = this;
	return (tasks.map(function (task) {
	    return (wq.pushOne(task, callback));
	}));
};

WorkQueue.prototype.updateConcurrency = function (concurrency)
{
	if (this.closed)
		throw new mod_verror.VError(
			'update concurrency invoked after queue closed');
	this.concurrency = concurrency;
	this.dispatchNext();
};

WorkQueue.prototype.close = function ()
{
	var wq = this;

	if (wq.closed)
		return;
	wq.closed = true;

	/*
	 * If the queue is already empty, just fire the "end" event on the
	 * next tick.
	 */
	if (wq.npending === 0 && wq.queued.length === 0) {
		setImmediate(function () {
			if (!wq.ended) {
				wq.ended = true;
				wq.emit('end');
			}
		});
	}
};

/* private */
WorkQueue.prototype.pushOne = function (task, callback)
{
	if (this.closed)
		throw new mod_verror.VError('push invoked after queue closed');

	var id = ++this.nextid;
	var entry = { 'id': id, 'task': task, 'callback': callback };

	this.queued.push(entry);
	this.dispatchNext();

	return (id);
};

/* private */
WorkQueue.prototype.dispatchNext = function ()
{
	var wq = this;
	if (wq.npending === 0 && wq.queued.length === 0) {
		if (wq.drain)
			wq.drain();
		wq.emit('drain');
		/*
		 * The queue is closed; emit the final "end"
		 * event before we come to rest:
		 */
		if (wq.closed) {
			wq.ended = true;
			wq.emit('end');
		}
	} else if (wq.queued.length > 0) {
		while (wq.queued.length > 0 && wq.npending < wq.concurrency) {
			var next = wq.queued.shift();
			wq.dispatch(next);

			if (wq.queued.length === 0) {
				if (wq.empty)
					wq.empty();
				wq.emit('empty');
			}
		}
	}
};

WorkQueue.prototype.dispatch = function (entry)
{
	var wq = this;

	mod_assert.ok(!this.pending.hasOwnProperty(entry['id']));
	mod_assert.ok(this.npending < this.concurrency);
	mod_assert.ok(!this.ended);

	this.npending++;
	this.pending[entry['id']] = entry;

	if (this.npending === this.concurrency) {
		if (this.saturated)
			this.saturated();
		this.emit('saturated');
	}

	/*
	 * We invoke the worker function on the next tick so that callers can
	 * always assume that the callback is NOT invoked during the call to
	 * push() even if the queue is not at capacity.  It also avoids O(n)
	 * stack usage when used with synchronous worker functions.
	 */
	setImmediate(function () {
		wq.worker(entry['task'], function (err) {
			--wq.npending;
			delete (wq.pending[entry['id']]);

			if (entry['callback'])
				entry['callback'].apply(null, arguments);

			wq.dispatchNext();
		});
	});
};

WorkQueue.prototype.length = function ()
{
	return (this.queued.length);
};

WorkQueue.prototype.kill = function ()
{
	this.killed = true;
	this.queued = [];
	this.drain = undefined;
	this.close();
};

/*
 * Barriers coordinate multiple concurrent operations.
 */
function barrier(args)
{
	return (new Barrier(args));
}

function Barrier(args)
{
	mod_assert.ok(!args || !args['nrecent'] ||
	    typeof (args['nrecent']) == 'number',
	    '"nrecent" must have type "number"');

	mod_events.EventEmitter.call(this);

	var nrecent = args && args['nrecent'] ? args['nrecent'] : 10;

	if (nrecent > 0) {
		this.nrecent = nrecent;
		this.recent = [];
	}

	this.pending = {};
	this.scheduled = false;
}

mod_util.inherits(Barrier, mod_events.EventEmitter);

Barrier.prototype.start = function (name)
{
	mod_assert.ok(!this.pending.hasOwnProperty(name),
	    'operation "' + name + '" is already pending');
	this.pending[name] = Date.now();
};

Barrier.prototype.done = function (name)
{
	mod_assert.ok(this.pending.hasOwnProperty(name),
	    'operation "' + name + '" is not pending');

	if (this.recent) {
		this.recent.push({
		    'name': name,
		    'start': this.pending[name],
		    'done': Date.now()
		});

		if (this.recent.length > this.nrecent)
			this.recent.shift();
	}

	delete (this.pending[name]);

	/*
	 * If we executed at least one operation and we're now empty, we should
	 * emit "drain".  But most code doesn't deal well with events being
	 * processed while they're executing, so we actually schedule this event
	 * for the next tick.
	 *
	 * We use the "scheduled" flag to avoid emitting multiple "drain" events
	 * on consecutive ticks if the user starts and ends another task during
	 * this tick.
	 */
	if (!isEmpty(this.pending) || this.scheduled)
		return;

	this.scheduled = true;

	var self = this;

	setImmediate(function () {
		self.scheduled = false;

		/*
		 * It's also possible that the user has started another task on
		 * the previous tick, in which case we really shouldn't emit
		 * "drain".
		 */
		if (isEmpty(self.pending))
			self.emit('drain');
	});
};

/*
 * waterfall([ funcs ], callback): invoke each of the asynchronous functions
 * "funcs" in series.  Each function is passed any values emitted by the
 * previous function (none for the first function), followed by the callback to
 * invoke upon completion.  This callback must be invoked exactly once,
 * regardless of success or failure.  As conventional in Node, the first
 * argument to the callback indicates an error (if non-null).  Subsequent
 * arguments are passed to the next function in the "funcs" chain.
 *
 * If any function fails (i.e., calls its callback with an Error), then the
 * remaining functions are not invoked and "callback" is invoked with the error.
 *
 * The only difference between waterfall() and pipeline() are the arguments
 * passed to each function in the chain.  pipeline() always passes the same
 * argument followed by the callback, while waterfall() passes whatever values
 * were emitted by the previous function followed by the callback.
 */
function waterfall(funcs, callback)
{
	mod_assert.ok(Array.isArray(funcs),
	    '"funcs" must be specified and must be an array');
	mod_assert.ok(arguments.length == 1 || typeof (callback) == 'function',
	    '"callback" must be a function');
	var opts = {
	    'funcs': funcs.slice(0),
	    'callback': callback,
	    'args': { impl: 'waterfall' },
	    'stop_when': 'error',
	    'res_type': 'values'
	};
	return (waterfall_impl(opts));
}

/*
 * This function is used to implement vasync-functions that need to execute a
 * list of functions in a sequence, but differ in how they make use of the
 * intermediate callbacks and finall callback, as well as under what conditions
 * they stop executing the functions in the list. Examples of such functions
 * are `pipeline`, `waterfall`, and `tryEach`. See the documentation for those
 * functions to see how they operate.
 *
 * This function's behavior is influenced via the `opts` object that we pass
 * in. This object has the following layout:
 *
 * 	{
 * 		'funcs': array of functions
 * 		'callback': the final callback
 * 		'args': {
 * 			'impl': 'pipeline' or 'tryEach' or 'waterfall'
 * 			'uarg': the arg passed to each func for 'pipeline'
 * 			}
 * 		'stop_when': 'error' or 'success'
 * 		'res_type': 'values' or 'arrays' or 'rv'
 * 	}
 *
 * In the object, 'res_type' is used to indicate what the type of the result
 * values(s) is that we pass to the final callback. We secondarily use
 * 'args.impl' to adjust this behavior in an implementation-specific way. For
 * example, 'tryEach' only returns an array if it has more than 1 result passed
 * to the final callback. Otherwise, it passes a solitary value to the final
 * callback.
 *
 * In case it's not clear, 'rv' in the `res_type` member, is just the
 * result-value that we also return. This is the convention in functions that
 * originated in `vasync` (pipeline), but not in functions that originated in
 * `async` (waterfall, tryEach).
 */
function waterfall_impl(opts)
{
	mod_assert.ok(typeof (opts) === 'object');
	var rv, current, next;
	var funcs = opts.funcs;
	var callback = opts.callback;

	mod_assert.ok(Array.isArray(funcs),
	    '"opts.funcs" must be specified and must be an array');
	mod_assert.ok(arguments.length == 1,
	    'Function "waterfall_impl" must take only 1 arg');
	mod_assert.ok(opts.res_type === 'values' ||
	    opts.res_type === 'array' || opts.res_type == 'rv',
	    '"opts.res_type" must either be "values", "array", or "rv"');
	mod_assert.ok(opts.stop_when === 'error' ||
	    opts.stop_when === 'success',
	    '"opts.stop_when" must either be "error" or "success"');
	mod_assert.ok(opts.args.impl === 'pipeline' ||
	    opts.args.impl === 'waterfall' || opts.args.impl === 'tryEach',
	    '"opts.args.impl" must be "pipeline", "waterfall", or "tryEach"');
	if (opts.args.impl === 'pipeline') {
		mod_assert.ok(typeof (opts.args.uarg) !== undefined,
		    '"opts.args.uarg" should be defined when pipeline is used');
	}

	rv = {
	    'operations': funcs.map(function (func) {
	        return ({
		    'func': func,
		    'funcname': func.name || '(anon)',
		    'status': 'waiting'
		});
	    }),
	    'successes': [],
	    'ndone': 0,
	    'nerrors': 0
	};

	if (funcs.length === 0) {
		if (callback)
			setImmediate(function () {
				var res = (opts.args.impl === 'pipeline') ? rv
				    : undefined;
				callback(null, res);
			});
		return (rv);
	}

	next = function (idx, err) {
		/*
		 * Note that nfunc_args contains the args we will pass to the
		 * next func in the func-list the user gave us. Except for
		 * 'tryEach', which passes cb's. However, it will pass
		 * 'nfunc_args' to its final callback -- see below.
		 */
		var res_key, nfunc_args, entry, nextentry;

		if (err === undefined)
			err = null;

		if (idx != current) {
			throw (new mod_verror.VError(
			    'vasync.waterfall: function %d ("%s") invoked ' +
			    'its callback twice', idx,
			    rv['operations'][idx].funcname));
		}

		mod_assert.equal(idx, rv['ndone'],
		    'idx should be equal to ndone');
		entry = rv['operations'][rv['ndone']++];
		if (opts.args.impl === 'tryEach' ||
		    opts.args.impl === 'waterfall') {
			nfunc_args = Array.prototype.slice.call(arguments, 2);
			res_key = 'results';
			entry['results'] = nfunc_args;
		} else if (opts.args.impl === 'pipeline') {
			nfunc_args = [ opts.args.uarg ];
			res_key = 'result';
			entry['result'] = arguments[2];
		}

		mod_assert.equal(entry['status'], 'pending',
		    'status should be pending');
		entry['status'] = err ? 'fail' : 'ok';
		entry['err'] = err;

		if (err) {
			rv['nerrors']++;
		} else {
			rv['successes'].push(entry[res_key]);
		}

		if ((opts.stop_when === 'error' && err) ||
		    (opts.stop_when === 'success' &&
		    rv['successes'].length > 0) ||
		    rv['ndone'] == funcs.length) {
			if (callback) {
				if (opts.res_type === 'values' ||
				    (opts.res_type === 'array' &&
				     nfunc_args.length <= 1)) {
					nfunc_args.unshift(err);
					callback.apply(null, nfunc_args);
				} else if (opts.res_type === 'array') {
					callback(err, nfunc_args);
				} else if (opts.res_type === 'rv') {
					callback(err, rv);
				}
			}
		} else {
			nextentry = rv['operations'][rv['ndone']];
			nextentry['status'] = 'pending';
			current++;
			nfunc_args.push(next.bind(null, current));
			setImmediate(function () {
				var nfunc = nextentry['func'];
				/*
				 * At first glance it may seem like this branch
				 * is superflous with the code above that
				 * branches on `opts.args.impl`. It may also
				 * seem like calling `nfunc.apply` is
				 * sufficient for both cases (after all we
				 * pushed `next.bind(null, current)` to the
				 * `nfunc_args` array), before we call
				 * `setImmediate()`. However, this is not the
				 * case, because the interface exposed by
				 * tryEach is different from the others. The
				 * others pass argument(s) from task to task.
				 * tryEach passes nothing but a callback
				 * (`next.bind` below). However, the callback
				 * itself _can_ be called with one or more
				 * results, which we collect into `nfunc_args`
				 * using the aformentioned `opts.args.impl`
				 * branch above, and which we pass to the
				 * callback via the `opts.res_type` branch
				 * above (where res_type is set to 'array').
				 */
				if (opts.args.impl !== 'tryEach') {
					nfunc.apply(null, nfunc_args);
				} else {
					nfunc(next.bind(null, current));
				}
			});
		}
	};

	rv['operations'][0]['status'] = 'pending';
	current = 0;
	if (opts.args.impl !== 'pipeline') {
		funcs[0](next.bind(null, current));
	} else {
		funcs[0](opts.args.uarg, next.bind(null, current));
	}
	return (rv);
}

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {},require("timers").setImmediate)
},{"assert":96,"events":114,"timers":184,"util":190,"verror":192}],192:[function(require,module,exports){
/*
 * verror.js: richer JavaScript errors
 */

var mod_assertplus = require('assert-plus');
var mod_util = require('util');

var mod_extsprintf = require('extsprintf');
var mod_isError = require('core-util-is').isError;
var sprintf = mod_extsprintf.sprintf;

/*
 * Public interface
 */

/* So you can 'var VError = require('verror')' */
module.exports = VError;
/* For compatibility */
VError.VError = VError;
/* Other exported classes */
VError.SError = SError;
VError.WError = WError;
VError.MultiError = MultiError;

/*
 * Common function used to parse constructor arguments for VError, WError, and
 * SError.  Named arguments to this function:
 *
 *     strict		force strict interpretation of sprintf arguments, even
 *     			if the options in "argv" don't say so
 *
 *     argv		error's constructor arguments, which are to be
 *     			interpreted as described in README.md.  For quick
 *     			reference, "argv" has one of the following forms:
 *
 *          [ sprintf_args... ]           (argv[0] is a string)
 *          [ cause, sprintf_args... ]    (argv[0] is an Error)
 *          [ options, sprintf_args... ]  (argv[0] is an object)
 *
 * This function normalizes these forms, producing an object with the following
 * properties:
 *
 *    options           equivalent to "options" in third form.  This will never
 *    			be a direct reference to what the caller passed in
 *    			(i.e., it may be a shallow copy), so it can be freely
 *    			modified.
 *
 *    shortmessage      result of sprintf(sprintf_args), taking options.strict
 *    			into account as described in README.md.
 */
function parseConstructorArguments(args)
{
	var argv, options, sprintf_args, shortmessage, k;

	mod_assertplus.object(args, 'args');
	mod_assertplus.bool(args.strict, 'args.strict');
	mod_assertplus.array(args.argv, 'args.argv');
	argv = args.argv;

	/*
	 * First, figure out which form of invocation we've been given.
	 */
	if (argv.length === 0) {
		options = {};
		sprintf_args = [];
	} else if (mod_isError(argv[0])) {
		options = { 'cause': argv[0] };
		sprintf_args = argv.slice(1);
	} else if (typeof (argv[0]) === 'object') {
		options = {};
		for (k in argv[0]) {
			options[k] = argv[0][k];
		}
		sprintf_args = argv.slice(1);
	} else {
		mod_assertplus.string(argv[0],
		    'first argument to VError, SError, or WError ' +
		    'constructor must be a string, object, or Error');
		options = {};
		sprintf_args = argv;
	}

	/*
	 * Now construct the error's message.
	 *
	 * extsprintf (which we invoke here with our caller's arguments in order
	 * to construct this Error's message) is strict in its interpretation of
	 * values to be processed by the "%s" specifier.  The value passed to
	 * extsprintf must actually be a string or something convertible to a
	 * String using .toString().  Passing other values (notably "null" and
	 * "undefined") is considered a programmer error.  The assumption is
	 * that if you actually want to print the string "null" or "undefined",
	 * then that's easy to do that when you're calling extsprintf; on the
	 * other hand, if you did NOT want that (i.e., there's actually a bug
	 * where the program assumes some variable is non-null and tries to
	 * print it, which might happen when constructing a packet or file in
	 * some specific format), then it's better to stop immediately than
	 * produce bogus output.
	 *
	 * However, sometimes the bug is only in the code calling VError, and a
	 * programmer might prefer to have the error message contain "null" or
	 * "undefined" rather than have the bug in the error path crash the
	 * program (making the first bug harder to identify).  For that reason,
	 * by default VError converts "null" or "undefined" arguments to their
	 * string representations and passes those to extsprintf.  Programmers
	 * desiring the strict behavior can use the SError class or pass the
	 * "strict" option to the VError constructor.
	 */
	mod_assertplus.object(options);
	if (!options.strict && !args.strict) {
		sprintf_args = sprintf_args.map(function (a) {
			return (a === null ? 'null' :
			    a === undefined ? 'undefined' : a);
		});
	}

	if (sprintf_args.length === 0) {
		shortmessage = '';
	} else {
		shortmessage = sprintf.apply(null, sprintf_args);
	}

	return ({
	    'options': options,
	    'shortmessage': shortmessage
	});
}

/*
 * See README.md for reference documentation.
 */
function VError()
{
	var args, obj, parsed, cause, ctor, message, k;

	args = Array.prototype.slice.call(arguments, 0);

	/*
	 * This is a regrettable pattern, but JavaScript's built-in Error class
	 * is defined to work this way, so we allow the constructor to be called
	 * without "new".
	 */
	if (!(this instanceof VError)) {
		obj = Object.create(VError.prototype);
		VError.apply(obj, arguments);
		return (obj);
	}

	/*
	 * For convenience and backwards compatibility, we support several
	 * different calling forms.  Normalize them here.
	 */
	parsed = parseConstructorArguments({
	    'argv': args,
	    'strict': false
	});

	/*
	 * If we've been given a name, apply it now.
	 */
	if (parsed.options.name) {
		mod_assertplus.string(parsed.options.name,
		    'error\'s "name" must be a string');
		this.name = parsed.options.name;
	}

	/*
	 * For debugging, we keep track of the original short message (attached
	 * this Error particularly) separately from the complete message (which
	 * includes the messages of our cause chain).
	 */
	this.jse_shortmsg = parsed.shortmessage;
	message = parsed.shortmessage;

	/*
	 * If we've been given a cause, record a reference to it and update our
	 * message appropriately.
	 */
	cause = parsed.options.cause;
	if (cause) {
		mod_assertplus.ok(mod_isError(cause), 'cause is not an Error');
		this.jse_cause = cause;

		if (!parsed.options.skipCauseMessage) {
			message += ': ' + cause.message;
		}
	}

	/*
	 * If we've been given an object with properties, shallow-copy that
	 * here.  We don't want to use a deep copy in case there are non-plain
	 * objects here, but we don't want to use the original object in case
	 * the caller modifies it later.
	 */
	this.jse_info = {};
	if (parsed.options.info) {
		for (k in parsed.options.info) {
			this.jse_info[k] = parsed.options.info[k];
		}
	}

	this.message = message;
	Error.call(this, message);

	if (Error.captureStackTrace) {
		ctor = parsed.options.constructorOpt || this.constructor;
		Error.captureStackTrace(this, ctor);
	}

	return (this);
}

mod_util.inherits(VError, Error);
VError.prototype.name = 'VError';

VError.prototype.toString = function ve_toString()
{
	var str = (this.hasOwnProperty('name') && this.name ||
		this.constructor.name || this.constructor.prototype.name);
	if (this.message)
		str += ': ' + this.message;

	return (str);
};

/*
 * This method is provided for compatibility.  New callers should use
 * VError.cause() instead.  That method also uses the saner `null` return value
 * when there is no cause.
 */
VError.prototype.cause = function ve_cause()
{
	var cause = VError.cause(this);
	return (cause === null ? undefined : cause);
};

/*
 * Static methods
 *
 * These class-level methods are provided so that callers can use them on
 * instances of Errors that are not VErrors.  New interfaces should be provided
 * only using static methods to eliminate the class of programming mistake where
 * people fail to check whether the Error object has the corresponding methods.
 */

VError.cause = function (err)
{
	mod_assertplus.ok(mod_isError(err), 'err must be an Error');
	return (mod_isError(err.jse_cause) ? err.jse_cause : null);
};

VError.info = function (err)
{
	var rv, cause, k;

	mod_assertplus.ok(mod_isError(err), 'err must be an Error');
	cause = VError.cause(err);
	if (cause !== null) {
		rv = VError.info(cause);
	} else {
		rv = {};
	}

	if (typeof (err.jse_info) == 'object' && err.jse_info !== null) {
		for (k in err.jse_info) {
			rv[k] = err.jse_info[k];
		}
	}

	return (rv);
};

VError.findCauseByName = function (err, name)
{
	var cause;

	mod_assertplus.ok(mod_isError(err), 'err must be an Error');
	mod_assertplus.string(name, 'name');
	mod_assertplus.ok(name.length > 0, 'name cannot be empty');

	for (cause = err; cause !== null; cause = VError.cause(cause)) {
		mod_assertplus.ok(mod_isError(cause));
		if (cause.name == name) {
			return (cause);
		}
	}

	return (null);
};

VError.hasCauseWithName = function (err, name)
{
	return (VError.findCauseByName(err, name) !== null);
};

VError.fullStack = function (err)
{
	mod_assertplus.ok(mod_isError(err), 'err must be an Error');

	var cause = VError.cause(err);

	if (cause) {
		return (err.stack + '\ncaused by: ' + VError.fullStack(cause));
	}

	return (err.stack);
};

VError.errorFromList = function (errors)
{
	mod_assertplus.arrayOfObject(errors, 'errors');

	if (errors.length === 0) {
		return (null);
	}

	errors.forEach(function (e) {
		mod_assertplus.ok(mod_isError(e));
	});

	if (errors.length == 1) {
		return (errors[0]);
	}

	return (new MultiError(errors));
};

VError.errorForEach = function (err, func)
{
	mod_assertplus.ok(mod_isError(err), 'err must be an Error');
	mod_assertplus.func(func, 'func');

	if (err instanceof MultiError) {
		err.errors().forEach(function iterError(e) { func(e); });
	} else {
		func(err);
	}
};


/*
 * SError is like VError, but stricter about types.  You cannot pass "null" or
 * "undefined" as string arguments to the formatter.
 */
function SError()
{
	var args, obj, parsed, options;

	args = Array.prototype.slice.call(arguments, 0);
	if (!(this instanceof SError)) {
		obj = Object.create(SError.prototype);
		SError.apply(obj, arguments);
		return (obj);
	}

	parsed = parseConstructorArguments({
	    'argv': args,
	    'strict': true
	});

	options = parsed.options;
	VError.call(this, options, '%s', parsed.shortmessage);

	return (this);
}

/*
 * We don't bother setting SError.prototype.name because once constructed,
 * SErrors are just like VErrors.
 */
mod_util.inherits(SError, VError);


/*
 * Represents a collection of errors for the purpose of consumers that generally
 * only deal with one error.  Callers can extract the individual errors
 * contained in this object, but may also just treat it as a normal single
 * error, in which case a summary message will be printed.
 */
function MultiError(errors)
{
	mod_assertplus.array(errors, 'list of errors');
	mod_assertplus.ok(errors.length > 0, 'must be at least one error');
	this.ase_errors = errors;

	VError.call(this, {
	    'cause': errors[0]
	}, 'first of %d error%s', errors.length, errors.length == 1 ? '' : 's');
}

mod_util.inherits(MultiError, VError);
MultiError.prototype.name = 'MultiError';

MultiError.prototype.errors = function me_errors()
{
	return (this.ase_errors.slice(0));
};


/*
 * See README.md for reference details.
 */
function WError()
{
	var args, obj, parsed, options;

	args = Array.prototype.slice.call(arguments, 0);
	if (!(this instanceof WError)) {
		obj = Object.create(WError.prototype);
		WError.apply(obj, args);
		return (obj);
	}

	parsed = parseConstructorArguments({
	    'argv': args,
	    'strict': false
	});

	options = parsed.options;
	options['skipCauseMessage'] = true;
	VError.call(this, options, '%s', parsed.shortmessage);

	return (this);
}

mod_util.inherits(WError, VError);
WError.prototype.name = 'WError';

WError.prototype.toString = function we_toString()
{
	var str = (this.hasOwnProperty('name') && this.name ||
		this.constructor.name || this.constructor.prototype.name);
	if (this.message)
		str += ': ' + this.message;
	if (this.jse_cause && this.jse_cause.message)
		str += '; caused by ' + this.jse_cause.toString();

	return (str);
};

/*
 * For purely historical reasons, WError's cause() function allows you to set
 * the cause.
 */
WError.prototype.cause = function we_cause(c)
{
	if (mod_isError(c))
		this.jse_cause = c;

	return (this.jse_cause);
};

},{"assert-plus":95,"core-util-is":113,"extsprintf":115,"util":190}],193:[function(require,module,exports){
arguments[4][192][0].apply(exports,arguments)
},{"assert-plus":95,"core-util-is":113,"dup":192,"extsprintf":115,"util":190}],194:[function(require,module,exports){
(function (global){(function (){
'use strict';

var forEach = require('for-each');
var availableTypedArrays = require('available-typed-arrays');
var callBound = require('call-bind/callBound');
var gOPD = require('gopd');

var $toString = callBound('Object.prototype.toString');
var hasToStringTag = require('has-tostringtag/shams')();

var g = typeof globalThis === 'undefined' ? global : globalThis;
var typedArrays = availableTypedArrays();

var $slice = callBound('String.prototype.slice');
var toStrTags = {};
var getPrototypeOf = Object.getPrototypeOf; // require('getprototypeof');
if (hasToStringTag && gOPD && getPrototypeOf) {
	forEach(typedArrays, function (typedArray) {
		if (typeof g[typedArray] === 'function') {
			var arr = new g[typedArray]();
			if (Symbol.toStringTag in arr) {
				var proto = getPrototypeOf(arr);
				var descriptor = gOPD(proto, Symbol.toStringTag);
				if (!descriptor) {
					var superProto = getPrototypeOf(proto);
					descriptor = gOPD(superProto, Symbol.toStringTag);
				}
				toStrTags[typedArray] = descriptor.get;
			}
		}
	});
}

var tryTypedArrays = function tryAllTypedArrays(value) {
	var foundName = false;
	forEach(toStrTags, function (getter, typedArray) {
		if (!foundName) {
			try {
				var name = getter.call(value);
				if (name === typedArray) {
					foundName = name;
				}
			} catch (e) {}
		}
	});
	return foundName;
};

var isTypedArray = require('is-typed-array');

module.exports = function whichTypedArray(value) {
	if (!isTypedArray(value)) { return false; }
	if (!hasToStringTag || !(Symbol.toStringTag in value)) { return $slice($toString(value), 8, -1); }
	return tryTypedArrays(value);
};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"available-typed-arrays":100,"call-bind/callBound":111,"for-each":116,"gopd":120,"has-tostringtag/shams":123,"is-typed-array":131}],195:[function(require,module,exports){
// Returns a wrapper function that returns a wrapped callback
// The wrapper function should do some stuff, and return a
// presumably different callback function.
// This makes sure that own properties are retained, so that
// decorations and such are not lost along the way.
module.exports = wrappy
function wrappy (fn, cb) {
  if (fn && cb) return wrappy(fn)(cb)

  if (typeof fn !== 'function')
    throw new TypeError('need wrapper function')

  Object.keys(fn).forEach(function (k) {
    wrapper[k] = fn[k]
  })

  return wrapper

  function wrapper() {
    var args = new Array(arguments.length)
    for (var i = 0; i < args.length; i++) {
      args[i] = arguments[i]
    }
    var ret = fn.apply(this, args)
    var cb = args[args.length-1]
    if (typeof ret === 'function' && ret !== cb) {
      Object.keys(cb).forEach(function (k) {
        ret[k] = cb[k]
      })
    }
    return ret
  }
}

},{}]},{},[1]);
