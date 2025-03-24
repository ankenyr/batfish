package org.batfish.datamodel;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Objects;
import org.batfish.common.util.ComparableStructure;

/** Represents the IKE proposal used for IKE phase 1 negotiation */
public class IkePhase1Proposal extends ComparableStructure<String> {

  private static final String PROP_AUTHENTICATION_METHOD = "authenticationMethod";
  private static final String PROP_ENCRYPTION_ALGORITHM = "encryptionAlgorithm";
  private static final String PROP_DIFFIE_HELLMAN_GROUP = "diffieHellmanGroup";
  private static final String PROP_HASHING_ALGORITHM = "hashingAlgorithm";
  private static final String PROP_LIFETIME_SECONDS = "lifetimeSeconds";

  private IkeAuthenticationMethod _authenticationMethod;

  private DiffieHellmanGroup _diffieHellmanGroup;

  private List<EncryptionAlgorithm> _encryptionAlgorithm;

  private List<IkeHashingAlgorithm> _hashingAlgorithm;

  private Integer _lifetimeSeconds;

  @JsonCreator
  public IkePhase1Proposal(@JsonProperty(PROP_NAME) String name) {
    super(name);
  }

  /** Authentication method to use for this IKE phase 1 proposal. */
  @JsonProperty(PROP_AUTHENTICATION_METHOD)
  public IkeAuthenticationMethod getAuthenticationMethod() {
    return _authenticationMethod;
  }

  /** Diffie-Hellman group to use for key exchange for this IKE phase 1 proposal. */
  @JsonProperty(PROP_DIFFIE_HELLMAN_GROUP)
  public DiffieHellmanGroup getDiffieHellmanGroup() {
    return _diffieHellmanGroup;
  }

  /** Encryption algorithm to use for this IKE phase 1 proposal. */
  @JsonProperty(PROP_ENCRYPTION_ALGORITHM)
  public List<EncryptionAlgorithm> getEncryptionAlgorithms() {
    return _encryptionAlgorithm;
  }

  @JsonProperty(PROP_ENCRYPTION_ALGORITHM)
  public void setEncryptionAlgorithms(List<EncryptionAlgorithm> encryptionAlgorithm) {
    _encryptionAlgorithm = encryptionAlgorithm;
  }

  /** Lifetime in seconds to use for this IKE phase 1 proposal. */
  @JsonProperty(PROP_LIFETIME_SECONDS)
  public Integer getLifetimeSeconds() {
    return _lifetimeSeconds;
  }

  @JsonProperty(PROP_AUTHENTICATION_METHOD)
  public void setAuthenticationMethod(IkeAuthenticationMethod authenticationMethod) {
    _authenticationMethod = authenticationMethod;
  }

  @JsonProperty(PROP_DIFFIE_HELLMAN_GROUP)
  public void setDiffieHellmanGroup(DiffieHellmanGroup diffieHellmanGroup) {
    _diffieHellmanGroup = diffieHellmanGroup;
  }

  /** Hashing algorithm to be used for this IKE phase 1 proposal. */
  @JsonProperty(PROP_HASHING_ALGORITHM)
  public List<IkeHashingAlgorithm> getHashingAlgorithms() {
    return _hashingAlgorithm;
  }

  @JsonProperty(PROP_HASHING_ALGORITHM)
  public void setHashingAlgorithms(List<IkeHashingAlgorithm> hashingAlgorithm) {
    _hashingAlgorithm = hashingAlgorithm;
  }

  @JsonProperty(PROP_LIFETIME_SECONDS)
  public void setLifetimeSeconds(Integer lifetimeSeconds) {
    _lifetimeSeconds = lifetimeSeconds;
  }

  public boolean isCompatibleWith(IkePhase1Proposal ikePhase1Proposal) {
    return Objects.equals(_authenticationMethod, ikePhase1Proposal._authenticationMethod)
        && Objects.equals(_diffieHellmanGroup, ikePhase1Proposal._diffieHellmanGroup)
        && Objects.equals(_encryptionAlgorithm, ikePhase1Proposal._encryptionAlgorithm)
        && Objects.equals(_hashingAlgorithm, ikePhase1Proposal._hashingAlgorithm);
  }
}
