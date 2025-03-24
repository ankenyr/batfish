package org.batfish.representation.juniper;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class IpsecPolicy implements Serializable {

  private final String _name;

  private final List<String> _proposals;

  public IpsecPolicy(String name) {
    _name = name;
    _proposals = new ArrayList<>();
  }

  public String getName() {
    return _name;
  }

  public List<String> getProposals() {
    return _proposals;
  }

}
