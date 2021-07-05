package com.binarystudio.academy.springsecurity.security.jwt.repository;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public abstract class TokenRepository {
  //Map<UUID tokenId, String userName>
  private final Map<UUID, String> tokens = new HashMap<>();

  public void add(UUID tokenId, String userName){
    tokens.put(tokenId, userName);
  }

  public boolean contains(UUID tokenId, String userName){
    return tokens.containsKey(tokenId) && tokens.get(tokenId).equals(userName);
  }

  public void delete(UUID tokenId){
    tokens.remove(tokenId);
  }
}
