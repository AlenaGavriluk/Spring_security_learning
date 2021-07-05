package com.binarystudio.academy.springsecurity.security.jwt;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenRepository {
  //Map<UUID tokenId, String userName>
  private Map<UUID, String> tokens = new HashMap<>();

  public void add(UUID tokenId, String userName){
    tokens.put(tokenId, userName);
  }

  public boolean contains(UUID tokenId, String userName){
    return tokens.containsKey(tokenId) && tokens.get(tokenId).equals(userName);
  }
}
