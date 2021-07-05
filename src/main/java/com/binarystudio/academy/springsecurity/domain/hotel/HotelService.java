package com.binarystudio.academy.springsecurity.domain.hotel;

import com.binarystudio.academy.springsecurity.domain.hotel.model.Hotel;
import com.binarystudio.academy.springsecurity.domain.user.UserService;
import com.binarystudio.academy.springsecurity.domain.user.model.User;
import com.binarystudio.academy.springsecurity.domain.user.model.UserRole;
import com.binarystudio.academy.springsecurity.security.auth.AuthoritiesException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@Service
public class HotelService {
	private final HotelRepository hotelRepository;
	@Autowired
	UserService userService;

	public HotelService(HotelRepository hotelRepository) {
		this.hotelRepository = hotelRepository;
	}

	public void delete(UUID hotelId) {
		if (userHasPermission(hotelId)) {
			boolean wasDeleted = hotelRepository.delete(hotelId);
			if (!wasDeleted) {
				throw new NoSuchElementException();
			}
		}
	}

	public List<Hotel> getAll() {
		return hotelRepository.getHotels();
	}


	public Hotel update(Hotel hotel) {
		if (userHasPermission(hotel.getId())) {
			getById(hotel.getId());
			return hotelRepository.save(hotel);
		}
		return null;
	}

	public Hotel create(Hotel hotel) {
		return hotelRepository.save(hotel);
	}

	public Hotel getById(UUID hotelId) {
		return hotelRepository.getById(hotelId).orElseThrow();
	}

	private boolean userHasPermission(UUID hotelId){
		User user = userService.getCurrentUser();
		if (!user.getAuthorities().contains(UserRole.ADMIN) && !hotelRepository.userIsHotelOwner(user, hotelId)){
			throw new AuthoritiesException();
		}
		return true;
	}
}
