package com.spring.controller;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MainController {
	
	private HttpServletRequest request;
	
	@RequestMapping(value = "/login")
	public String showLoginPage(){
		return "loginpage";
	}
	
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String rootUrl(HttpServletRequest request,HttpServletResponse response){
		return "redirect:/home";
	}
	
	@RequestMapping(value = "/home", method = RequestMethod.GET)
	public String homePage(HttpServletRequest request,HttpServletResponse response){
		return "home";
	}
	
	@RequestMapping(value = "/dashboard", method = RequestMethod.GET)
	public String adminHomePage(HttpServletRequest request,HttpServletResponse response){
		return "dashboard";
	}
	
	@RequestMapping(value = "/machine", method = RequestMethod.GET)
	public String singleProductPage(HttpServletRequest request,HttpServletResponse response){
		return "machine";
	}
	
	@RequestMapping(value = "/signin", method = RequestMethod.GET)
	public String signinPage(HttpServletRequest request,HttpServletResponse response){
		return "signin";
	}
	
	@RequestMapping(value = "/getChatHistory", method = RequestMethod.POST)
	@ResponseBody
	public Map<String,Object> getChatHistory(@RequestBody Map<String,Object> inputData){
		//LOG.debug("START getChatHistory() Method!!!");
		Map<String,Object> returnObj=new HashMap<>();
		try {
			System.out.println("INPUT :"+inputData);
			//returnObj = chatHistoryController.getChatHistory(inputData);	
		} catch (Exception e) {
			//throw new UIException(e.getFaultCode(), e);
		}
		///LOG.debug("END getChatHistory() Method!!!");
		return returnObj;
	}

}
