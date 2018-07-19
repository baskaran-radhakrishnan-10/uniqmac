package com.jamcracker.common.security.tags.dataobject;

import java.io.Serializable;

/**
 * This class holds user web information
 * such as server address, port and other
 * web server related information. 
 * This information is useful in the middle
 * tier where we don't have access to
 * web server and request information
 * 
 * @author Sudhakar KV
 * @version 1.0
 * @see HttpServletRequest 
 */
public class WebInfo implements Serializable{
	 
	/**
	 * 
	 */
	private static final long serialVersionUID = -4721894689778540348L;
	public final String SCHEME_HTTP = "http";
	public final String SCHEME_HTTPS = "https";

	public final int DEFAULT_PORT = 7001;
	public final String DEFAULT_SCHEME = SCHEME_HTTP;
    
	private String contextPath;
	private String localAddr;
	private int localPort;
	private String method;
	private String pathInfo;
	private String pathTranslated;
	private String protocol;
	private String queryString;
	private String remoteAddr;
	private String remoteHost;
	private int remotePort;
	private String remoteUser;
	private String requestURI;
	private String requestURL;
	private String scheme = DEFAULT_SCHEME;
	private String serverName;
	private int serverPort = DEFAULT_PORT;
	private String servletPath;
	private String userAgent;
	
	public String getUserAgent() {
		return userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public String getContextPath() {
		return contextPath;
	}
	
	public void setContextPath(String contextPath) {
		this.contextPath = contextPath;
	}
	
	public String getLocalAddr() {
		return localAddr;
	}
	
	public void setLocalAddr(String localAddr) {
		this.localAddr = localAddr;
	}
	
	public int getLocalPort() {
		return localPort;
	}
	
	public void setLocalPort(int localPort) {
		this.localPort = localPort;
	}
	
	public String getMethod() {
		return method;
	}
	
	public void setMethod(String method) {
		this.method = method;
	}
	
	public String getPathInfo() {
		return pathInfo;
	}
	
	public void setPathInfo(String pathInfo) {
		this.pathInfo = pathInfo;
	}
	
	public String getPathTranslated() {
		return pathTranslated;
	}
	
	public void setPathTranslated(String pathTranslated) {
		this.pathTranslated = pathTranslated;
	}
	
	public String getProtocol() {
		return protocol;
	}
	
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
	
	public String getQueryString() {
		return queryString;
	}
	
	public void setQueryString(String queryString) {
		this.queryString = queryString;
	}
	
	public String getRemoteAddr() {
		return remoteAddr;
	}
	
	public void setRemoteAddr(String remoteAddr) {
		this.remoteAddr = remoteAddr;
	}
	
	public String getRemoteHost() {
		return remoteHost;
	}
	
	public void setRemoteHost(String remoteHost) {
		this.remoteHost = remoteHost;
	}
	
	public int getRemotePort() {
		return remotePort;
	}
	
	public void setRemotePort(int remotePort) {
		this.remotePort = remotePort;
	}
	
	public String getRemoteUser() {
		return remoteUser;
	}
	public void setRemoteUser(String remoteUser) {
		this.remoteUser = remoteUser;
	}
	
	public String getRequestURI() {
		return requestURI;
	}
	
	public void setRequestURI(String requestURI) {
		this.requestURI = requestURI;
	}
	
	public String getRequestURL() {
		return requestURL;
	}
	
	public void setRequestURL(String requestURL) {
		this.requestURL = requestURL;
	}
	
	public String getScheme() {
		return scheme;
	}
	
	public void setScheme(String scheme) {
		this.scheme = scheme;
	}
	
	public String getServerName() {
		return serverName;
	}
	
	public void setServerName(String serverName) {
		this.serverName = serverName;
	}
	
	public int getServerPort() {
		return serverPort;
	}
	
	public void setServerPort(int serverPort) {
		this.serverPort = serverPort;
	}
	
	public String getServletPath() {
		return servletPath;
	}
	
	public void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}
	
	public String toString() {
		
		StringBuilder sb = new StringBuilder();
		sb.append("WebInfo [ ");
		sb.append(" contextPath = ").append(contextPath).append(",");
		sb.append(" method = ").append(method).append(",");
		sb.append(" pathInfo = ").append(pathInfo).append(",");
		sb.append(" pathTranslated = ").append(pathTranslated).append(",");
		sb.append(" protocol = ").append(protocol).append(",");
		sb.append(" queryString = ").append(queryString).append(",");
		sb.append(" remoteAddr = ").append(remoteAddr).append(",");
		sb.append(" remoteHost = ").append(remoteHost).append(",");
		sb.append(" remoteUser = ").append(remoteUser).append(",");
		sb.append(" requestURI = ").append(requestURI).append(",");
		sb.append(" requestURL = ").append(requestURL).append(",");
		sb.append(" scheme = ").append(scheme).append(",");
		sb.append(" serverName = ").append(serverName).append(",");		
		sb.append(" serverPort = ").append(serverPort).append(",");	
		sb.append(" servletPath = ").append(servletPath).append(",");	
		sb.append(" localAddr = ").append(localAddr).append(",");		
		sb.append(" userAgent = ").append(userAgent);
		sb.append(" ]");
		return sb.toString();
	}
	
}
