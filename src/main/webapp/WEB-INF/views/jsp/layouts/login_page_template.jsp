<%@ page contentType="text/html;charset=UTF-8"%>
<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<spring:url value="/resources/miminiumTheme/img/equiniti.ico" var="equIcon" />
<!DOCTYPE html>
<html lang="en">
<head>
		<title><tiles:insertAttribute name="title" ignore="true" /></title>
		<%-- <link href="${equIcon}" rel="shortcut icon" type="image/x-icon"> --%>
</head>
<body> 
		<tiles:insertAttribute name="body" />
</body>
</html>