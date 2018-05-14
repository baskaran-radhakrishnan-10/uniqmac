<%@ page contentType="text/html;charset=UTF-8"%>
<%@taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<spring:url	value="/resources/miminiumTheme/css/under_construction_style.css"	var="StyleCss" />
<spring:url value="/resources/miminiumTheme/img/banner1.png" var="bannerImg" />
<spring:url	value="/resources/miminiumTheme/js/custom/custom_under_construction.js" var="underConstructionJS" />
	
<link href="${bannerImg}" rel="icon" type="image/x-icon">
<link href="${StyleCss}" rel="stylesheet" type="text/css">
<script src="${underConstructionJS}"></script>

<div class="wrap">
	<div class="content">
		<div class="banner">
			<img src="${bannerImg}" title="profesor">
			<h2>Sorry! This page is Currently</h2>
			<h3>Under Construction</h3>
			<h4 id="page_path_id" style="margin-bottom: 0px;margin-top: 22px;color: rgba(134, 129, 129, 0.72);"></h4>
			<input type="hidden" id="pathValue" value="${sessionScope.currentActionPath}" />
		</div>
		<div class="clear"></div>
	</div>
</div>