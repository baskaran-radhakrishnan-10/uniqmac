<%@ page contentType="text/html;charset=UTF-8"%>
<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<c:url var="home" value="/" scope="request" />

<!-- start: Css -->
<spring:url value="/resources/miminiumTheme/css/bootstrap.min.css" var="boostrapCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/font-awesome.min.css"	var="FontAwesomeCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/simple-line-icons.css"	var="SimpleLineIconCss" />
<spring:url value="/resources/miminiumTheme/css/plugins/animate.min.css"	var="AnimateMinCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/fullcalendar.min.css"	var="FullCalendarMinCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/bootstrap-material-datetimepicker.css"	var="DateTimeCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/nouislider.min.css"	var="nouSLiderCss" />
<spring:url value="/resources/miminiumTheme/css/plugins/select2.min.css"	var="select2Css" />
<spring:url	value="/resources/miminiumTheme/css/plugins/ionrangeslider/ion.rangeSlider.css"	var="ionRangerCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/ionrangeslider/ion.rangeSlider.skinFlat.css"	var="ionRangerSkinCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/datatables.bootstrap.min.css"	var="dataTableCss" />
<spring:url value="/resources/miminiumTheme/css/style.css"	var="StyleCss" />
<spring:url value="/resources/miminiumTheme/css/validation.css"	var="validationCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/notify/notifIt.css"	var="notifyCss" />
<!-- end: Css -->

<spring:url value="/resources/miminiumTheme/img/logomi.png"	var="LogoMiImg" />
<spring:url value="/resources/miminiumTheme/img/ajax-loader.gif" var="ajaxLoaderImage" />
<spring:url value="/resources/miminiumTheme/img/equiniti.ico" var="equIcon" />
<!--  Javascript -->
<spring:url value="/resources/miminiumTheme/js/jquery.min.js"	var="jqueryJs" />
<spring:url value="/resources/miminiumTheme/js/jquery.ui.min.js"	var="jqueryUIJs" />
<spring:url value="/resources/miminiumTheme/js/bootstrap.min.js"	var="bootstrapJs" />
<spring:url value="/resources/miminiumTheme/js/underscore.js"	var="underscoreJs" />
<!-- plugins -->
<spring:url value="/resources/miminiumTheme/js/plugins/moment.min.js"	var="momentJs" />
<spring:url	value="/resources/miminiumTheme/js/plugins/jquery.nicescroll.js"	var="niceScrollJs" />


<spring:url	value="/resources/miminiumTheme/js/plugins/ion.rangeSlider.min.js"	var="rangeSliderJS" />
<spring:url	value="/resources/miminiumTheme/js/plugins/bootstrap-material-datetimepicker.js"	var="dateTimePickerJS" />
<spring:url	value="/resources/miminiumTheme/js/plugins/jquery.mask.min.js"	var="maskJS" />
<spring:url	value="/resources/miminiumTheme/js/plugins/nouislider.min.js"	var="nouSliderJS" />
<spring:url	value="/resources/miminiumTheme/js/plugins/jquery.validate.min.js"	var="validateJs" />
<spring:url	value="/resources/miminiumTheme/js/plugins/jquery.datatables.min.js"	var="dataTableJs" />
<spring:url	value="/resources/miminiumTheme/js/plugins/datatables.bootstrap.min.js"	var="dataTableBtJs" />

<!-- custom -->
<spring:url value="/resources/miminiumTheme/js/main.js" var="mainJs" />
<spring:url	value="/resources/miminiumTheme/js/plugins/select2.full.min.js"	var="select2js" />
<%-- <spring:url value="/resources/miminiumTheme/js/custom/general_custom.js"	var="generalCustomJS" /> --%>
<spring:url	value="/resources/miminiumTheme/js/common/common.js" var="commonJS" />
<spring:url	value="/resources/miminiumTheme/js/plugins/notify/notifIt.js"	var="notifyJs" />
<spring:url	value="/resources/miminiumTheme/js/custom/custom_left_menu.js" var="leftMenuJS" />
<%-- <spring:url	value="/resources/miminiumTheme/js/service-worker/service-worker-impl.js" var="serviceWorkerImplJs" /> --%>

<!DOCTYPE html>
<html lang="en" class="no-js">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
<meta name="author" content="" />
<meta name="company" content="" />
<meta name="abstract" content="" />

<title><tiles:insertAttribute name="title" ignore="true" /></title>

<link href="${boostrapCss}" rel="stylesheet" type="text/css">
<link href="${FontAwesomeCss}" rel="stylesheet">
<link href="${SimpleLineIconCss}" rel="stylesheet" type="text/css">
<link href="${AnimateMinCss}" rel="stylesheet" type="text/css">
<link href="${FullCalendarMinCss}" rel="stylesheet" type="text/css">
<link href="${nouSLiderCss}" rel="stylesheet" type="text/css">
<link href="${select2Css}" rel="stylesheet" type="text/css">
<link href="${ionRangerCss}" rel="stylesheet" type="text/css">
<link href="${ionRangerSkinCss}" rel="stylesheet" type="text/css">
<link href="${dataTableCss}" rel="stylesheet" type="text/css">
<link href="${DateTimeCss}" rel="stylesheet" type="text/css">
<link href="${validationCss}" rel="stylesheet" type="text/css">
<link href="${StyleCss}" rel="stylesheet" type="text/css">
<link href="${LogoMiImg}" rel="stylesheet" type="image/x-icon">
<link href="${notifyCss}" rel="stylesheet" type="text/css">
<link href="${equIcon}" rel="shortcut icon"  type="image/x-icon">
<!-- <style>
/* Start by setting display:none to make this hidden.
   Then we position it in relation to the viewport window
   with position:fixed. Width, height, top and left speak
   speak for themselves. Background we set to 80% white with
   our animation centered, and no-repeating */
.ajaxloader {
    display:    none;
    position:   fixed;
    z-index:    1000;
    top:        0;
    left:       0;
    height:     100%;
    width:      100%;
    background: rgba( 255, 255, 255, .8 ) 
                url('./resources/miminiumTheme/img/ajax-loader.gif') 
                50% 50% 
                no-repeat;
}
/* When the body has the loading class, we turn
   the scrollbar off with overflow:hidden */
body.loading {
    overflow: hidden;   
}
/* Anytime the body has the loading class, our
   modal element will be visible */
body.loading .ajaxloader {
    display: block;
}
</style> -->

<!-- start: Javascript -->
<script src="${jqueryJs}"></script>
<script src="${jqueryUIJs}"></script>
<script src="${underscoreJs}"></script>
<script src="${momentJs}"></script>
<!-- plugins -->
<script src="${dataTableJs}"></script>
<script src="${dataTableBtJs}"></script>
<script src="${rangeSliderJS}"></script>
<script src="${dateTimePickerJS}"></script>
<script src="${nouSliderJS}"></script>
<script src="${validateJs}"></script>
<script src="${maskJS}"></script>
<script src="${select2js}"></script>
<script src="${generalCustomJS}"></script>
<script src="${commonJS}"></script>
<script src="${notifyJs}"></script>
<script src="${leftMenuJS}"></script>
</head>

<body id="mimin" class="dashboard">

	<input id="loggedInUser" name="loggedInUser" type="hidden" value="<%=session.getAttribute("USER_OBJ")%>">
	<input id="loggedInUserId" name="loggedInUserId" type="hidden" value="<%=session.getAttribute("USER_ID")%>">
	<input id="loggedInRoleId" name="loggedInUserRoleName" type="hidden" value="<%=session.getAttribute("roleId")%>">
	<input id="loggedInUserName" name="loggedInUserName" type="hidden" value="<%=session.getAttribute("USER_NAME")%>">
	<input id="isFirstTimeLoggedIn" name="isFirstTimeLoggedIn" type="hidden" value="<%=session.getAttribute("FIRST_LOGIN")%>">
	
	<!-- start: Header -->
	<tiles:insertAttribute name="header_menu" />
	<!-- end: Header -->
	<div class="container-fluid mimin-wrapper">
		<!-- start:Left Menu -->
		<tiles:insertAttribute name="left_menu" />
		<!-- end: Left Menu -->
		<!-- start: content -->
		<div id="content">
			<tiles:insertAttribute name="body_content" />
		</div>
		<!-- end: content -->
		<!-- start: right menu -->
		<div id="right-menu">
			<!-- -ADD Right MEnu Tile -->
		</div>
		<!-- end: right menu -->
	</div>
	<!-- start: Mobile -->
	<!--  Left Menu - Mobile Tile -->
	<%-- <tiles:insertAttribute name="mobileLeftMenu" /> --%>
	<!-- end: Mobile -->

	<script src="${bootstrapJs}"></script>

	<!-- plugins -->
	<script src="${momentJs}"></script>
	<script src="${niceScrollJs}"></script>
	<%-- 	<script src="${chartJs}"></script> --%>
	<script src="${mainJs}"></script>
	<%-- <script src="${serviceWorkerImplJs}"></script> --%>
	
</body>

</html>