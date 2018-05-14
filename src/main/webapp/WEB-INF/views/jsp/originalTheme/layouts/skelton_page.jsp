<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<c:url var="home" value="/" scope="request" />

<!-- start: Css -->
<spring:url value="/resources/originalTheme/css/bootstrap.min.css" var="boostrapCss" />
<spring:url value="/resources/originalTheme/css/style.css"	var="StyleCss" />
<spring:url	value="/resources/originalTheme/css/font-awesome.css"	var="FontAwesomeCss" />
<spring:url	value="/resources/originalTheme/css/icon-font.min.css"	var="IconFontCss" />
<spring:url value="/resources/originalTheme/css/animate.css"	var="AnimateCss" />
<!-- end: Css -->

<!--  Start:Javascript -->
<spring:url value="/resources/originalTheme/js/plugin/jquery-1.10.2.min.js"	var="jqueryJs" />
<spring:url value="/resources/originalTheme/js/plugin/bootstrap.min.js"	var="bootstrapJs" />
<spring:url	value="/resources/originalTheme/js/plugin/jquery.nicescroll.js"	var="niceScrollJs" />
<spring:url value="/resources/originalTheme/js/plugin/scripts.js"	var="ScriptJS" />
<spring:url value="/resources/originalTheme/js/plugin/wow.min.js"	var="WOWMinJS" />
<spring:url value="/resources/originalTheme/js/plugin/underscore.js"	var="underscoreJs" />
<spring:url value="/resources/originalTheme/js/plugin/moment.js"	var="momentJs" />
<spring:url value="/resources/originalTheme/js/common/common.js"	var="commonJs" />

<!--  End:Javascript -->

<!DOCTYPE HTML>
<html>
<head>

<tiles:insertAttribute name="title" />

<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="keywords" content="Intelligent Help Desk Application" />

<script type="application/x-javascript"> 
	addEventListener("load", function() { setTimeout(hideURLbar, 0); }, false); function hideURLbar(){ window.scrollTo(0,1); } 
</script>

 <!-- Bootstrap Core CSS -->
<link href="${boostrapCss}" rel="stylesheet" type="text/css" />
<!-- Custom CSS -->
<link href="${StyleCss}" rel='stylesheet' type='text/css' />
<!-- Graph CSS -->
<link href="${FontAwesomeCss}" rel="stylesheet"> 
<!-- jQuery -->
<!-- lined-icons -->
<link rel="stylesheet" href="${IconFontCss}" type='text/css' />
<!-- //lined-icons -->

<!--animate-->
<link href="${AnimateCss}" rel="stylesheet" type="text/css" media="all">

<script src="${WOWMinJS}"></script>
<script>
		 new WOW().init();
	</script>
<!--//end-animate-->

 <!-- Meters graphs -->
<script src="${jqueryJs}"></script>
<!-- Placed js at the end of the document so the pages load faster -->
<script src="${underscoreJs}"></script>
<script src="${momentJs}"></script>
<script src="${commonJs}"></script>

</head> 
   
 <body class="sticky-header left-side-collapsed" >
 
 	<input id="loggedInUserName" name="loggedInUserName" type="hidden" value="<%=session.getAttribute("USER_NAME")%>">
 
    <section>
    	<!-- left side start-->
			<tiles:insertAttribute name="left_menu" />
		<!-- left side end-->
    
		<!-- main content start-->
		<div class="main-content">
			
		<!-- header-starts -->
			<tiles:insertAttribute name="header_menu" />
		<!-- //header-ends -->
			<div id="page-wrapper">
				<div class="graphs">
					<tiles:insertAttribute name="body_content" />
				</div>
			<!--body wrapper start-->
			</div>
			 <!--body wrapper end-->
		</div>
      <!-- main content end-->
   </section>
  
<script src="${niceScrollJs}"></script>

<script src="${ScriptJS}"></script>

<!-- Bootstrap Core JavaScript -->
<script src="${bootstrapJs}"></script>

</body>
</html>