<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<c:url var="home" value="/" scope="request" />

<!-- start: Css -->
<spring:url value="/resources/miminiumTheme/css/bootstrap.min.css" var="boostrapCss" />

<!-- plugins -->
<spring:url	value="/resources/miminiumTheme/css/plugins/font-awesome.min.css"	var="FontAwesomeCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/simple-line-icons.css"	var="SimpleLineIconCss" />
<spring:url value="/resources/miminiumTheme/css/plugins/animate.min.css" var="AnimateMinCss" />
<spring:url	value="/resources/miminiumTheme/css/plugins/icheck/skins/flat/aero.css"	var="aeroCss" />
<spring:url value="/resources/miminiumTheme/css/style.css" var="StyleCss" />

<!-- end: Css -->

<spring:url value="/resources/miminiumTheme/img/equiniti.ico" var="equIcon" />
<spring:url value="/resources/miminiumTheme/img/logomi.png" var="LogoMiImg" />
<spring:url value="/resources/miminiumTheme/img/equiniti-logo.png" var="equinitiLogo" />


<!--  Javascript -->
<spring:url value="/resources/miminiumTheme/js/jquery.min.js" var="jqueryJs" />
<spring:url value="/resources/miminiumTheme/js/jquery.ui.min.js"	var="jqueryUIJs" />
<spring:url value="/resources/miminiumTheme/js/bootstrap.min.js"	var="bootstrapJs" />
<!-- plugins -->
<spring:url value="/resources/miminiumTheme/js/plugins/moment.min.js"	var="momentJs" />
<spring:url	value="/resources/miminiumTheme/js/plugins/jquery.nicescroll.js"	var="niceScrollJs" />
<spring:url value="/resources/miminiumTheme/js/plugins/icheck.min.js"	var="iCheckJs" />
<!-- custom -->
<spring:url value="/resources/originalTheme/js/common/common.js"	var="commonJs" />
<spring:url value="/resources/miminiumTheme/js/main.js" var="mainJs" />
<spring:url value="/resources/originalTheme/js/custom/custom_loginpage.js" var="loginPageJS" />
<%-- <spring:url value="/resources/core/js/custom/custom.js" var="customJS" /> --%>

<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
<title>Login Page</title>
<!-- Custom Theme files -->

<link href="${equIcon}" rel="icon" type="image/x-icon">
<link href="${boostrapCss}" rel="stylesheet" type="text/css">
<link href="${FontAwesomeCss}" rel="stylesheet">
<link href="${SimpleLineIconCss}" rel="stylesheet" type="text/css">
<link href="${AnimateMinCss}" rel="stylesheet" type="text/css">
<link href="${StyleCss}" rel="stylesheet" type="text/css">
<%-- <link href="${loginCss}" rel="stylesheet" type="text/css" media="all"> --%>
<link href="${LogoMiImg}" rel="stylesheet" type="image/x-icon">


<!-- Custom Theme files -->
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">

<!--script-->
<!-- start: Javascript -->
<script src="${jqueryJs}"></script>
<script src="${jqueryUIJs}"></script>
<script src="${bootstrapJs}"></script>

<!-- plugins -->
<script src="${momentJs}"></script>
<script src="${niceScrollJs}"></script>
<script src="${iCheckJs}"></script>
<!-- custom -->
<script src="${commonJs}"></script>
<script src="${mainJs}"></script>
<script src="${loginPageJS}"></script>

<!--script-->

</head>
<!-- style=" background-color: #54a3ab !important;" -->
<body id="mimin" class="dashboard form-signin-wrapper" style="background: rgba( 255, 255, 255, .8 ) url('./resources/miminiumTheme/img/QA.jpg') no-repeat center center fixed; -webkit-background-size: cover; -moz-background-size: cover; -o-background-size: cover; background-size: cover; !important;">
 <!-- 	style="background: rgba(33, 150, 243, 0.1) !important;"> -->
	<div class="container">

		<form:form modelAttribute="loginModelAttribute" id="loginForm" action="doLogin" method="post" class="form-signin">
			<div class="panel periodic-login">
				<!-- 				<span class="atomic-number">28</span> -->
				<div class="panel-body text-center">
					<img src="${equinitiLogo}" alt="Equiniti Logo">
				<!-- 	<h1 class="atomic-symbol" style="font-size: 8em !important;">Logo</h1> -->
					<p class="atomic-mass"style="margin-top: 1em;">HELP DESK APP</p>
					<!-- <p class="element-name">Web App</p> -->
					<div class="form-group form-animate-text" style="margin-top: 40px !important;">
						<form:input path="userId" id="userIdField" type="text"	class="form-text" required="true" autocomplete="off" />
						<form:errors path="userId" />
						<span class="bar"></span> <label>User ID</label>
					</div>
					<div class="form-group form-animate-text" style="margin-top: 40px !important;" >
						<form:input path="password" id="passwordIdField" type="password" class="form-text" required="true" autocomplete="off" />
						<form:errors path="password" />
						<span class="bar"></span> <label style="top: -25px;">Password</label>
					</div>
					<label class="pull-left" id="errorMessageUl"> <span style="color: #F84E4E;">${error}</span>
					</label> <input type="submit" id="submitField" value="Log In" class="btn col-md-12" />
				</div>

				<!-- <div class="text-center" style="padding: 6px;">
					<a href="#" style="color: #a5a5a5 !important;">Forgot Password ?</a> 
				</div> -->

			</div>
		</form:form>

	</div>

	<script src="${loginPageJS}" type="text/javascript"></script>
	<script type="text/javascript">
		$(document).ready(function() {
			$('input').iCheck({
				checkboxClass : 'icheckbox_flat-aero',
				radioClass : 'iradio_flat-aero'
			});
		});
	</script>
	<!-- end: Javascript -->
</body>
</html>