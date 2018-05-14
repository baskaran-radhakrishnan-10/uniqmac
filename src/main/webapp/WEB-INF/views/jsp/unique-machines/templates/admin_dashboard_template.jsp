<%@ page contentType="text/html;charset=UTF-8"%>
<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<c:url var="home" value="/" scope="request" />

<spring:url value="/resources/unique-machines/admin-lte/css/font-awesome.min.css" var="fontAwesomeCss" />
<spring:url	value="/resources/unique-machines/admin-lte/css/adminlte.min.css"	var="adminlteMinCss" />


<spring:url value="/resources/unique-machines/admin-lte/js/jquery.min.js"	var="jqueryJs" />
<spring:url value="/resources/unique-machines/admin-lte/js/bootstrap.bundle.min.js"	var="bootstrapJs" />
<spring:url value="/resources/unique-machines/admin-lte/js/adminlte.js"	var="adminlteJs" />
<spring:url value="/resources/unique-machines/admin-lte/js/Chart.min.js"	var="chartJs" />
<spring:url value="/resources/unique-machines/admin-lte/js/demo.js"	var="demoJs" />
<spring:url value="/resources/unique-machines/admin-lte/js/dashboard3.js"	var="dashboard3Js" />

<html lang="en" style="height: auto;">

	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<meta http-equiv="x-ua-compatible" content="ie=edge">
		
		<title><tiles:insertAttribute name="title" ignore="true" /></title>
		
		<link rel="stylesheet" href="${fontAwesomeCss}">
		<link rel="stylesheet" href="http://code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css">
		<link rel="stylesheet" href="${adminlteMinCss}">
		<link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700" rel="stylesheet">
		
		<style type="text/css">/* Chart.js */
			@-webkit-keyframes chartjs-render-animation{from{opacity:0.99}to{opacity:1}}
			@keyframes chartjs-render-animation{from{opacity:0.99}to{opacity:1}}
			.chartjs-render-monitor{-webkit-animation:chartjs-render-animation 0.001s;animation:chartjs-render-animation 0.001s;}
		</style>
		
	</head>
	
	<body class="sidebar-mini sidebar-open" style="height: auto;">
	
		<div class="wrapper">
			
			<!-- Navbar -->
			<tiles:insertAttribute name="admin_dashboard_header" />
			<!-- /.navbar -->
			
			<!-- Main Sidebar Container -->
			<tiles:insertAttribute name="admin_dashboard_sidebar_left" />
			
			<!-- Content Wrapper. Contains page content -->
			<tiles:insertAttribute name="page_content" />
			<!-- /.content-wrapper -->
			
			<!-- Control Sidebar -->
			<tiles:insertAttribute name="admin_dashboard_sidebar_right" />
			<!-- /.control-sidebar -->
			
			<!-- Main Footer -->
		  	<tiles:insertAttribute name="admin_dashboard_footer" />
			<div id="sidebar-overlay"></div>
			
		</div>
		<!-- ./wrapper -->
	
		<!-- REQUIRED SCRIPTS -->
		<script src="${jqueryJs}"></script>
		<script src="${bootstrapJs}"></script>
		<script src="${adminlteJs}"></script>
		<script src="${chartJs}"></script>
		<script src="${demoJs}"></script>
		<script src="${dashboard3Js}"></script>
	
	</body>
	
</html>