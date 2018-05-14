<!-- http://tr.ozgencmachine.com/ 
http://eng.penmak.com/pvc-makinasi/185/my2s-full-automatic-double-head-cutting-machine-new-model.html -->

<%@ page contentType="text/html;charset=UTF-8"%>
<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<c:url var="home" value="/" scope="request" />

<!-- start: Css -->
<spring:url value="/resources/unique-machines/css/bootstrap.css" var="boostrapCss" />
<spring:url	value="/resources/unique-machines/css/flexslider.css"	var="flexSliderCss" />
<spring:url	value="/resources/unique-machines/css/style.css"	var="styleCss" />
<spring:url value="/resources/unique-machines/css/fontawesome-all.css"	var="fontAwesomeCss" />
<spring:url value="/resources/unique-machines/css/simpleLightbox.css"	var="simpleLightboxCss" />
<spring:url value="/resources/unique-machines/css/aos.css"	var="aosCss" />
<spring:url value="/resources/unique-machines/css/aos-animation.css"	var="aosAnimationCss" />
<spring:url value="/resources/unique-machines/css/light-carousel.css"	var="carouselCss" />
<!-- end: Css -->


<!--  Start:Javascript -->
<spring:url value="/resources/unique-machines/js/jquery-2.2.3.min.js"	var="jqueryJs" />
<spring:url value="/resources/unique-machines/js/bootstrap.js"	var="bootstrapJs" />
<spring:url value="/resources/unique-machines/js/jquery.flexisel.js"	var="jqueryFlexiselJs" />
<spring:url value="/resources/unique-machines/js/jquery.flexslider.js"	var="jqueryFlexsliderJs" />
<spring:url value="/resources/unique-machines/js/simpleLightbox.js"	var="simpleLightboxJs" />
<spring:url value="/resources/unique-machines/js/aos.js"	var="aosJs" />
<spring:url value="/resources/unique-machines/js/aosindex.js"	var="aosIndexJs" />
<spring:url value="/resources/unique-machines/js/move-top.js"	var="moveTopJs" />
<spring:url value="/resources/unique-machines/js/easing.js"	var="easingJs" />
<spring:url value="/resources/unique-machines/js/jquery.light-carousel.js"	var="carouselJs" />
<!--  End:Javascript -->

<!DOCTYPE html>
<html lang="en" class="no-js">

<head>

	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
	<meta name="author" content="" />
	<meta name="company" content="" />
	<meta name="abstract" content="" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	
	<title><tiles:insertAttribute name="title" ignore="true" /></title>
	
	<script>
		addEventListener("load", function () {
			setTimeout(hideURLbar, 0);
		}, false);

		function hideURLbar() {
			window.scrollTo(0, 1);
		}
	</script>
	
	<link href="${boostrapCss}" rel="stylesheet" type="text/css">
	<link href="${flexSliderCss}" rel="stylesheet" type="text/css" media="screen" property="" >
	<link href="${styleCss}" rel="stylesheet" type="text/css">
	<link href="${fontAwesomeCss}" rel="stylesheet" type="text/css">
	<link href="${simpleLightboxCss}" rel="stylesheet" type="text/css">
	<link href="${aosCss}" rel='stylesheet prefetch' type="text/css" media="all" />
	<link href="${aosAnimationCss}" rel='stylesheet prefetch' type="text/css" media="all" />
	<link href="${carouselCss}" rel="stylesheet" type="text/css">

</head>

<body data-aos-easing="ease" data-aos-duration="1200" data-aos-delay="0">

	
	<tiles:insertAttribute name="page_header_layout" />
	
	<tiles:insertAttribute name="body_content" />
		
	<tiles:insertAttribute name="page_footer_layout" />
	
	<script src="${jqueryJs}"></script>
	<script src="${bootstrapJs}"></script>
	<script src="${jqueryFlexiselJs}"></script>
	<script src="${jqueryFlexsliderJs}"></script>
	<script src="${simpleLightboxJs}"></script>
	<script src="${aosJs}"></script>
	<script src="${aosIndexJs}"></script>
	<script src="${moveTopJs}"></script>
	<script src="${easingJs}"></script>
	<script src="${carouselJs}"></script> 
	
	<script>
		$(window).load(function () {
			$("#flexiselDemo1").flexisel({
				visibleItems: 4,
				animationSpeed: 1000,
				autoPlay: true,
				autoPlaySpeed: 3000,
				pauseOnHover: true,
				enableResponsiveBreakpoints: true,
				responsiveBreakpoints: {
					portrait: {
						changePoint: 480,
						visibleItems: 1
					},
					landscape: {
						changePoint: 640,
						visibleItems: 2
					},
					tablet: {
						changePoint: 768,
						visibleItems: 3
					}
				}
			});
			
			$('.flexslider').flexslider({
				animation: "slide",
				start: function (slider) {
					$('body').removeClass('loading');
				}
			});
			
			$('.proj_gallery_grid a').simpleLightbox();
			
			$(".scroll").click(function (event) {
				event.preventDefault();
				$('html,body').animate({
					scrollTop: $(this.hash).offset().top
				}, 900);
			});
			
			$().UItoTop({
				easingType: 'easeOutQuart'
			});
		});
	</script>
	
	<script>
		$('.sample1').lightCarousel();
	</script> 
		
</body>

</html>