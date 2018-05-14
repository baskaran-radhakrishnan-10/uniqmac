<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<spring:url value="/resources/miminiumTheme/img/avatar.jpg" var="avatarImg" />
	<spring:url value="/resources/miminiumTheme/img/equiniti-logo.png" var="equinitiLogo" />
	
<link href="${avatarImg}" rel="icon" type="image/x-icon">

<!-- start: Header -->
<nav class="navbar navbar-default header navbar-fixed-top">
	<div class="col-md-12 nav-wrapper">
		<div class="navbar-header" style="width: 100%;">
			<div class="opener-left-menu is-open">
				<span class="top"></span> <span class="middle"></span> <span
					class="bottom"></span>
			</div>
			<a href="${sessionScope.baseUrl}dashboard" class="navbar-brand"> <%-- <img src="${equinitiLogo}" alt="Equiniti Logo"/> --%>
			</a>

			<!-- 			<ul class="nav navbar-nav search-nav">
				<li>
					<div class="search">
						<span class="fa fa-search icon-search" style="font-size: 23px;"></span>
						<div class="form-group form-animate-text">
							<input type="text" class="form-text" required> <span
								class="bar"></span> <label class="label-search">Type
								anywhere to <b>Search</b>
							</label>
						</div>
					</div>
				</li>
			</ul> -->

			<ul class="nav navbar-nav navbar-right user-nav">
				<li class="user-name"><span><%=session.getAttribute("USER_ID")%></span></li>
				<li class="dropdown avatar-dropdown"><img src="${avatarImg}"
					class="img-circle avatar" alt="user name" data-toggle="dropdown"
					aria-haspopup="true" aria-expanded="true" />
			<%-- 		<ul class="dropdown-menu user-dropdown">
					 <li><a href="user_det_page"><span class="fa fa-user"></span>
								My Profile</a></li>
												<li><a href="data_import_page"><span class="fa fa-import"></span> Data Import</a></li>								
						<li><a href="DO_list_page"><span class="fa fa-file-text"></span>
								My Work Orders</a></li>
						<li><a href="user_det_page"><span class="fa fa-user-plus"></span>
								Add User</a></li>
						<li role="separator" class="divider"></li> 
						<li class="more">
							<ul>
								<li><a href="#" data-toggle="tooltip"
									data-placement="auto bottom" title="Manage Users"><span
										class="fa fa-cogs"></span></a></li>
								<li><a href="#" data-toggle="tooltip"
									data-placement="auto bottom" title="Lock Profile"><span
										class="fa fa-lock"></span></a></li>
								<li><a href="${sessionScope.baseUrl}logout" data-toggle="tooltip"
									data-placement="auto bottom" title="Logout"><span
										class="fa fa-power-off "></span></a></li>
							</ul>
						</li>
					</ul> --%>
					<li><a href="${sessionScope.baseUrl}logout" data-toggle="tooltip"
									data-placement="auto bottom" title="Logout"><span
										class="fa fa-power-off "></span></a>
						</li>
				<!-- 				<li><a href="#" class="opener-right-menu"><span
						class="fa fa-coffee"></span></a></li> -->
			</ul>
		</div>
	</div>
</nav>
<!-- end: Header -->
