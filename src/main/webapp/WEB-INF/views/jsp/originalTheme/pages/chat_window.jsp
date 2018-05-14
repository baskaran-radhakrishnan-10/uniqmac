<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<spring:url value="/resources/originalTheme/css/chat/jquery.mCustomScrollbar.min.css" var="mCustomScrollbarCss" />
<spring:url value="/resources/originalTheme/css/chat/normalize.css" var="NormalizeCss" />
<spring:url value="/resources/originalTheme/css/chat/style.css"	var="StyleCss" />

<spring:url value="/resources/originalTheme/js/plugin/jquery.mCustomScrollbar.concat.min.js"	var="mCustomScrollbarJs" />
<spring:url value="/resources/originalTheme/js/custom/custom_chat.js"	var="customChatJs" />
<spring:url value="/resources/originalTheme/js/custom/custom_chatHistory.js"	var="customChatHistoryJs" />

<spring:url value="/resources/originalTheme/img/sys_response.png" var="sys_response_logo" />
<spring:url value="/resources/originalTheme/img/profile_pic.jpg" var="profile_pic_logo" />

<link rel="stylesheet" href="${NormalizeCss}">
<link rel="stylesheet" href="${mCustomScrollbarCss}">
<link rel="stylesheet" href="${StyleCss}">

<input type="hidden" id="sys_response_logo_path" value="${sys_response_logo}" />

<div class="chat">
	<div class="chat-title" style="">
		<h1 style="text-transform: uppercase;color: rgba(255, 255, 255, 0.68);"><%=session.getAttribute("USER_NAME")%></h1>
		<h2 style="text-transform: lowercase;color: rgb(255, 255, 255);"><%=session.getAttribute("USER_ID")%></h2>
		<figure class="avatar">
			<img src="${profile_pic_logo}">
		</figure>
	</div>
	<div class="messages">
		<div class="messages-content"></div>
	</div>
	<div class="message-box">
		<input type="text" class="message-input" id="send_chat_id" placeholder="Type your query..."></input>
		<!-- <button type="submit" id="send_chat_id" class="message-submit" style="height: 44px;width: 103px;">Send</button> -->
	</div>
</div>

<!-- <div id="tableDivId"> -->
	<table id="querySolutionTable" class="table table-striped">
		<thead>
			<tr class="warning" id="tableHeadId"></tr>
		</thead>
		<tbody id="tableBodyId"></tbody>
	</table>
<!-- </div> -->


<div class="bg"></div>

<script	src="${mCustomScrollbarJs}"></script> 	
<script src="${customChatHistoryJs}"></script>

