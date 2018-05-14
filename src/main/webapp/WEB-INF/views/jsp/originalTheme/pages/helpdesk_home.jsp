<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>

<spring:url value="/resources/originalTheme/js/custom/custom_chatHistoryDetails.js"	var="customChatHistoryDetailsJs" />

<input id="selectedChatId" name="selectedChatIdInput" type="hidden" value="<%=session.getAttribute("SELECTED_CHAT_ID")%>">

<div class="xs">
	<div class="col-md-8 inbox_right" style="margin: 0% 0%;">
		<div class="Compose-Message">
			<div class="panel panel-default" style="width: 1116px;">
				<!-- <div class="panel-heading">Query Solution Display</div> -->
				<div class="panel-body panel-body-com-m">
					<form class="com-mail" id="solutionDetailsFormId">
						
						<input id="backToChatWindowId1" type="submit" value="Back to Chat Window">
						<hr>
						<label>User Query : </label> <input type="text" class="form-control1 control3" id="userQueryId"> 
						<div class="panel" data-widget="{&quot;draggable&quot;: &quot;false&quot;}" data-widget-static="">
							<!-- <div class="panel-heading">
								<h2>Query Solution Table</h2>
								<div class="panel-ctrls" data-actions-container="" data-action-collapse="{&quot;target&quot;: &quot;.panel-body&quot;}"><span class="button-icon has-bg"><i class="ti ti-angle-down"></i></span></div>
							</div> -->
							<div class="panel-body no-padding" style="display: block;">
								<table id="querySolutionTable" class="table table-striped" style="width: 30%;left: -1%;position: relative;">
									<thead>
										<tr class="warning" id="tableHeadId">
											<!-- <th>Last Name</th> -->
										</tr>
									</thead>
									<tbody id="tableBodyId">
										<!-- <tr>
											<td>Mark</td>
										</tr> -->
									</tbody>
								</table>
							</div>
						</div>
						<hr>
						<input id="backToChatWindowId2" type="submit" value="Back to Chat Window">
					</form>
				</div>
			</div>
		</div>
	</div>
	<div class="clearfix"></div>
</div>

<script src="${customChatHistoryDetailsJs}"></script>

