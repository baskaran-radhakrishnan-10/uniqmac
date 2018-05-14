<!-- start:Left Menu -->
<div id="left-menu">

	<div class="sub-left-menu scroll bg-verylight-grey">
		
		<ul class="nav nav-list" id="leftMenuUL">
		
			<li id="time_li" class="time" style="border-bottom: 1px solid #eee;"><h1></h1><p></p></li>
			
			<li id="dashboard_li"><a href="${sessionScope.baseUrl}dashboard"><span class="fa-tachometer fa"></span>Dashboard</a></li>
			
			<li id="rbac_li" class="ripple" style="display:none;"><a class="tree-toggle nav-header"><span class="fa-user-secret fa"></span> Users &amp; Roles <span class="fa-angle-right fa right-arrow text-right"></span></a>
				<ul class="nav nav-list tree" style="display:none;"></ul>
			</li>
			
			<%-- <li id="change_password_li" style="display:none;"><a href="${sessionScope.baseUrl}rbac/managePassword"> <span class="fa-key fa"></span> Change Password </a></li> --%>
			
			<li id="build_test_plan_li" style="display:none;"><a href="${sessionScope.baseUrl}build_test_plan/show"> <span class="fa-pencil-square-o fa"></span> Build Test Plan </a></li>
			
			<li id="daily_status_report_li" style="display:none;"><a href="${sessionScope.baseUrl}dsr/show"> <span class="fa-calendar fa"></span> Daily Status Report </a></li>
			
			<li id="kt_plan_li" style="display:none;"><a href="${sessionScope.baseUrl}kt_plan/ktPlan"> <span class="fa-bullhorn fa"></span> KT Plan </a></li>
			
			<li id="report_search_li" class="ripple" style="display:none;"><a class="tree-toggle nav-header"> <span	class="fa-search fa"></span> Report <span class="fa-angle-right fa right-arrow text-right"></span></a>
				<ul class="nav nav-list tree" style="display:none;"></ul>
			</li>
			
			<li id="operations_li" class="ripple" style="display:none;"><a class="tree-toggle nav-header"> <span class="fa-cogs fa"></span>Operation<span class="fa-angle-right fa right-arrow text-right"></span></a>
				<ul class="nav nav-list tree" style="display:none;"></ul>
			</li>
			
		</ul>
		
	</div>
	
</div>
<!-- end: Left Menu -->

