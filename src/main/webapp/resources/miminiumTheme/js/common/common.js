var sessionStorageObj=null;
var indexDBObj=null;

$(document).ready(function() {
	if (storageAvailable('sessionStorage')) {
		sessionStorageObj=new SessionStorage();
	}
	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
	if (window.indexedDB) {
		indexDBObj=new IndexDB();
	}
	
	$(document).on("blur","input",function(event){
		var type= $(this).prop("type");
		if(null != type && type != "" && "date" == type){
			$(this).removeClass('error');
			var isValid=true;
			var value = $(this).val();
			if("" == value || value.length == 0){
				return false;
			}
			var yearStr=value.split("-")[0];
			if(yearStr.length > 4){
				$(this).addClass('error');
				isValid=false;
			}else{
				var year = parseInt(yearStr);
				if(!(year >= 2000 && year <= 2100)){
					isValid=false;
				}
			}
			if(!isValid){
				var notifyObj={msg: '<b>Error :</b> Invalid Year Value Given !!!',type: "error",position: "center"};
				notif(notifyObj);
			}
		}
	});
	
});

function IndexDB(){
	var request=null;
	var db=null;
	var isConnectionReady=false;
};

IndexDB.prototype={
		constructor  : IndexDB,
		openDatabase : function(dbName,objectStorage,key){
			indexDBObj.request = window.indexedDB.open(dbName, 2);
			indexDBObj.request.onerror = function(event){
				console.log("Error opening DB", event);
			};
			indexDBObj.request.onupgradeneeded = function(event){
				console.log("Upgrading");
				indexDBObj.db = event.target.result;
				indexDBObj.db.createObjectStore(objectStorage, { keyPath : key });
			};
			indexDBObj.request.onsuccess = function(event){
				console.log("Success opening DB");
				indexDBObj.db = event.target.result;
				indexDBObj.isConnectionReady=true;
			};
		},
		addData : function(objectStoreName,data){
			if(indexDBObj.isConnectionReady){
				var transaction = indexDBObj.db.transaction([objectStoreName],"readwrite");
				transaction.oncomplete = function(event) {
					console.log("Success");
				};
				transaction.onerror = function(event) {
					console.log("Error");
				};  
				var objectStore = transaction.objectStore(objectStoreName);
				objectStore.add(data);
			}
		}
};

function SessionStorage(){};

SessionStorage.prototype.setItem=function(key,value){
	sessionStorage.setItem(key,JSON.stringify(value));
}

SessionStorage.prototype.getItem=function(key){
	if(null != sessionStorage.getItem(key)){
		return JSON.parse(sessionStorage.getItem(key));
	}
	return null;
}

SessionStorage.prototype.removeItem=function(key,value){
	sessionStorage.removeItem(key);
}

function storageAvailable(type) {
	try {
		var storage = window[type],
		x = '__storage_test__';
		storage.setItem(x, x);
		storage.removeItem(x);
		return true;
	}
	catch(e) {
		return false;
	}
}

function ajaxHandler(requestType,data,contentType,url,dataType,errorCallback,successCallback,async){
	//console.log("url :"+url);
	$.ajax({
		type : requestType,
		contentType : contentType,
		url : url,
		data : data,
		dataType : dataType,
		async : async,
		success : function(serverData) {
			//console.log("SUCCESS : ", serverData);
			if(typeof serverData != 'undefined' && null != serverData){
				if(null != serverData['REDIRECT_TO_LOGIN_PAGE'] && serverData['REDIRECT_TO_LOGIN_PAGE']){
					logoutMethod();
				}else {
					if(null != successCallback){
						successCallback(serverData,JSON.parse(data));
					}
				}
			}
		},
		error : function(e) {
			
			console.log(e);
			
			var data = {};
			data["ATTRIBUTE_KEY"]="IS_LOGGED_IN";
			
			$.ajax({
				type : "POST",
				contentType : "application/json",
				url : getApplicationRootPath()+"getSessionAttribute",
				data : JSON.stringify(data),
				dataType : "json",
				async : true,
				success : function(response) {
					if(null == response["IS_LOGGED_IN"]){
						logoutMethod();
					}
				},
				error : function(e) {
					console.log( e);
				}
			});
			
			if(typeof e != 'undefined' && null != e){
				if(null != errorCallback){
					errorCallback(e);
				}
			}
			
		}
	});
}


function getApplicationRootPath(){
	var href=window.location.href;
	var rootPathArray=href.split("/");
	var rootPath = "";
	if(rootPathArray.length > 5){
		for(var index in rootPathArray){
			if(index < 4){
				rootPath += rootPathArray[index] + "/";
			}
		}
	}else{
		rootPath=href.substring(0,href.lastIndexOf("/")+1);
	}
	return rootPath;
}

function getCurrentServerTimeSuccess(data){
	currentServerTime=data['SERVER_TIME'];
}

function getDifferenceBetweenDate(postedDate,currentDate){
	var diffDays = Math.round(Math.abs((postedDate.getTime() - currentDate.getTime())/(24*60*60*1000)));
	return diffDays;
}

function logoutMethod(){
	window.location.href=getApplicationRootPath()+"logout";
}

function constructModalDialogBox(isCloseButtonNeed,modalTitle,modalBodyContent,buttonArrayObj){
	var modalHtml='';
	modalHtml += '<div class="modal-header">';
	if(isCloseButtonNeed){
		modalHtml += '<button type="button" class="close" data-dismiss="modal" aria-hidden="true">(x)</button>';
	}
	modalHtml += '<h2 class="modal-title">'+modalTitle+'</h2>';
	modalHtml += '</div>';
	modalHtml += '<div class="modal-body">';
	modalHtml += '<p style="font-size: 0.95em;">'+modalBodyContent+'</p>';
	modalHtml += '</div>';
	modalHtml += '<div class="modal-footer">';
	for(var index in buttonArrayObj){
		var buttonObject=buttonArrayObj[index];
		var buttonClass=buttonObject['BUTTON_IS_PRIMARY'] ? 'btn btn-primary' : 'btn btn-default';
		var buttonClickFunction=buttonObject['FUNCTION'];
		modalHtml += '<button type="button" id="'+buttonObject['BUTTON_ID']+'" class="'+buttonClass+'" data-dismiss="modal" onclick="modalMethodExecution('+buttonClickFunction+')">'+buttonObject['BUTTON_NAME']+'</button>';
	}
	modalHtml += '</div>';
	return modalHtml;
}

function modalMethodExecution(method){
	method();
}

function isValidEmail(email) {
	var regex = /^([a-zA-Z0-9_.+-])+\@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9])+$/;
	return regex.test(email);
}

function getFormatedDateByTime(dateObj,hour,min,sec,millisec){
	dateObj.setHours(hour,min,sec,millisec);
	return dateObj;
}

function getDaysInMonth(month,year) {
    return new Date(year, (month+1), 0).getDate();
}

function fillSelectDropDown(dropDownId,arrayData,selectedOption){
	$('#'+dropDownId).html("");
	$.each(arrayData, function(key, value) {   
		$('#'+dropDownId).append($("<option></option>").attr("value",value).text(value)); 
	});
	$('#'+dropDownId).val(selectedOption);
}

function getDateValue(dateObj,format,delimeter){
	var formatedDateStr="";
	if($.type(dateObj) === "string"){
		return dateObj;
	}
	if(null != dateObj){
		var day=(dateObj['dayOfMonth'] > 9) ? (""+dateObj['dayOfMonth']) : ("0"+dateObj['dayOfMonth']);
		var month=(dateObj['monthOfYear'] > 9) ? (""+dateObj['monthOfYear']) : ("0"+dateObj['monthOfYear']);
		if("dd/MM/yyyy" == format){
			if("/" == delimeter){
				formatedDateStr=day+"/"+ month+"/"+ dateObj['year'];
			}else if("-" == delimeter){
				formatedDateStr=day+"-"+ month+"-"+ dateObj['year'];
			}
		}else if("yyyy-MM-dd" == format){
			if("/" == delimeter){
				formatedDateStr=dateObj['year']+"/"+month+"/"+day;
			}else if("-" == delimeter){
				formatedDateStr=dateObj['year']+"-"+month+"-"+day;
			}
		}
	}
	return formatedDateStr;
}

function checkisNumber(charCode){
	if (charCode != 8 && charCode != 0 && (charCode < 48 || charCode > 57)) {
		return false;
	}
	return true;
}

function checkIsDecimelNumber(charCode){
	if (charCode != 8 && charCode != 0 && (charCode < 48 || charCode > 57) && charCode != 46) {
		return false;
	}
	return true;
}
