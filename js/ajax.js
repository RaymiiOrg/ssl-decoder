// Copyright (C) 2015 Remy van Elst

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

function showdiv(id) {
    document.getElementById(id).style.display = 'block';
}

function hidediv(id) {
    document.getElementById(id).style.display = 'none';
}

var request = createRequestObject();
var dataReturn='';
var ajaxTimeout='';
var enterChecker=false;

function createRequestObject()
{
    var ro;
    var browser = navigator.appName;
    if(browser == 'Microsoft Internet Explorer')
    {
        ro = new ActiveXObject('Microsoft.XMLHTTP');
    }
    else{
        ro = new XMLHttpRequest();
        ro.setRequestHeader('HTTP_X_REQUESTED_WITH', 'XMLHttpRequest');
    }
    return ro;
}

function makeRequest (url, fun)
{
    enterChecker=false;
    request.open('get', url);
    request.onreadystatechange = function() { handleResponse(fun); }
    
    try{
        request.send(null);
        window.history.pushState('wut', 'SSL Decoder for ' + document.getElementById('host').value, '/ssl/?port=' + document.getElementById('port').value + '&csr=' + document.getElementById('csr').value + '&s=&host=' + document.getElementById('host').value);
    }
    catch(err){
        alert('Error occured: '+err);
        showElementbyID(false, 'preloader'); 
        showElementbyID(false, 'resultDiv'); 
        showElementbyID(true, 'sslform'); 
    }
}


function handleResponse(fun) {
    if(request.readyState < 4)
    {
        ajaxTimeout=setTimeout('handleResponse(\''+fun+'\')',10);
    }
    else if(request.readyState == 4 && !enterChecker)
    {
        enterChecker=true;
        var response = request.responseText;
        dataReturn=response;
        
        if(fun!='')
            ajaxTimeout=setTimeout(fun+'()', 200);
    }
}

function stopAjax()
{
    clearTimeout('ajaxTimeout');
    ajaxTimeout='';
}


function showContent(){
    showElementbyID(false, 'preloader');
    document.getElementById('resultDiv').innerHTML=dataReturn;
}

function showElementbyID(show, element){
    if(show)
        document.getElementById(element).style.display='block';
    else
        document.getElementById(element).style.display='none';
}

function strStartsWith(str, prefix) {
  return str.indexOf(prefix) === 0;
}

