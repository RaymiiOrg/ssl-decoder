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
        window.history.pushState('wut', 'SSL Decoder for ' + document.getElementById('host').value, '/ssl/?host=' + document.getElementById('host').value + '&port=' + document.getElementById('port').value + '&csr=' + document.getElementById('csr').value + '&s=');
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