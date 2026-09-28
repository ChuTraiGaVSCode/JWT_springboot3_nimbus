$(document).ready(function () {
	var token = localStorage.getItem('token');

	if (!token) {
		window.location.href = '/login';
		return;
	}

	$.ajax({
		type: 'GET',
		url: '/users/me',
		dataType: 'json',
		contentType: 'application/json; charset=utf-8',
		beforeSend: function (xhr) {
			xhr.setRequestHeader('Authorization', 'Bearer ' + token);
		},
		success: function (data) {
			$('#profile').text(data.fullName);
			if (data.images) {
				$('#images').attr('src', data.images).show();
			}
		},
		error: function () {
			localStorage.removeItem('token');
			alert('Sorry, you are not logged in.');
			window.location.href = '/login';
		}
	});

	$('#logout').click(function () {
		localStorage.removeItem('token');
		window.location.href = '/login';
	});
});
