            $(document).ready(function() {
                
                $('.errorlist').addClass("alert alert-error");

                {% if current_user_companies %}
                    $('#company-pill').addClass('active').siblings().removeClass('active');
                {% else %}
                    $('#industry-pill').addClass('active').siblings().removeClass('active');
                {% endif %}


                $('.nav-pills li a').click(function() {
                    $(this).parent().addClass('active').siblings().removeClass('active');
                });
                
                $('.accordion-body').collapse('hide');


                $('.tr_group_member').bind('click', function() {
                    var checkbox = $(this).find(':checkbox');
                    checkbox.prop('checked', !checkbox.prop('checked'));
                    $(this).toggleClass('tr_group_member_clicked');
                });


                function range(start, stop, step){
                    if (typeof stop=='undefined'){
                        // one param defined
                        stop = start;
                        start = 0;
                    };
                    if (typeof step=='undefined'){
                        step = 1;
                    };
                    if ((step>0 && start>=stop) || (step<0 && start<=stop)){
                        return [];
                    };
                    var result = [];

                    for (var i=start; step>0 ? i<stop : i>stop; i+=step){
                        result.push(i);
                    };
                    return result;
                };


                $.noty.defaults = {
                    layout: 'bottom',
                    theme: 'default',
                    type: 'alert',
                    text: '',
                    dismissQueue: true, // If you want to use queue feature set this true
                    template: '<div class="noty_message"><span class="noty_text"></span><div class="noty_close"></div></div>',
                    animation: {
                        open: {height: 'toggle'},
                        close: {height: 'toggle'},
                        easing: 'swing',
                        speed: 500 // opening & closing animation speed
                    },
                    timeout: false, // delay for closing event. Set false for sticky notifications
                    force: false, // adds notification to the beginning of queue when set to true
                    modal: false,
                    closeWith: ['click'], // ['click', 'button', 'hover']
                    callback: {
                        onShow: function() {},
                        afterShow: function() {},
                        onClose: function() {},
                        afterClose: function() {}
                    },
                    buttons: false // an array of buttons
                };


                // prepare Options Object 
                var options = { 
                    // target:     '#divToUpdate', 
                    // url:        '{% url "invite_to_group" %}', 
                    success:    function(user_notification) { 
                        var user_notification = user_notification.split(';');
                        var n = noty({ 
                            text: user_notification[1], 
                            type: user_notification[0], 
                            timeout: 7000,
                        });
                    }
                }; 
                 
                // attach handler to form's submit event 
                $('#invite_to_group, #request_access').submit(function() { 
                    // submit the form 
                    $(this).ajaxSubmit(options); 
                    // return false to prevent normal browser submit and page navigation 
                    return false; 
                });
                    

                // $('#add_group').submit(function() { 
                //     $(this).ajaxSubmit(options);
                //     return false;
                // });


                $("a.accordion-toggle").click(function() {

                    var self = $(this); 
                    var data = escape(self.text()); 
                    var counter = $(this).data("counter"); 

                    if (self.hasClass('company')) {
                        var getPrepend = 'company=';
                    } else if (self.hasClass('industry')) {
                        var getPrepend = 'industry=';
                    }; 

                    // Don't refetch from DB if already done before. 
                    if ($("#accordion-heading"+counter).children().length < 2) {
                    
                        $.ajax({
                            type: "GET",
                            url: '{% url "ajax" %}',
                            dataType: 'json', 
                            data: getPrepend + data,
                            success: function(response) {

                                htmlString = "<div id=\"collapse" + counter + "\" class=\"accordion-body collapse in\">" + "<div id=\"accordion-inner" + counter + "\"  class=\"accordion-inner\"><table class=\"table table-bordered table-hover\">"; 
                                
                                for (var i=0; i < response.length; i++) {

                                    var person = response[i]; 

                                    htmlString += "<tr><td><a href=\"" + person['public_url'] + "\" class=\"picture_url\"><img alt=\"profile-pic\" id=\"node_profile_picture\" class=\"img-rounded\" src=\""; 

                                    if (person['picture_url'] == 'No picture given') {
                                        htmlString += "http://www.vdvl.nl/wp-content/uploads/2012/10/icon_no_photo_no_border_80x80.png"; 
                                    } else { 
                                        htmlString += person['picture_url']; 
                                    }; 

                                    htmlString += "\" /></a></td><td><a href=\"" + person['public_url'] + "\" class=\"member_public_url\">" + person['first_name'] + " " + person['last_name'] + "</a>, " + person['location'] + ", " + person['industry'] + "</td><td>" + person['title'] + "</td><td>" + person['company'] + "</td><td>Connected through: ";

                                    connectors = range(person['connectors'].length);

                                    for (var index in connectors) {
                                        htmlString += "<a href=\"" + person['connector_urls'][index] + "\" class=\"member_public_url\">" + person['connectors'][index] + "</a>";

                                        if (index < person['connectors'].length-1) { 
                                            htmlString += ", "; 
                                        };
                                    }; 

                                    htmlString += "</td></tr>"; 

                                };

                                htmlString += "</table></div></div>"; 

                                self.after(htmlString);

                            }, 
                            error: function(response) {
                                $(this).html('There was an error.');
                            }

                        });

                    }; 

                });


                $.unblockUI();

                $('a').click(function(e) {
                    if($(e.target).is('a.accordion-toggle, #UpdateEmail, #LeaveGroup, #MyGroups, .member_public_url, .picture_url')){
                        e.preventDefault();
                        return;
                    }; 

                    $.blockUI({ message: 'Loading...', 
                        css: { 
                            border: 'none', 
                            padding: '15px', 
                            backgroundColor: '#000', 
                            '-webkit-border-radius': '10px', 
                            '-moz-border-radius': '10px', 
                            opacity: .5, 
                            color: '#fff', 
                            'font-size': '28px',
                            font: 'helvetica', 
                        } 
                    }); 
                }); 

            }).ajaxStart(function() {
                $.blockUI({ message: 'Loading...', 
                    css: { 
                        border: 'none', 
                        padding: '15px', 
                        backgroundColor: '#000', 
                        '-webkit-border-radius': '10px', 
                        '-moz-border-radius': '10px', 
                        opacity: .5, 
                        color: '#fff', 
                        'font-size': '28px',
                        font: 'helvetica', 
                    } 
                }); 
            }).ajaxStop(function() {
                $.unblockUI();
            });