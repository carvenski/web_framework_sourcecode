



# *******************************************************************************
# see csrf.py, it teach you how to self-define a middleware !!

# different middleware methods will be called in different period ???
#
#  1.process_request(self, request)
#  2.process_view(self, request, callback, callback_args, callback_kwargs)
#  3.process_response(self, request, response) 
# 
#   browser -> server -> req  (middleware here?)->  req -> django app handler  \
#   browser <- server <- res  <-(middleware here?)  res <- django app handler  |
#
# *******************************************************************************



