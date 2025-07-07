from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from collections import OrderedDict


class CustomPagination(PageNumberPagination):
    """
    Custom pagination class to match frontend expectations.
    Frontend expects: { data: [], pagination: { page, limit, total, totalPages } }
    """
    page_size = 10
    page_size_query_param = 'limit'
    max_page_size = 100
    page_query_param = 'page'

    def get_paginated_response(self, data):
        return Response(OrderedDict([
            ('data', data),
            ('pagination', OrderedDict([
                ('page', self.page.number),
                ('limit', self.page.paginator.per_page),
                ('total', self.page.paginator.count),
                ('totalPages', self.page.paginator.num_pages),
            ]))
        ])) 