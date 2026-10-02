"""Project-wide pagination."""

from rest_framework.pagination import PageNumberPagination


class ClientSizedPagination(PageNumberPagination):
    """Page-number pagination whose page size the client may choose.

    Stock ``PageNumberPagination`` leaves ``page_size_query_param`` unset, so
    ``PAGE_SIZE`` is the only page size any client can get. The Risk Register's
    board groups a page into columns, so a column count describes the register
    only when the page holds it. A caller that asks for no size still gets
    ``PAGE_SIZE``.

    Without ``max_page_size``, ``?page_size=999999`` is a request to serialize
    an entire table.
    """

    page_size_query_param = "page_size"
    # Arbitrary: a round bound, and the largest size the Risk Register offers.
    # Nothing was measured. Raise it alongside a figure for the payload that
    # produces.
    max_page_size = 200
