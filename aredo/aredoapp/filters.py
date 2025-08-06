# filters.py
import django_filters
from django_filters import rest_framework as filters
from django.db.models import Q, Count
from .models import ApplicationForm, FormKind, University


class ApplicationFormFilter(django_filters.FilterSet):
    """
    Enhanced filter for ApplicationForm with comprehensive filtering options
    """

    # ============ EXACT MATCH FILTERS ============
    degree = django_filters.ChoiceFilter(
        choices=ApplicationForm.DEGREE_CHOICES,
        help_text="Filter by degree type"
    )
    govern = django_filters.ChoiceFilter(
        choices=ApplicationForm.GOVERNORATE_CHOICES,
        help_text="Filter by governorate"
    )

    # ============ BOOLEAN STATUS FILTERS ============
    submitted = django_filters.BooleanFilter(
        help_text="Filter by submission status"
    )
    approved = django_filters.BooleanFilter(
        help_text="Filter by approval status"
    )
    accepted = django_filters.BooleanFilter(
        help_text="Filter by acceptance status"
    )
    received = django_filters.BooleanFilter(
        help_text="Filter by received status"
    )
    payoff = django_filters.BooleanFilter(
        help_text="Filter by payment status"
    )
    touch = django_filters.BooleanFilter(
        help_text="Filter by touch status (user has interacted with form)"
    )

    # ============ DATE RANGE FILTERS ============
    date_applied = django_filters.DateFromToRangeFilter(
        help_text="Filter by date range (from_date,to_date)"
    )
    date_applied_after = django_filters.DateFilter(
        field_name='date_applied',
        lookup_expr='gte',
        help_text="Filter applications after this date (YYYY-MM-DD)"
    )
    date_applied_before = django_filters.DateFilter(
        field_name='date_applied',
        lookup_expr='lte',
        help_text="Filter applications before this date (YYYY-MM-DD)"
    )

    # Date shortcuts
    date_applied_year = django_filters.NumberFilter(
        field_name='date_applied__year',
        help_text="Filter by year (YYYY)"
    )
    date_applied_month = django_filters.NumberFilter(
        field_name='date_applied__month',
        help_text="Filter by month (1-12)"
    )

    # ============ TEXT SEARCH FILTERS ============
    full_name = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Search in applicant's full name"
    )
    email = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Search in email address"
    )
    phone = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Search in phone number"
    )
    department = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Search in department name"
    )

    # Add tracker search (note: keeping the original field name 'traker')
    tracker = django_filters.CharFilter(
        field_name='traker',
        lookup_expr='icontains',
        help_text="Search by tracker ID"
    )

    # ============ FOREIGN KEY FILTERS ============
    university = django_filters.ModelChoiceFilter(
        queryset=University.objects.all(),
        help_text="Filter by university"
    )
    university_name = django_filters.CharFilter(
        field_name='university__name',
        lookup_expr='icontains',
        help_text="Search in university name"
    )

    # Form kind filters
    kind = django_filters.ModelChoiceFilter(
        queryset=FormKind.objects.filter(is_active=True),
        help_text="Filter by form kind"
    )
    kind_code = django_filters.CharFilter(
        field_name='kind__code',
        lookup_expr='exact',
        help_text="Filter by form kind code (applicant, translate, etc.)"
    )

    # ============ CUSTOM STATUS FILTER ============
    status = django_filters.ChoiceFilter(
        choices=[
            ('draft', 'Draft - Not started or saved'),
            ('in_progress', 'In Progress - Started but not submitted'),
            ('submitted', 'Submitted - Waiting for approval'),
            ('approved', 'Approved - Waiting for acceptance'),
            ('accepted', 'Accepted - Waiting to be received'),
            ('received', 'Received - Process completed'),
            ('incomplete', 'Incomplete - Missing required fields'),
            ('pending_review', 'Pending Review - Submitted applications'),
        ],
        method='filter_by_status',
        help_text="Filter by application status"
    )

    # ============ ADVANCED SEARCH FILTER ============
    search = django_filters.CharFilter(
        method='search_applications',
        help_text="Global search across name, email, phone, department, and tracker"
    )

    # ============ USER FILTER (for admin use) ============
    user = django_filters.NumberFilter(
        field_name='user__id',
        help_text="Filter by user ID (admin only)"
    )
    user_email = django_filters.CharFilter(
        field_name='user__email',
        lookup_expr='icontains',
        help_text="Filter by user email (admin only)"
    )

    # ============ COMPLETION AND PRIORITY FILTERS ============
    has_university = django_filters.BooleanFilter(
        field_name='university__isnull',
        exclude=True,
        help_text="Filter applications that have university selected"
    )

    needs_attention = django_filters.BooleanFilter(
        method='filter_needs_attention',
        help_text="Filter applications that need admin attention"
    )

    class Meta:
        model = ApplicationForm
        fields = {
            'kind': ['exact'],
            'degree': ['exact'],
            'govern': ['exact'],
            'submitted': ['exact'],
            'approved': ['exact'],
            'accepted': ['exact'],
            'received': ['exact'],
            'payoff': ['exact'],
            'touch': ['exact'],
            'university': ['exact'],
            'date_applied': ['exact', 'gte', 'lte', 'year', 'month'],
            'full_name': ['icontains', 'exact'],
            'email': ['icontains', 'exact'],
            'department': ['icontains', 'exact'],
            'phone': ['icontains'],
            'traker': ['icontains', 'exact'],
        }

    def filter_by_status(self, queryset, name, value):
        """
        Enhanced custom filter method for application status
        """
        if value == 'draft':
            # Not touched and not submitted
            return queryset.filter(touch=False, submitted=False)
        elif value == 'in_progress':
            # Touched but not submitted
            return queryset.filter(touch=True, submitted=False)
        elif value == 'submitted':
            # Submitted but not approved
            return queryset.filter(submitted=True, approved=False)
        elif value == 'approved':
            # Approved but not accepted
            return queryset.filter(approved=True, accepted=False)
        elif value == 'accepted':
            # Accepted but not received
            return queryset.filter(accepted=True, received=False)
        elif value == 'received':
            # Received (final state)
            return queryset.filter(received=True)
        elif value == 'incomplete':
            # Has missing required fields
            return queryset.filter(
                touch=True,
                submitted=False
            ).filter(
                Q(full_name__isnull=True) | Q(full_name='') |
                Q(email__isnull=True) | Q(email='') |
                Q(phone__isnull=True) | Q(phone='')
            )
        elif value == 'pending_review':
            # All submitted applications pending review
            return queryset.filter(submitted=True, received=False)
        return queryset

    def search_applications(self, queryset, name, value):
        """
        Global search across multiple fields
        """
        if not value:
            return queryset

        return queryset.filter(
            Q(full_name__icontains=value) |
            Q(email__icontains=value) |
            Q(phone__icontains=value) |
            Q(department__icontains=value) |
            Q(traker__icontains=value) |
            Q(university__name__icontains=value) |
            Q(user__email__icontains=value) |
            Q(kind__name__icontains=value)
        )

    def filter_needs_attention(self, queryset, name, value):
        """
        Filter applications that need admin attention
        """
        if value:
            return queryset.filter(
                Q(submitted=True, approved=False) |  # Pending approval
                Q(approved=True, accepted=False)  # Pending acceptance
            )
        return queryset

    @property
    def qs(self):
        """
        Override to add default ordering and optimization
        """
        parent = super().qs
        return parent.select_related(
            'user', 'university', 'kind'
        ).prefetch_related(
            'university__country'
        ).order_by('-date_applied')


class AdminApplicationFormFilter(ApplicationFormFilter):
    """
    Extended filter for admin users with additional fields
    """

    # Admin-specific filters
    is_active_user = django_filters.BooleanFilter(
        field_name='user__is_active',
        help_text="Filter by user active status"
    )

    created_this_month = django_filters.BooleanFilter(
        method='filter_created_this_month',
        help_text="Filter applications created this month"
    )

    created_today = django_filters.BooleanFilter(
        method='filter_created_today',
        help_text="Filter applications created today"
    )

    def filter_created_this_month(self, queryset, name, value):
        """Filter applications created in current month"""
        if value:
            from django.utils import timezone
            now = timezone.now()
            return queryset.filter(
                date_applied__year=now.year,
                date_applied__month=now.month
            )
        return queryset

    def filter_created_today(self, queryset, name, value):
        """Filter applications created today"""
        if value:
            from django.utils import timezone
            today = timezone.now().date()
            return queryset.filter(date_applied__date=today)
        return queryset


