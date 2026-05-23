---
aliases: {% for alias in aliases %}
    - {{alias}}
    {% endfor %}
mitre-attack: {{mitre_attack}}
---

## {{title}}

{{description | parse_description(references)}}

### Techniques Used
| ID | Name | Use |
| --- | --- | --- |
{% for technique in techniques %}| [[{{technique['link']}}\|{{technique['id']}}]] | {{technique['name']}} | {{ technique['description'] | parse_description(references) }} |
{% endfor %}

{% if groups %}
### Groups That Use This Software
| ID | Name |
| --- | --- |
{% for group in groups %}| [[{{group['link']}}\|{{group['id']}}]] | {{group['name']}} |
{% endfor %}
{% endif %}

## References
{% for ref in references %}
{% if ref['url'] %}[^{{ref['id']}}]: [{{ref['source_name']}}]({{ref['url']}})
{% else %}[^{{ref['id']}}]: {{ref['source_name']}}
{% endif %}
{% endfor %}
