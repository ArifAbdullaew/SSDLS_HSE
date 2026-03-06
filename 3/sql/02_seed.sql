INSERT INTO cve (cve_id, title) VALUES ('CVE-2024-12345','Use-after-free in ABC') RETURNING id;


INSERT INTO cve_nvd (cve_id_ref, source_cve_id, summary, published_date, source_url, raw_json)
VALUES (1,'CVE-2024-12345','NVD summary text','2024-06-10','https://nvd.nist.gov/vuln/detail/CVE-2024-12345', '{"example":"nvd"}'::jsonb)
RETURNING id;

INSERT INTO cve_rhel (cve_id_ref, advisory_name, summary, severity, published_date, source_url, raw_json)
VALUES (1,'RHSA-2024:0001','RHEL advisory text','Important','2024-07-01','https://access.redhat.com/errata/RHSA-2024:0001','{"example":"rhel"}'::jsonb)
RETURNING id;

INSERT INTO cve_mitre (cve_id_ref, description, assigner, published_date, source_url, raw_json)
VALUES (1,'MITRE description text','mitre.org','2024-06-05','https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345','{"example":"mitre"}'::jsonb)
RETURNING id;

INSERT INTO cve_github (cve_id_ref, gh_advisory_id, summary, ecosystem, published_date, source_url, raw_json)
VALUES (1,'GH-2024-12345','GH advisory text','npm','2024-06-12','https://github.com/advisories/GHSA-xxxx','{"example":"github"}'::jsonb)
RETURNING id;

INSERT INTO cvss_score (source_name, source_entry_id, version, vector, score)
VALUES ('nvd', 10, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8);

INSERT INTO reference (cve_id_ref, source_name, source_entry_id, url, note)
VALUES (1,'nvd',10,'https://nvd.nist.gov/vuln/detail/CVE-2024-12345','NVD page');
