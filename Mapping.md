# Mapping between Specifications and Tests

This document maps the API specifications (routes) to the corresponding test functions, primarily found in `test_api.py`. Coverage percentages are based on the report generated on 2025-10-25 14:42 +0200.

## Public Endpoints

* **GET /healthz**
    * Server Function: `create_app.healthz` (71% coverage)
    * Covered by Test: `test_api.py::test_healthz`

* **POST /api/create-user**
    * Server Function: `create_app.create_user` (89% coverage)
    * Covered by Tests:
        * `test_api.py::test_create_user_validation_error` (tests validation)
        * `test_api.py::test_create_user_success_then_login` (tests success case)

* **POST /api/login**
    * Server Function: `create_app.login` (72% coverage)
    * Covered by Test: `test_api.py::test_create_user_success_then_login`
    * *Note: Coverage < 100% suggests untested error paths (e.g., wrong password).*

* **GET /api/get-watermarking-methods**
    * Server Function: `create_app.get_watermarking_methods` (100% coverage)
    * Covered by Test: `test_api.py::test_get_watermarking_methods`

* **GET /api/get-version/<link>**
    * Server Function: `create_app.get_version` (14% coverage)
    * Covered by Tests:
        * `test_api.py::test_get_version_invalid_link_400` (tests invalid link format)
        * `test_api.py::test_get_version_happy_path_and_not_found` (tests success and not found)

## Authenticated Endpoints

* **POST /api/upload-document**
    * Server Function: `create_app.upload_document` (81% coverage)
    * Covered by Tests:
        * `test_api.py::test_upload_requires_auth` (tests auth failure)
        * `test_api.py::test_upload_list_get_roundtrip` (via helper `_upload_one_pdf`)

* **GET /api/list-documents**
    * Server Function: `create_app.list_documents` (71% coverage)
    * Covered by Test: `test_api.py::test_upload_list_get_roundtrip`

* **GET /api/get-document/<int:document_id>** and **GET /api/get-document?id=...**
    * Server Function: `create_app.get_document` (68% coverage)
    * Covered by Test: `test_api.py::test_upload_list_get_roundtrip`

* **GET /api/list-versions/<int:document_id>** and **GET /api/list-versions?documentid=...**
    * Server Function: `create_app.list_versions` (85% coverage)
    * Covered by Tests:
        * `test_api.py::test_create_and_read_watermark_and_list_versions` (path param version)
        * `test_api.py::test_list_versions_invalid_id_400` (query param version, error case)

* **GET /api/list-all-versions**
    * Server Function: `create_app.list_all_versions` (71% coverage)
    * Covered by Test: `test_api.py::test_create_and_read_watermark_and_list_versions`

* **POST /api/create-watermark/<int:document_id>** and **POST /api/create-watermark**
    * Server Function: `create_app.create_watermark` (74% coverage)
    * Covered by Tests:
        * `test_api.py::test_create_and_read_watermark_and_list_versions` 
        * `test_api.py::test_get_version_happy_path_and_not_found` 
        * `test_api.py::test_create_watermark_nonxmp_success_and_failures` 

* **POST /api/read-watermark/<int:document_id>** and **POST /api/read-watermark**
    * Server Function: `create_app.read_watermark` (70% coverage)
    * Covered by Tests:
        * `test_api.py::test_create_and_read_watermark_and_list_versions` 
        * `test_api.py::test_read_watermark_nonxmp_ok_and_error` 

* **DELETE /api/delete-document/<document_id>** and **DELETE, POST /api/delete-document**
    * Server Function: `create_app.delete_document` (72% coverage)
    * Covered by Tests:
        * `test_api.py::test_delete_document_missing_or_bad_id_400` 
        * `test_api.py::test_delete_document_success_then_404` 
        * `test_api.py::test_delete_document_post_variant_success` 

## RMAP Endpoints

* **POST /api/rmap-initiate**
    * Server Function: `rmap_initiate` (in `rmap_route.py`, 70% coverage)
    * Covered by Tests:
        * `test_rmap_route_unit_extra.py::test_rmap_initiate_ok`
        
* **POST /api/rmap-get-link**
    * Server Function: `rmap_get_link` (in `rmap_route.py`, 60% coverage)
    * Covered by Tests:
        * `test_rmap_route_unit_extra.py::test_rmap_get_link_returns_absolute_url`
