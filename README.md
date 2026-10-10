# sourcecodester Online Food Ordering System in PHP and MySQL Source Code — Missing Authentication on Admin Delete Endpoints

## Vendor

sourcecodester

## Product

Online Food Ordering System in PHP and MySQL Source Code  
Product URL: https://www.sourcecodester.com/php/18232/food-order-system.html

## Vulnerability

The `admin/delete_admin.php` endpoint performs a sensitive deletion without first requiring an authenticated admin session (CWE-306).

**Discovered by:** Shailendra Mourya (CyberShailendra)  
**Affected files:** `admin/delete_admin.php`; similar missing checks are reported in `admin/delete.php` and `admin/delete_category.php`  
**Report date:** 2026-10-10  
**Status:** Reported as reproduced on a local XAMPP test instance.

---

## Finding Details

| Field | Value |
|---|---|
| **Title** | Online Food Ordering System `delete_admin.php` Missing Authentication Check |
| **Affected File** | `admin/delete_admin.php` (same pattern in `admin/delete.php`, `admin/delete_category.php`) |
| **Vulnerability Type** | Missing Authentication for Critical Function (CWE-306) |
| **Attack Vector** | Network (remote) |
| **Authentication Required** | None |
| **CVSS 3.1 Vector (estimated)** | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H |
| **CVSS 3.1 Score (estimated)** | 8.6 (High) |
| **Root Cause** | The script only includes `config/constants.php` for the DB connection; it never includes `user_logged.php` or checks `$_SESSION['user']` before executing the delete query. |
| **Proof of Concept** | Unauthenticated `GET /web/admin/delete_admin.php?id=50` |
| **Observed Impact** | Admin account with `id=50` was deleted without any login session present, confirmed via direct unauthenticated browser request. |
| **Confirmed By** | User, local XAMPP instance, 2026-10-10 — admin record removed, visible in `tbl_admin` / login no longer possible for that account. |
| **Remediation** | `include('user_logged.php');` at the top of every admin action script (delete, update, add) before any database operation runs; additionally guard the catch-all redirect in `user_logged.php` with `exit()` so execution cannot continue past the redirect header. |

---

## Technical Details — Vulnerable Code (`admin/delete_admin.php`)

```php
<?php 
include('../config/constants.php');     // <-- only DB connection, no auth check
if(isset($_GET['id'])){
    $id = intval($_GET['id']);
    $sql = "delete from tbl_admin where id=$id";
    $res = mysqli_query($conn, $sql);
    ...
}
?>
```

The endpoint neither includes `user_logged.php` nor checks `$_SESSION['user']` before running the delete query. As written, it does not distinguish an authenticated admin from an unauthenticated visitor.

### Contributing Bug in `admin/partials/user_logged.php`
Used elsewhere, but shows why relying on it alone isn't enough without `exit()`:

```php
<?php
    if(!isset($_SESSION['user'])){
        $_SESSION['not-logged-in'] = "please login";
        header("Location:" . SITEURL. 'admin/login.php');
        // <-- missing exit(); PHP keeps executing the rest of the including page
    }
?>
```

---

## Remediation Code

### Fix for `admin/delete_admin.php`
```php
<?php 
include('../config/constants.php');
include('user_logged.php');     // enforce login before anything else runs

if(isset($_GET['id'])){
    $id = intval($_GET['id']);
    $sql = "delete from tbl_admin where id=?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $id);
    $res = mysqli_stmt_execute($stmt);
    if($res){
        $_SESSION['delete_admin'] = "admin deleted successfully";
    }
    header('Location:'.SITEURL.'admin/admin.php');
    exit();
}
?>
```

### Fix for `admin/partials/user_logged.php`
Fix `user_logged.php` itself so every page that includes it is protected even without remembering to add a redundant check:
```php
<?php
    if(!isset($_SESSION['user'])){
        $_SESSION['not-logged-in'] = "please login";
        header("Location:" . SITEURL. 'admin/login.php');
        exit();   // <-- stop execution here
    }
?>
```
