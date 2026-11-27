# Badminton Inventory Management System (TangkisStock)

A single-file full-stack web inventory system built with **PHP 8**, **MariaDB 10**, **PDO**, **HTML5**, **CSS3**, **JavaScript**, **Bootstrap 5**, **Font Awesome 6**, and **Chart.js** for a small badminton equipment store managing **Rackets**, **Strings**, and **Shuttlecocks**.

---

## Key Features

- **Single-File Architecture (`index.php`):** All PHP routing, business logic, HTML layout, Upin & Ipin-inspired Malaysian village theme CSS, and JavaScript live inside one file.
- **Role-Based Access Control (RBAC):**
  - **Admin (`admin`):** Full dashboard, product CRUD (including product deletion), stock movements, inventory reports, and user management (create, edit, role changes, delete other accounts).
  - **User (`user`):** Dashboard, add/view/edit products, search & filter, record stock movements, view stock history, and view/print reports. Cannot delete products or manage users.
- **Transactional Stock Movements:** Records **Stock In** and **Stock Out** inside PDO transactions with row locking (`FOR UPDATE`), preventing negative stock or Stock Out above available units.
- **Visual Analytics & Printable Reports:** Displays summary KPIs, Stock by Category doughnut chart, Inventory Stock Levels bar chart, and filterable print-ready reports (`window.print()`).
- **Security Controls:** PDO prepared statements, `password_hash()` / `password_verify()`, session regeneration on login, CSRF tokens on POST forms, and `htmlspecialchars()` output escaping.

---

## Folder Structure (XAMPP)

Place `index.php` and `README.md` inside a dedicated folder under `htdocs`:

```text
C:\xampp\htdocs\badminton_inventory\
├── index.php
└── README.md