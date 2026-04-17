using System.Data;
using Oracle.ManagedDataAccess.Client;
using System.Text.RegularExpressions;

namespace OracleAdminApp.Services
{
    public static class PrivilegeServices
    {
        // Helper riêng — chạy query qua OracleDbConnection của team
        private static DataTable Run(OracleDbConnection db, string sql, OracleParameter[]? parms = null)
        {
            if (db == null)
                throw new Exception("Chưa kết nối đến cơ sở dữ liệu Oracle.");

            var dt = new DataTable();
            using var conn = db.GetConnection();
            conn.Open();
            using var cmd = new OracleCommand(sql, conn);
            if (parms != null) cmd.Parameters.AddRange(parms);
            using var adapter = new OracleDataAdapter(cmd);
            adapter.Fill(dt);
            return dt;
        }

        // ========== QUYỀN TRÊN BẢNG/VIEW/PROC (Object-level) ==========

        public static DataTable GetAllTablePrivileges(OracleDbConnection db)
        {
            const string sql = @"
                SELECT GRANTEE, OWNER, TABLE_NAME, GRANTOR,
                       PRIVILEGE, GRANTABLE, HIERARCHY
                FROM   DBA_TAB_PRIVS
                WHERE  OWNER NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS',
                                     'ORDSYS','WMSYS','APPQOSSYS','DBSNMP',
                                     'OUTLN','GSMADMIN_INTERNAL','AUDSYS',
                                     'DVSYS','LBACSYS','OLAPSYS','ORDDATA',
                                     'EXFSYS','ANONYMOUS','APEX_040000',
                                     'APEX_PUBLIC_USER','FLOWS_FILES')
                ORDER  BY GRANTEE, OWNER, TABLE_NAME";
            return Run(db, sql);
        }

        public static DataTable GetTablePrivilegesByGrantee(OracleDbConnection db, string grantee)
        {
            const string sql = @"
                SELECT GRANTEE, OWNER, TABLE_NAME, GRANTOR,
                       PRIVILEGE, GRANTABLE, HIERARCHY
                FROM   DBA_TAB_PRIVS
                WHERE  GRANTEE = :grantee
                ORDER  BY OWNER, TABLE_NAME";

            var parms = new[]
            {
                new OracleParameter(":grantee", OracleDbType.Varchar2)
                    { Value = grantee.ToUpperInvariant() }
            };
            return Run(db, sql, parms);
        }

        // ========== QUYỀN TRÊN CỘT (Column-level) ==========

        public static DataTable GetAllColumnPrivileges(OracleDbConnection db)
        {
            const string sql = @"
                SELECT GRANTEE, OWNER, TABLE_NAME, COLUMN_NAME,
                       GRANTOR, PRIVILEGE, GRANTABLE
                FROM   DBA_COL_PRIVS
                ORDER  BY GRANTEE, OWNER, TABLE_NAME, COLUMN_NAME";
            return Run(db, sql);
        }

        public static DataTable GetColumnPrivilegesByGrantee(OracleDbConnection db, string grantee)
        {
            const string sql = @"
                SELECT GRANTEE, OWNER, TABLE_NAME, COLUMN_NAME,
                       GRANTOR, PRIVILEGE, GRANTABLE
                FROM   DBA_COL_PRIVS
                WHERE  GRANTEE = :grantee
                ORDER  BY OWNER, TABLE_NAME, COLUMN_NAME";

            var parms = new[]
            {
                new OracleParameter(":grantee", OracleDbType.Varchar2)
                    { Value = grantee.ToUpperInvariant() }
            };
            return Run(db, sql, parms);
        }

        // ========== QUYỀN HỆ THỐNG ==========

        public static DataTable GetSystemPrivilegesByGrantee(OracleDbConnection db, string grantee)
        {
            const string sql = @"
                SELECT GRANTEE, PRIVILEGE, ADMIN_OPTION
                FROM   DBA_SYS_PRIVS
                WHERE  GRANTEE = :grantee
                ORDER  BY PRIVILEGE";

            var parms = new[]
            {
                new OracleParameter(":grantee", OracleDbType.Varchar2)
                    { Value = grantee.ToUpperInvariant() }
            };
            return Run(db, sql, parms);
        }




        // ====== PHÂN QUYỀN ======
        private static readonly Regex IdentifierValidator = new("^[A-Za-z][A-Za-z0-9_$#]*$");

        private static void ValidateIdentifier(string identifier, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(identifier))
                throw new ArgumentException("Giá trị không được rỗng.", parameterName);

            if (!IdentifierValidator.IsMatch(identifier))
                throw new ArgumentException(
                    "Tên phải bắt đầu bằng chữ cái và chỉ chứa chữ cái, số, _, $ hoặc #.",
                    parameterName);
        }

        private static void ExecuteNonQuery(OracleDbConnection db, string sql)
        {
            if (db == null)
                throw new Exception("Chưa kết nối đến cơ sở dữ liệu Oracle.");

            using var conn = db.GetConnection();
            conn.Open();
            using var cmd = new OracleCommand(sql, conn);
            cmd.ExecuteNonQuery();
        }

        public static void GrantPrivilege(OracleDbConnection db, string grantee, string privilege, string objectName = null, bool grantOption = false)
        {
            ValidateIdentifier(grantee, nameof(grantee));

            if (string.IsNullOrWhiteSpace(privilege))
                throw new ArgumentException("Privilege không được rỗng.", nameof(privilege));

            string sql;

            if (!string.IsNullOrWhiteSpace(objectName))
            {
                ValidateIdentifier(objectName, nameof(objectName));
                sql = $"GRANT {privilege.ToUpperInvariant()} ON {objectName.ToUpperInvariant()} TO {grantee.ToUpperInvariant()}";

                if (grantOption)
                    sql += " WITH GRANT OPTION";
            }
            else
            {
                sql = $"GRANT {privilege.ToUpperInvariant()} TO {grantee.ToUpperInvariant()}";
            }

            ExecuteNonQuery(db, sql);
        }



        // ====== THU HỒI QUYỀN ======
        public static void RevokePrivilege(OracleDbConnection db, string grantee, string privilege, string objectName = null)
        {
            ValidateIdentifier(grantee, nameof(grantee));

            if (string.IsNullOrWhiteSpace(privilege))
                throw new ArgumentException("Privilege không được rỗng.", nameof(privilege));

            string sql;

            if (!string.IsNullOrWhiteSpace(objectName))
            {
                ValidateIdentifier(objectName, nameof(objectName));

                sql = $"REVOKE {privilege.ToUpperInvariant()} ON {objectName.ToUpperInvariant()} FROM {grantee.ToUpperInvariant()}";
            }
            else
            {
                sql = $"REVOKE {privilege.ToUpperInvariant()} FROM {grantee.ToUpperInvariant()}";
            }

            ExecuteNonQuery(db, sql);
        }
    }
}