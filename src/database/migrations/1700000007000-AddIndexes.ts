import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddIndexes1700000007000 implements MigrationInterface {
  name = 'AddIndexes1700000007000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add indexes for email columns (already unique, but helpful for queries)
    await queryRunner.query(`CREATE INDEX "IDX_DEALERS_BUSINESS_EMAIL" ON "dealers" ("business_email")`);
    await queryRunner.query(`CREATE INDEX "IDX_ROOF_TOP_LOCATION_BUSINESS_EMAIL" ON "roof_top_location" ("business_email")`);
    await queryRunner.query(`CREATE INDEX "IDX_DEALER_ADMIN_EMAIL" ON "dealer_admin" ("email")`);
    await queryRunner.query(`CREATE INDEX "IDX_DEALER_STAFF_EMAIL" ON "dealer_staff" ("email")`);
    await queryRunner.query(`CREATE INDEX "IDX_CUSTOMERS_EMAIL" ON "customers" ("email")`);
    await queryRunner.query(`CREATE INDEX "IDX_SYSADMINS_EMAIL" ON "sysadmins" ("email")`);

    // Add indexes for foreign key columns
    await queryRunner.query(`CREATE INDEX "IDX_ROOF_TOP_LOCATION_DEALER_ID" ON "roof_top_location" ("dealer_id")`);
    await queryRunner.query(`CREATE INDEX "IDX_DEALER_ADMIN_DEALER_ID" ON "dealer_admin" ("dealer_id")`);
    await queryRunner.query(`CREATE INDEX "IDX_DEALER_STAFF_DEALER_ID" ON "dealer_staff" ("dealer_id")`);

    // Add indexes for commonly queried columns
    await queryRunner.query(`CREATE INDEX "IDX_DEALER_ADMIN_IS_PRIMARY" ON "dealer_admin" ("is_primary_admin")`);
    await queryRunner.query(`CREATE INDEX "IDX_DEALER_ADMIN_IS_VERIFIED" ON "dealer_admin" ("is_account_verified")`);
    await queryRunner.query(`CREATE INDEX "IDX_DEALER_STAFF_IS_VERIFIED" ON "dealer_staff" ("is_account_verified")`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop all indexes
    await queryRunner.query(`DROP INDEX "IDX_DEALERS_BUSINESS_EMAIL"`);
    await queryRunner.query(`DROP INDEX "IDX_ROOF_TOP_LOCATION_BUSINESS_EMAIL"`);
    await queryRunner.query(`DROP INDEX "IDX_DEALER_ADMIN_EMAIL"`);
    await queryRunner.query(`DROP INDEX "IDX_DEALER_STAFF_EMAIL"`);
    await queryRunner.query(`DROP INDEX "IDX_CUSTOMERS_EMAIL"`);
    await queryRunner.query(`DROP INDEX "IDX_SYSADMINS_EMAIL"`);
    await queryRunner.query(`DROP INDEX "IDX_ROOF_TOP_LOCATION_DEALER_ID"`);
    await queryRunner.query(`DROP INDEX "IDX_DEALER_ADMIN_DEALER_ID"`);
    await queryRunner.query(`DROP INDEX "IDX_DEALER_STAFF_DEALER_ID"`);
    await queryRunner.query(`DROP INDEX "IDX_DEALER_ADMIN_IS_PRIMARY"`);
    await queryRunner.query(`DROP INDEX "IDX_DEALER_ADMIN_IS_VERIFIED"`);
    await queryRunner.query(`DROP INDEX "IDX_DEALER_STAFF_IS_VERIFIED"`);
  }
}