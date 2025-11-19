import { MigrationInterface, QueryRunner } from 'typeorm';
import * as bcrypt from 'bcrypt';

export class SeedSysAdminData1700000008000 implements MigrationInterface {
  name = 'SeedSysAdminData1700000008000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // First, clear any existing sys admin data to ensure we only have the specified 2 admins
    await queryRunner.query('DELETE FROM sysadmins');

    // Hash the password 'admin@123'
    const passwordHash = await bcrypt.hash('admin@123', 10);

    // Insert the two sys admins
    await queryRunner.query(`
      INSERT INTO sysadmins (email, password_hash, first_name, last_name, created_at, updated_at)
      VALUES 
        ('floris.chaumat@icloud.com', $1, 'Floris', 'C', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
        ('watsteinpd@hotmail.com', $1, 'Philip', 'S', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `, [passwordHash]);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Remove the seeded sys admin data
    await queryRunner.query(`
      DELETE FROM sysadmins 
      WHERE email IN ('floris.chaumat@icloud.com', 'watsteinpd@hotmail.com')
    `);
  }
}