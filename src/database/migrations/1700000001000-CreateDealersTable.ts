import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class CreateDealersTable1700000001000 implements MigrationInterface {
  name = 'CreateDealersTable1700000001000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'dealers',
        columns: [
          {
            name: 'id',
            type: 'serial',
            isPrimary: true,
          },
          {
            name: 'dealership_name',
            type: 'varchar',
            length: '255',
          },
          {
            name: 'branding_logo',
            type: 'varchar',
            length: '500',
            isNullable: true,
          },
          {
            name: 'color_theme',
            type: 'varchar',
            length: '100',
            isNullable: true,
          },
          {
            name: 'business_email',
            type: 'varchar',
            length: '255',
            isUnique: true,
          },
          {
            name: 'website',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'phone',
            type: 'varchar',
            length: '50',
            isNullable: true,
          },
          {
            name: 'stripe_customer_id',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            onUpdate: 'CURRENT_TIMESTAMP',
          },
        ],
      }),
      true,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('dealers');
  }
}