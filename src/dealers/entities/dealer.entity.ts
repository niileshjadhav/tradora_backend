import { Entity, PrimaryGeneratedColumn, Column, OneToMany, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { DealerAdmin } from '../../auth/entities/dealer-admin.entity';
import { DealerStaff } from '../../auth/entities/dealer-staff.entity';
import { RoofTopLocation } from './roof-top-location.entity';

@Entity('dealers')
export class Dealer {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'dealership_name', type: 'varchar', length: 255 })
  dealershipName: string;

  @Column({ name: 'branding_logo', type: 'varchar', length: 500, nullable: true })
  brandingLogo: string;

  @Column({ name: 'color_theme', type: 'varchar', length: 100, nullable: true })
  colorTheme: string;

  @Column({ name: 'business_email', type: 'varchar', length: 255, unique: true })
  businessEmail: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  website: string;

  @Column({ type: 'varchar', length: 50, nullable: true })
  phone: string;

  @Column({ name: 'stripe_customer_id', type: 'varchar', length: 255, nullable: true })
  stripeCustomerId: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => DealerAdmin, dealerAdmin => dealerAdmin.dealer)
  dealerAdmins: DealerAdmin[];

  @OneToMany(() => DealerStaff, dealerStaff => dealerStaff.dealer)
  dealerStaff: DealerStaff[];

  @OneToMany(() => RoofTopLocation, location => location.dealer)
  roofTopLocations: RoofTopLocation[];
}