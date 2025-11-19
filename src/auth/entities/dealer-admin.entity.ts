import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { Dealer } from '../../dealers/entities/dealer.entity';

@Entity('dealer_admin')
export class DealerAdmin {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'dealer_id', nullable: true })
  dealerId: number;

  @Column({ name: 'first_name', type: 'varchar', length: 100 })
  firstName: string;

  @Column({ name: 'last_name', type: 'varchar', length: 100 })
  lastName: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  email: string;

  @Column({ name: 'password_hash', type: 'varchar', length: 255 })
  passwordHash: string;

  @Column({ name: 'is_primary_admin', type: 'boolean', default: false })
  isPrimaryAdmin: boolean;

  @Column({ name: 'otp_code', type: 'varchar', length: 10, nullable: true })
  otpCode: string;

  @Column({ name: 'expires_at', type: 'timestamp', nullable: true })
  expiresAt: Date;

  @Column({ name: 'is_account_verified', type: 'boolean', default: false })
  isAccountVerified: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @ManyToOne(() => Dealer, dealer => dealer.dealerAdmins)
  @JoinColumn({ name: 'dealer_id' })
  dealer: Dealer;
}