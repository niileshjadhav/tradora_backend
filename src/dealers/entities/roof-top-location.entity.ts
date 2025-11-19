import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { Dealer } from '../../dealers/entities/dealer.entity';

@Entity('roof_top_location')
export class RoofTopLocation {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'dealer_id' })
  dealerId: number;

  @Column({ name: 'business_email', type: 'varchar', length: 255, unique: true })
  businessEmail: string;

  @Column({ type: 'varchar', length: 255 })
  branch: string;

  @Column({ type: 'varchar', length: 500 })
  address: string;

  @Column({ type: 'varchar', length: 100 })
  city: string;

  @Column({ type: 'varchar', length: 100 })
  state: string;

  @Column({ type: 'varchar', length: 20 })
  zip: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @ManyToOne(() => Dealer, dealer => dealer.roofTopLocations)
  @JoinColumn({ name: 'dealer_id' })
  dealer: Dealer;
}