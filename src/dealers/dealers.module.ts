import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DealersService } from './dealers.service';
import { DealersController } from './dealers.controller';
import { Dealer } from './entities/dealer.entity';
import { DealerAdmin } from '../auth/entities/dealer-admin.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Dealer, DealerAdmin])],
  controllers: [DealersController],
  providers: [DealersService],
  exports: [DealersService],
})
export class DealersModule {}