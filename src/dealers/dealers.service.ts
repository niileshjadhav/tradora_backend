import { Injectable, NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Dealer } from './entities/dealer.entity';
import { CreateDealerDto, UpdateDealerDto } from './dto/create-dealer.dto';
import { DealerAdmin } from '../auth/entities/dealer-admin.entity';

@Injectable()
export class DealersService {
  constructor(
    @InjectRepository(Dealer)
    private dealerRepository: Repository<Dealer>,
    @InjectRepository(DealerAdmin)
    private dealerAdminRepository: Repository<DealerAdmin>,
  ) {}

  async create(createDealerDto: CreateDealerDto) {
    // Check if dealer with same name already exists
    const existingDealer = await this.dealerRepository.findOne({
      where: { dealershipName: createDealerDto.dealershipName }
    });

    if (existingDealer) {
      throw new ConflictException('Dealer with this name already exists');
    }

    // Check if dealer with same email already exists
    const existingEmail = await this.dealerRepository.findOne({
      where: { businessEmail: createDealerDto.businessEmail }
    });

    if (existingEmail) {
      throw new ConflictException('Dealer with this email already exists');
    }

    const dealer = this.dealerRepository.create(createDealerDto);
    return await this.dealerRepository.save(dealer);
  }

  async createForDealerAdmin(createDealerDto: CreateDealerDto, adminId: number) {
    // Check if admin already has a dealer
    const admin = await this.dealerAdminRepository.findOne({ where: { id: adminId } });
    if (!admin) {
      throw new BadRequestException('Dealer admin not found');
    }

    if (admin.dealerId) {
      throw new BadRequestException('Dealer admin already has an associated dealer');
    }

    if (!admin.isPrimaryAdmin) {
      throw new BadRequestException('Only primary dealer-admin can create a dealer');
    }

    // Check if dealer with same name already exists
    const existingDealer = await this.dealerRepository.findOne({
      where: { dealershipName: createDealerDto.dealershipName }
    });

    if (existingDealer) {
      throw new ConflictException('Dealer with this name already exists');
    }

    // Check if dealer with same email already exists
    const existingEmail = await this.dealerRepository.findOne({
      where: { businessEmail: createDealerDto.businessEmail }
    });

    if (existingEmail) {
      throw new ConflictException('Dealer with this email already exists');
    }

    // Create dealer
    const dealer = this.dealerRepository.create(createDealerDto);
    const savedDealer = await this.dealerRepository.save(dealer);

    // Associate admin with the created dealer
    await this.dealerAdminRepository.update(adminId, { dealerId: savedDealer.id });

    return {
      ...savedDealer,
      message: 'Dealer created successfully and associated with your account'
    };
  }

  async findAll() {
    return await this.dealerRepository.find({
      select: {
        id: true,
        dealershipName: true,
        businessEmail: true,
        brandingLogo: true,
        colorTheme: true,
        website: true,
        phone: true,
        createdAt: true,
      },
      order: { createdAt: 'DESC' },
    });
  }

  async findOne(id: number) {
    const dealer = await this.dealerRepository.findOne({
      where: { id },
      select: {
        id: true,
        dealershipName: true,
        businessEmail: true,
        brandingLogo: true,
        colorTheme: true,
        website: true,
        phone: true,
        stripeCustomerId: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!dealer) {
      throw new NotFoundException(`Dealer with ID ${id} not found`);
    }

    return dealer;
  }

  async update(id: number, updateDealerDto: UpdateDealerDto) {
    const dealer = await this.findOne(id);

    // Check for name conflicts if name is being updated
    if (updateDealerDto.dealershipName && updateDealerDto.dealershipName !== dealer.dealershipName) {
      const existingName = await this.dealerRepository.findOne({
        where: { dealershipName: updateDealerDto.dealershipName }
      });
      if (existingName) {
        throw new ConflictException('Dealer with this name already exists');
      }
    }

    // Check for email conflicts if email is being updated
    if (updateDealerDto.businessEmail && updateDealerDto.businessEmail !== dealer.businessEmail) {
      const existingEmail = await this.dealerRepository.findOne({
        where: { businessEmail: updateDealerDto.businessEmail }
      });
      if (existingEmail) {
        throw new ConflictException('Dealer with this email already exists');
      }
    }

    await this.dealerRepository.update(id, updateDealerDto);
    return await this.findOne(id);
  }
}