import { Injectable, ConflictException, UnauthorizedException, BadRequestException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { DealerAdmin, DealerStaff, Customer, SysAdmin } from './entities';
import { Dealer } from '../dealers/entities/dealer.entity';
import { 
  DealerAdminSignupDto,
  DealerStaffSignupDto,
  CustomerSignupDto,
  CreateDealerAdminDto,
  CreateDealerStaffDto,
  CreatePrimaryDealerAdminDto,
  VerifyOtpDto
} from './dto';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './strategies/jwt.strategy';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(DealerAdmin)
    private dealerAdminRepository: Repository<DealerAdmin>,
    @InjectRepository(DealerStaff)
    private dealerStaffRepository: Repository<DealerStaff>,
    @InjectRepository(Customer)
    private customerRepository: Repository<Customer>,
    @InjectRepository(SysAdmin)
    private sysAdminRepository: Repository<SysAdmin>,
    @InjectRepository(Dealer)
    private dealerRepository: Repository<Dealer>,
    private jwtService: JwtService,
  ) {}

  async dealerAdminSignUp(signUpDto: DealerAdminSignupDto) {
    const { email, password, firstName, lastName } = signUpDto;

    await this.checkEmailExists(email);

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Set OTP and expiry (60 seconds)
    const otpCode = 'abcd';
    const expiresAt = new Date(Date.now() + 60 * 1000);

    // Create dealer-admin
    const dealerAdmin = this.dealerAdminRepository.create({
      email,
      passwordHash: hashedPassword,
      firstName,
      lastName,
      isPrimaryAdmin: true,
      dealerId: null,
      otpCode,
      expiresAt,
      isAccountVerified: false,
    });

    const savedDealerAdmin = await this.dealerAdminRepository.save(dealerAdmin);

    return this.generateAuthResponse(savedDealerAdmin, 'dealer-admin');
  }

  async customerSignUp(signUpDto: CustomerSignupDto) {
    const { email, password, firstName, lastName } = signUpDto;

    // Check if email already exists across all user types
    await this.checkEmailExists(email);

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Create customer
    const customer = this.customerRepository.create({
      email,
      passwordHash: hashedPassword,
      firstName,
      lastName,
    });

    const savedCustomer = await this.customerRepository.save(customer);

    return this.generateAuthResponse(savedCustomer, 'customer');
  }

  async dealerStaffSignUp(signUpDto: DealerStaffSignupDto) {
    const { email, password, firstName, lastName, dealerId } = signUpDto;

    // Check if email already exists across all user types
    await this.checkEmailExists(email);

    // Verify dealer exists
    const dealer = await this.dealerRepository.findOne({ where: { id: dealerId } });
    if (!dealer) {
      throw new BadRequestException('Invalid dealer ID');
    }

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Set OTP and expiry (60 seconds from now)
    const otpCode = 'abcd';
    const expiresAt = new Date(Date.now() + 60 * 1000); // 60 seconds

    // Create dealer-staff
    const dealerStaff = this.dealerStaffRepository.create({
      email,
      passwordHash: hashedPassword,
      firstName,
      lastName,
      dealerId,
      otpCode,
      expiresAt,
      isAccountVerified: false,
    });

    const savedDealerStaff = await this.dealerStaffRepository.save(dealerStaff);
    
    // Load with dealer relation
    const staffWithDealer = await this.dealerStaffRepository.findOne({
      where: { id: savedDealerStaff.id },
      relations: ['dealer'],
    });

    return this.generateAuthResponse(staffWithDealer, 'dealer-staff');
  }

  async login(loginDto: LoginDto) {
    const { email, password, userType } = loginDto;

    let user: DealerAdmin | DealerStaff | Customer | SysAdmin | null = null;

    // Find user based on type
    switch (userType) {
      case 'dealer-admin':
        user = await this.dealerAdminRepository.findOne({
          where: { email },
          relations: ['dealer'],
        });
        break;
      case 'dealer-staff':
        user = await this.dealerStaffRepository.findOne({
          where: { email },
          relations: ['dealer'],
        });
        break;
      case 'customer':
        user = await this.customerRepository.findOne({
          where: { email },
        });
        break;
      case 'sysadmin':
        user = await this.sysAdminRepository.findOne({
          where: { email },
        });
        break;
    }

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if account is verified for dealer-admin and dealer-staff
    if ((userType === 'dealer-admin' || userType === 'dealer-staff') && 'isAccountVerified' in user && !user.isAccountVerified) {
      throw new UnauthorizedException('Account not verified. Please verify your OTP first.');
    }

    return this.generateAuthResponse(user, userType);
  }

  async refreshToken(user: any, userType: 'dealer-admin' | 'dealer-staff' | 'customer' | 'sysadmin') {
    return this.generateAuthResponse(user, userType);
  }

  async createDealerForAdmin(dealerId: number, adminId: number) {
    // Associate dealer-admin with dealer
    await this.dealerAdminRepository.update(adminId, { dealerId });
    
    // Get updated admin with dealer info
    const adminWithDealer = await this.dealerAdminRepository.findOne({
      where: { id: adminId },
      relations: ['dealer'],
    });

    return adminWithDealer;
  }

  async createDealerAdminByAdmin(createDto: CreateDealerAdminDto, creatingAdminId: number) {
    const { email, password, firstName, lastName } = createDto;

    // Verify the creating admin exists and has a dealer associated
    const creatingAdmin = await this.dealerAdminRepository.findOne({
      where: { id: creatingAdminId },
      relations: ['dealer'],
    });

    if (!creatingAdmin) {
      throw new BadRequestException('Creating admin not found');
    }

    if (!creatingAdmin.dealerId || !creatingAdmin.dealer) {
      throw new BadRequestException('Creating admin must have a dealer associated to create other admins');
    }

    if (!creatingAdmin.isPrimaryAdmin) {
      throw new BadRequestException('Only primary dealer-admin can create new dealer-admins');
    }

    // Ensure we don't create another primary admin for the same dealer
    const existingPrimaryForDealer = await this.dealerAdminRepository.findOne({
      where: { dealerId: creatingAdmin.dealerId, isPrimaryAdmin: true }
    });
    if (existingPrimaryForDealer && existingPrimaryForDealer.id !== creatingAdmin.id) {
      throw new BadRequestException('This dealer already has a primary admin');
    }

    // Check if email already exists across all user types
    await this.checkEmailExists(email);

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Set OTP and expiry (60 seconds from now)
    const otpCode = 'abcd';
    const expiresAt = new Date(Date.now() + 60 * 1000); // 60 seconds

    // Create dealer-admin (not primary)
    const dealerAdmin = this.dealerAdminRepository.create({
      email,
      passwordHash: hashedPassword,
      firstName,
      lastName,
      isPrimaryAdmin: false,
      dealerId: creatingAdmin.dealerId,
      otpCode,
      expiresAt,
      isAccountVerified: false,
    });

    const savedDealerAdmin = await this.dealerAdminRepository.save(dealerAdmin);

    // Load with dealer relation
    const adminWithDealer = await this.dealerAdminRepository.findOne({
      where: { id: savedDealerAdmin.id },
      relations: ['dealer'],
    });

    return {
      userType: adminWithDealer,
      message: 'Dealer admin created successfully'
    };
  }

  async createDealerStaffByAdmin(createDto: CreateDealerStaffDto, creatingAdminId: number) {
    const { email, password, firstName, lastName } = createDto;

    // Verify the creating admin exists and has a dealer associated
    const creatingAdmin = await this.dealerAdminRepository.findOne({
      where: { id: creatingAdminId },
      relations: ['dealer'],
    });

    if (!creatingAdmin) {
      throw new BadRequestException('Creating admin not found');
    }

    if (!creatingAdmin.dealerId || !creatingAdmin.dealer) {
      throw new BadRequestException('Creating admin must have a dealer associated to create staff members');
    }

    // Check if email already exists across all user types
    await this.checkEmailExists(email);

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Set OTP and expiry (60 seconds from now)
    const otpCode = 'abcd';
    const expiresAt = new Date(Date.now() + 60 * 1000); // 60 seconds

    // Create dealer-staff
    const dealerStaff = this.dealerStaffRepository.create({
      email,
      passwordHash: hashedPassword,
      firstName,
      lastName,
      dealerId: creatingAdmin.dealerId,
      otpCode,
      expiresAt,
      isAccountVerified: false,
    });

    const savedDealerStaff = await this.dealerStaffRepository.save(dealerStaff);

    // Load with dealer relation
    const staffWithDealer = await this.dealerStaffRepository.findOne({
      where: { id: savedDealerStaff.id },
      relations: ['dealer'],
    });

    return {
      userType: staffWithDealer,
      message: 'Dealer staff created successfully'
    };
  }

  async verifyOtp(verifyOtpDto: VerifyOtpDto) {
    const { email, otpCode, userType } = verifyOtpDto;

    let user: DealerAdmin | DealerStaff | null = null;

    // Find user based on type
    if (userType === 'dealer-admin') {
      user = await this.dealerAdminRepository.findOne({
        where: { email },
        relations: ['dealer'],
      });
    } else if (userType === 'dealer-staff') {
      user = await this.dealerStaffRepository.findOne({
        where: { email },
        relations: ['dealer'],
      });
    }

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.isAccountVerified) {
      throw new BadRequestException('Account is already verified');
    }

    if (!user.otpCode || !user.expiresAt) {
      throw new BadRequestException('No OTP found for this account');
    }

    if (new Date() > user.expiresAt) {
      throw new BadRequestException('OTP has expired');
    }

    if (user.otpCode !== otpCode) {
      throw new UnauthorizedException('Invalid OTP code');
    }

    // Verify account and clear OTP
    if (userType === 'dealer-admin') {
      await this.dealerAdminRepository.update(user.id, {
        isAccountVerified: true,
        otpCode: null,
        expiresAt: null,
      });
      // Update the user object with verified status
      user.isAccountVerified = true;
    } else {
      await this.dealerStaffRepository.update(user.id, {
        isAccountVerified: true,
        otpCode: null,
        expiresAt: null,
      });
      // Update the user object with verified status
      user.isAccountVerified = true;
    }

    return this.generateAuthResponse(user, userType);
  }

  async createPrimaryDealerAdmin(createDto: CreatePrimaryDealerAdminDto) {
    const { email, password, firstName, lastName } = createDto;

    // Check if email already exists across all user types
    await this.checkEmailExists(email);

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Set OTP and expiry (60 seconds from now)
    const otpCode = 'abcd';
    const expiresAt = new Date(Date.now() + 60 * 1000); // 60 seconds

    // Create primary dealer-admin (no dealer yet)
    const dealerAdmin = this.dealerAdminRepository.create({
      email,
      passwordHash: hashedPassword,
      firstName,
      lastName,
      isPrimaryAdmin: true,
      dealerId: null, // Will be set when they create their dealer
      otpCode,
      expiresAt,
      isAccountVerified: false,
    });

    const savedDealerAdmin = await this.dealerAdminRepository.save(dealerAdmin);

    return this.generateAuthResponse(savedDealerAdmin, 'dealer-admin');
  }

  // Helper methods
  private async checkEmailExists(email: string): Promise<void> {
    const [dealerAdmin, dealerStaff, customer, sysAdmin] = await Promise.all([
      this.dealerAdminRepository.findOne({ where: { email } }),
      this.dealerStaffRepository.findOne({ where: { email } }),
      this.customerRepository.findOne({ where: { email } }),
      this.sysAdminRepository.findOne({ where: { email } }),
    ]);

    if (dealerAdmin || dealerStaff || customer || sysAdmin) {
      throw new ConflictException('Email already exists');
    }
  }

  private async hashPassword(password: string): Promise<string> {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
  }

  private generateAuthResponse(user: any, userType: 'dealer-admin' | 'dealer-staff' | 'customer' | 'sysadmin') {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      userType,
    };

    const responseUser: any = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      userType,
    };

    // Add dealer info for dealer-admin and dealer-staff
    if ((userType === 'dealer-admin' || userType === 'dealer-staff') && user.dealer) {
      responseUser.dealer = {
        id: user.dealer.id,
        dealershipName: user.dealer.dealershipName,
        businessEmail: user.dealer.businessEmail,
      };
    }

    // Add isPrimaryAdmin for dealer-admin
    if (userType === 'dealer-admin') {
      responseUser.isPrimaryAdmin = user.isPrimaryAdmin;
    }

    // Add isAccountVerified for dealer-admin and dealer-staff
    if (userType === 'dealer-admin' || userType === 'dealer-staff') {
      responseUser.isAccountVerified = user.isAccountVerified;
    }

    return {
      accessToken: this.jwtService.sign(payload),
      user: responseUser,
    };
  }
}