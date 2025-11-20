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
  InviteAdminStaffDto,
  SetPasswordDto,
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

  async createUserByEmail(createDto: InviteAdminStaffDto, creatingAdminId: number) {
    const { email, firstName, lastName, userType } = createDto;

    // Verify the creating admin exists and has a dealer associated
    const creatingAdmin = await this.dealerAdminRepository.findOne({
      where: { id: creatingAdminId },
      relations: ['dealer'],
    });

    if (!creatingAdmin) {
      throw new BadRequestException('Creating admin not found');
    }

    if (!creatingAdmin.dealerId || !creatingAdmin.dealer) {
      throw new BadRequestException('Creating admin must have a dealer associated to create users');
    }

    if (!creatingAdmin.isPrimaryAdmin) {
      throw new BadRequestException('Only primary dealer-admin can create new users');
    }

    // Check if email already exists across all user types
    await this.checkEmailExists(email);

    // Set OTP and expiry (60 seconds from now)
    const otpCode = 'abcd';
    const expiresAt = new Date(Date.now() + 60 * 1000); // 60 seconds

    let savedUser: any;
    let userEntity: any;

    if (userType === 'dealer-admin') {
      // Create dealer-admin without password (not primary)
      userEntity = this.dealerAdminRepository.create({
        email,
        passwordHash: '', // Empty password hash - will be set later
        firstName,
        lastName,
        isPrimaryAdmin: false,
        dealerId: creatingAdmin.dealerId,
        otpCode,
        expiresAt,
        isAccountVerified: false,
      });

      savedUser = await this.dealerAdminRepository.save(userEntity);

      // Load with dealer relation
      savedUser = await this.dealerAdminRepository.findOne({
        where: { id: savedUser.id },
        relations: ['dealer'],
      });
    } else {
      // Create dealer-staff without password
      userEntity = this.dealerStaffRepository.create({
        email,
        passwordHash: '', // Empty password hash - will be set later
        firstName,
        lastName,
        dealerId: creatingAdmin.dealerId,
        otpCode,
        expiresAt,
        isAccountVerified: false,
      });

      savedUser = await this.dealerStaffRepository.save(userEntity);

      // Load with dealer relation
      savedUser = await this.dealerStaffRepository.findOne({
        where: { id: savedUser.id },
        relations: ['dealer'],
      });
    }

    return {
      user: {
        id: savedUser.id,
        email: savedUser.email,
        firstName: savedUser.firstName,
        lastName: savedUser.lastName,
        userType: userType,
        dealer: savedUser.dealer ? {
          id: savedUser.dealer.id,
          dealershipName: savedUser.dealer.dealershipName,
          businessEmail: savedUser.dealer.businessEmail,
        } : null,
      },
      message: `${userType === 'dealer-admin' ? 'Dealer admin' : 'Dealer staff'} created successfully. OTP sent for password setup.`
    };
  }



  async setPassword(setPasswordDto: SetPasswordDto) {
    const { email, password, userType } = setPasswordDto;

    let user: DealerAdmin | DealerStaff | null = null;

    // Find user based on type
    if (userType === 'dealer-admin') {
      user = await this.dealerAdminRepository.findOne({
        where: { email },
      });
    } else if (userType === 'dealer-staff') {
      user = await this.dealerStaffRepository.findOne({
        where: { email },
      });
    }

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.isAccountVerified) {
      throw new BadRequestException('Account is already verified. Use login to access your account.');
    }

    // Hash the new password
    const hashedPassword = await this.hashPassword(password);

    // Set new OTP and expiry (60 seconds from now)
    const otpCode = 'abcd';
    const expiresAt = new Date(Date.now() + 60 * 1000); // 60 seconds

    // Update user with new password and OTP
    if (userType === 'dealer-admin') {
      await this.dealerAdminRepository.update(user.id, {
        passwordHash: hashedPassword,
        otpCode,
        expiresAt,
      });
    } else {
      await this.dealerStaffRepository.update(user.id, {
        passwordHash: hashedPassword,
        otpCode,
        expiresAt,
      });
    }

    return {
      message: 'Password updated successfully. OTP sent for verification.'
    };
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