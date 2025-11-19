import { Controller, Post, Body, UseGuards, Get, HttpCode, HttpStatus, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { 
  DealerAdminSignupDto,
  DealerStaffSignupDto,
  CustomerSignupDto,
  AuthResponseDto,
  CreateDealerAdminDto,
  CreateDealerStaffDto,
  CreatePrimaryDealerAdminDto,
  VerifyOtpDto,
} from './dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Public } from './decorators/public.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { AuthenticatedUser } from './strategies/jwt.strategy';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('signup/dealer-admin')
  @ApiOperation({ summary: 'Dealer admin registration - only first dealer admin can create dealer later' })
  @ApiResponse({ 
    status: 201, 
    description: 'Dealer admin successfully registered',
    type: AuthResponseDto 
  })
  @ApiResponse({ 
    status: 409, 
    description: 'Email already exists' 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - validation errors' 
  })
  async dealerAdminSignUp(@Body() signUpDto: DealerAdminSignupDto): Promise<AuthResponseDto> {
    return this.authService.dealerAdminSignUp(signUpDto);
  }

  @Public()
  @Post('signup/customer')
  @ApiOperation({ summary: 'Customer registration' })
  @ApiResponse({ 
    status: 201, 
    description: 'Customer successfully registered',
    type: AuthResponseDto 
  })
  @ApiResponse({ 
    status: 409, 
    description: 'Email already exists' 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - validation errors' 
  })
  async customerSignUp(@Body() signUpDto: CustomerSignupDto): Promise<AuthResponseDto> {
    return this.authService.customerSignUp(signUpDto);
  }

  @Public()
  @Post('signup/dealer-staff')
  @ApiOperation({ summary: 'Dealer staff registration' })
  @ApiResponse({ 
    status: 201, 
    description: 'Dealer staff successfully registered',
    type: AuthResponseDto 
  })
  @ApiResponse({ 
    status: 409, 
    description: 'Email already exists' 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - validation errors or invalid dealer ID' 
  })
  async dealerStaffSignUp(@Body() signUpDto: DealerStaffSignupDto): Promise<AuthResponseDto> {
    return this.authService.dealerStaffSignUp(signUpDto);
  }



  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User login with user type' })
  @ApiResponse({ 
    status: 200, 
    description: 'User successfully authenticated',
    type: AuthResponseDto 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Invalid credentials' 
  })
  async login(@Body() loginDto: LoginDto): Promise<AuthResponseDto> {
    return this.authService.login(loginDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ 
    status: 200, 
    description: 'User profile retrieved successfully' 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Unauthorized - invalid or missing token' 
  })
  async getProfile(@CurrentUser() user: AuthenticatedUser) {
    const response: any = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      userType: user.userType,
      createdAt: user.createdAt,
    };

    // Add dealer info for dealer-admin and dealer-staff
    if ((user.userType === 'dealer-admin' || user.userType === 'dealer-staff') && 'dealer' in user && user.dealer) {
      response.dealer = {
        id: user.dealer.id,
        dealershipName: user.dealer.dealershipName,
        businessEmail: user.dealer.businessEmail,
      };
    }

    // Add isPrimaryAdmin for dealer-admin
    if (user.userType === 'dealer-admin' && 'isPrimaryAdmin' in user) {
      response.isPrimaryAdmin = user.isPrimaryAdmin;
    }

    return response;
  }

  @UseGuards(JwtAuthGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ 
    status: 200, 
    description: 'Token refreshed successfully',
    type: AuthResponseDto 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Unauthorized - invalid or missing token' 
  })
  async refreshToken(@CurrentUser() user: AuthenticatedUser): Promise<AuthResponseDto> {
    return this.authService.refreshToken(user, user.userType);
  }

  @UseGuards(JwtAuthGuard)
  @Post('create-dealer-admin')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Create new dealer admin (primary dealer-admin only)' })
  @ApiResponse({ 
    status: 201, 
    description: 'Dealer admin created successfully'
  })
  @ApiResponse({ 
    status: 409, 
    description: 'Email already exists' 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - validation errors or insufficient permissions' 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Unauthorized - invalid or missing token' 
  })
  async createDealerAdmin(
    @Body() createDto: CreateDealerAdminDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    if (user.userType !== 'dealer-admin') {
      throw new BadRequestException('Only dealer-admin can create new dealer admins');
    }
    
    return this.authService.createDealerAdminByAdmin(createDto, user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Post('create-dealer-staff')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Create new dealer staff (dealer-admin only)' })
  @ApiResponse({ 
    status: 201, 
    description: 'Dealer staff created successfully'
  })
  @ApiResponse({ 
    status: 409, 
    description: 'Email already exists' 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - validation errors or insufficient permissions' 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Unauthorized - invalid or missing token' 
  })
  async createDealerStaff(
    @Body() createDto: CreateDealerStaffDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    if (user.userType !== 'dealer-admin') {
      throw new BadRequestException('Only dealer-admin can create dealer staff');
    }
    
    return this.authService.createDealerStaffByAdmin(createDto, user.id);
  }

  @Public()
  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify OTP for dealer-admin or dealer-staff account' })
  @ApiResponse({ 
    status: 200, 
    description: 'OTP verified successfully and account activated',
    type: AuthResponseDto 
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Bad request - invalid or expired OTP' 
  })
  @ApiResponse({ 
    status: 401, 
    description: 'Unauthorized - invalid OTP code or user not found' 
  })
  async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto): Promise<AuthResponseDto> {
    return this.authService.verifyOtp(verifyOtpDto);
  }
}