import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, ParseIntPipe, ForbiddenException, NotFoundException, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { DealersService } from './dealers.service';
import { CreateDealerDto, UpdateDealerDto } from './dto/create-dealer.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { AuthenticatedUser } from '../auth/strategies/jwt.strategy';

@ApiTags('Dealers')
@Controller('dealers')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('JWT-auth')
export class DealersController {
  constructor(private readonly dealersService: DealersService) {}

  @Post('create-dealer')
  @ApiOperation({ summary: 'Create dealer for current dealer-admin user' })
  @ApiResponse({ status: 201, description: 'Dealer created successfully and associated with user.' })
  @ApiResponse({ status: 409, description: 'Dealer with this name/email already exists or user already has a dealer.' })
  @ApiResponse({ status: 403, description: 'Forbidden - dealer-admin access required.' })
  createMyDealer(@Body() createDealerDto: CreateDealerDto, @CurrentUser() user: AuthenticatedUser) {
    // Only dealer-admin can create their own dealer
    if (user.userType !== 'dealer-admin') {
      throw new ForbiddenException('Only dealer-admin can create their own dealer');
    }
    return this.dealersService.createForDealerAdmin(createDealerDto, user.id);
  }



  @Get()
  @ApiOperation({ summary: 'Get all dealers (sysadmin only)' })
  @ApiResponse({ status: 200, description: 'List of all dealers.' })
  @ApiResponse({ status: 403, description: 'Forbidden - sysadmin access required.' })
  findAll(@CurrentUser() user: AuthenticatedUser) {
    // Only sysadmin can see all dealers
    if (user.userType !== 'sysadmin') {
      throw new ForbiddenException('Only sysadmin can list all dealers');
    }
    return this.dealersService.findAll();
  }

  @Get('my-dealer')
  @ApiOperation({ summary: 'Get current user\'s dealer data (dealer-admin and dealer-staff only)' })
  @ApiResponse({ status: 200, description: 'Current user\'s dealer details.' })
  @ApiResponse({ status: 404, description: 'Dealer not found or user not associated with any dealer.' })
  @ApiResponse({ status: 403, description: 'Forbidden - dealer-admin or dealer-staff access required.' })
  getMyDealer(@CurrentUser() user: AuthenticatedUser) {
    // Only dealer-admin and dealer-staff can access their dealer data
    if (!['dealer-admin', 'dealer-staff'].includes(user.userType)) {
      throw new ForbiddenException('Dealer-admin or dealer-staff access required');
    }
    
    // Check if user is associated with a dealer
    if (!('dealerId' in user) || !user.dealerId) {
      return {
        message: 'No dealer associated with this user',
        hasDealer: false,
        dealer: null
      };
    }
    
    return this.dealersService.findOne(user.dealerId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get dealer by ID' })
  @ApiResponse({ status: 200, description: 'Dealer details.' })
  @ApiResponse({ status: 404, description: 'Dealer not found.' })
  findOne(@Param('id', ParseIntPipe) id: number, @CurrentUser() user: AuthenticatedUser) {
    // sysadmin can view any dealer, dealer-admin/staff can view their own dealer
    if (user.userType === 'sysadmin' || ('dealerId' in user && user.dealerId === id)) {
      return this.dealersService.findOne(id);
    }
    throw new ForbiddenException('You can only view your own dealer');
  }



  @Patch(':id')
  @ApiOperation({ summary: 'Update dealer (dealer-admin only)' })
  @ApiResponse({ status: 200, description: 'Dealer updated successfully.' })
  @ApiResponse({ status: 404, description: 'Dealer not found.' })
  @ApiResponse({ status: 409, description: 'Dealer with this name/email already exists.' })
  @ApiResponse({ status: 403, description: 'Forbidden - dealer-admin access required.' })
  update(
    @Param('id', ParseIntPipe) id: number, 
    @Body() updateDealerDto: UpdateDealerDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    // Only dealer-admin can update their own dealer
    if (user.userType !== 'dealer-admin' || !('dealerId' in user) || user.dealerId !== id) {
      throw new ForbiddenException('Only dealer-admin can update their own dealer');
    }
    return this.dealersService.update(id, updateDealerDto);
  }
}