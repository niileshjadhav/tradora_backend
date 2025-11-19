import { IsEmail, IsString, MinLength, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateDealerAdminDto {
  @ApiProperty({ example: 'admin@dealer.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'John' })
  @IsString()
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  @IsString()
  lastName: string;
}

export class CreateDealerStaffDto {
  @ApiProperty({ example: 'staff@dealer.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'Jane' })
  @IsString()
  firstName: string;

  @ApiProperty({ example: 'Smith' })
  @IsString()
  lastName: string;
}

export class CreatePrimaryDealerAdminDto {
  @ApiProperty({ example: 'primary@newdealer.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'John' })
  @IsString()
  firstName: string;

  @ApiProperty({ example: 'Admin' })
  @IsString()
  lastName: string;
}

export class VerifyOtpDto {
  @ApiProperty({ example: 'admin@dealer.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'abcd' })
  @IsString()
  otpCode: string;

  @ApiProperty({ example: 'dealer-admin', enum: ['dealer-admin', 'dealer-staff'] })
  @IsString()
  @IsIn(['dealer-admin', 'dealer-staff'])
  userType: 'dealer-admin' | 'dealer-staff';
}