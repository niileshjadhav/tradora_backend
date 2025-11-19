import { IsEmail, IsString, MinLength, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SetPasswordDto {
  @ApiProperty({ example: 'admin@dealer.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'dealer-admin', enum: ['dealer-admin', 'dealer-staff'] })
  @IsString()
  @IsIn(['dealer-admin', 'dealer-staff'])
  userType: 'dealer-admin' | 'dealer-staff';
}

export class VerifyOtpAndSetPasswordDto {
  @ApiProperty({ example: 'admin@dealer.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'abcd' })
  @IsString()
  otpCode: string;

  @ApiProperty({ example: 'password123' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'dealer-admin', enum: ['dealer-admin', 'dealer-staff'] })
  @IsString()
  @IsIn(['dealer-admin', 'dealer-staff'])
  userType: 'dealer-admin' | 'dealer-staff';
}