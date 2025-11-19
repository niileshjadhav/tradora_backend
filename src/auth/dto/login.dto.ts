import { IsEmail, IsString, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'john.doe@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsString()
  password: string;

  @ApiProperty({ 
    example: 'dealer-admin', 
    enum: ['dealer-admin', 'dealer-staff', 'customer', 'sysadmin'],
    description: 'User type to authenticate as'
  })
  @IsIn(['dealer-admin', 'dealer-staff', 'customer', 'sysadmin'])
  userType: 'dealer-admin' | 'dealer-staff' | 'customer' | 'sysadmin';
}