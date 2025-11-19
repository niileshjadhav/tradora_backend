import { IsEmail, IsString, MinLength, IsOptional, IsIn, Allow } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SignUpDto {
  @ApiProperty({ example: 'john.doe@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password123' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ 
    example: 'customer', 
    required: false, 
    enum: ['customer', 'dealer-admin'],
    description: 'User role. Only customer and dealer-admin allowed for signup. Only dealer-admin can create dealer entities later.'
  })
  @IsOptional()
  @IsIn(['customer', 'dealer-admin'])
  roleName?: 'customer' | 'dealer-admin';
}