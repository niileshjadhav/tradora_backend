import { IsString, IsEmail, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateDealerDto {
  @ApiProperty({ example: 'ABC Motors' })
  @IsString()
  dealershipName: string;

  @ApiProperty({ example: 'business@abcmotors.com' })
  @IsEmail()
  businessEmail: string;

  @ApiProperty({ example: 'https://example.com/logo.png', required: false })
  @IsOptional()
  @IsString()
  brandingLogo?: string;

  @ApiProperty({ example: '#1E40AF', required: false })
  @IsOptional()
  @IsString()
  colorTheme?: string;

  @ApiProperty({ example: 'https://abcmotors.com', required: false })
  @IsOptional()
  @IsString()
  website?: string;

  @ApiProperty({ example: '555-123-4567', required: false })
  @IsOptional()
  @IsString()
  phone?: string;

  @ApiProperty({ example: 'cus_stripe_customer_id', required: false })
  @IsOptional()
  @IsString()
  stripeCustomerId?: string;
}

export class UpdateDealerDto {
  @ApiProperty({ example: 'ABC Motors Updated', required: false })
  @IsOptional()
  @IsString()
  dealershipName?: string;

  @ApiProperty({ example: 'newbusiness@abcmotors.com', required: false })
  @IsOptional()
  @IsEmail()
  businessEmail?: string;

  @ApiProperty({ example: 'https://example.com/new-logo.png', required: false })
  @IsOptional()
  @IsString()
  brandingLogo?: string;

  @ApiProperty({ example: '#DC2626', required: false })
  @IsOptional()
  @IsString()
  colorTheme?: string;

  @ApiProperty({ example: 'https://newabcmotors.com', required: false })
  @IsOptional()
  @IsString()
  website?: string;

  @ApiProperty({ example: '555-987-6543', required: false })
  @IsOptional()
  @IsString()
  phone?: string;

  @ApiProperty({ example: 'cus_new_stripe_customer_id', required: false })
  @IsOptional()
  @IsString()
  stripeCustomerId?: string;
}