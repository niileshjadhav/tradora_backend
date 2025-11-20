import { IsEmail, IsString, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class InviteAdminStaffDto {
  @ApiProperty({ example: 'user@dealer.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'John' })
  @IsString()
  firstName: string;

  @ApiProperty({ example: 'Doe' })
  @IsString()
  lastName: string;

  @ApiProperty({ example: 'dealer-admin', enum: ['dealer-admin', 'dealer-staff'] })
  @IsString()
  @IsIn(['dealer-admin', 'dealer-staff'])
  userType: 'dealer-admin' | 'dealer-staff';
}