import { ApiProperty } from '@nestjs/swagger';

export class AuthResponseDto {
  @ApiProperty()
  accessToken: string;

  @ApiProperty()
  user: {
    id: number;
    email: string;
    firstName: string;
    lastName: string;
    userType: 'dealer-admin' | 'dealer-staff' | 'customer' | 'sysadmin';
    dealer?: {
      id: number;
      dealershipName: string;
      businessEmail: string;
    };
    isPrimaryAdmin?: boolean; // Only for dealer-admin
  };
}

export class MessageResponseDto {
  @ApiProperty()
  message: string;
}