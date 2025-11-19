import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DealerAdmin, DealerStaff, Customer, SysAdmin } from '../entities';

export interface JwtPayload {
  sub: number;
  email: string;
  userType: 'dealer-admin' | 'dealer-staff' | 'customer' | 'sysadmin';
}

export type AuthenticatedUser = (DealerAdmin | DealerStaff | Customer | SysAdmin) & {
  userType: 'dealer-admin' | 'dealer-staff' | 'customer' | 'sysadmin';
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    @InjectRepository(DealerAdmin)
    private dealerAdminRepository: Repository<DealerAdmin>,
    @InjectRepository(DealerStaff)
    private dealerStaffRepository: Repository<DealerStaff>,
    @InjectRepository(Customer)
    private customerRepository: Repository<Customer>,
    @InjectRepository(SysAdmin)
    private sysAdminRepository: Repository<SysAdmin>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET', 'your-secret-key-here'),
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    let user: DealerAdmin | DealerStaff | Customer | SysAdmin | null = null;

    switch (payload.userType) {
      case 'dealer-admin':
        user = await this.dealerAdminRepository.findOne({
          where: { id: payload.sub },
          relations: ['dealer'],
        });
        break;
      case 'dealer-staff':
        user = await this.dealerStaffRepository.findOne({
          where: { id: payload.sub },
          relations: ['dealer'],
        });
        break;
      case 'customer':
        user = await this.customerRepository.findOne({
          where: { id: payload.sub },
        });
        break;
      case 'sysadmin':
        user = await this.sysAdminRepository.findOne({
          where: { id: payload.sub },
        });
        break;
    }

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return { ...user, userType: payload.userType };
  }
}