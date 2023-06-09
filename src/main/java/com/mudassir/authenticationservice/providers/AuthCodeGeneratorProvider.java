package com.mudassir.authenticationservice.providers;

import com.mudassir.authenticationservice.models.User;
import java.util.UUID;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class AuthCodeGeneratorProvider {

  private final CodeWriterProvider codeWriterProvider;
  private final JwtTokenProvider jwtTokenProvider;

  public String provide(User user) {
    // TODO mfa check

    //           const codePayload: ClientAuthCode<User, typeof User.prototype.id> = {
    //                clientId: client.clientId,
    //                user: user,
    //      };
    //      const isMfaEnabled = await this.checkMfa(user);
    //        if (isMfaEnabled) {
    //            codePayload.mfa = true;
    //            if (
    //                    this.mfaConfig.secondFactor === STRATEGY.OTP &&
    //                            this.otpConfig.method === OtpMethodType.OTP
    //            ) {
    //                await this.otpService.sendOtp(user, client);
    //            }
    //        }
    String token = this.jwtTokenProvider.generateToken(user);
    return String.valueOf(this.codeWriterProvider.provide(token));
  }
}
