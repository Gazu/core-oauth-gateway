import type { ServiceInfoDto } from "@/oauth/application/dto/service-info.dto";

export class GetServiceInfoUseCase {
  constructor(private readonly serviceInfo: ServiceInfoDto) {}

  execute(): ServiceInfoDto {
    return this.serviceInfo;
  }
}
