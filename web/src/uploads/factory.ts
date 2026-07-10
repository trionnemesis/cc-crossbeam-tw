import "server-only";

import { parseRuntimeConfig } from "@/src/config/runtime";
import { AppStore } from "@/src/db/app-store";
import { getLocalDatabase } from "@/src/db/local";
import { UploadService } from "@/src/uploads/service";

export function getUploadService() {
  const config = parseRuntimeConfig(process.env);
  const database = getLocalDatabase(config);
  const appStore = new AppStore(database);
  return new UploadService(database, appStore, config);
}
