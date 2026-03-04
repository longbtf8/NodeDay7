require("module-alias/register");
require("dotenv").config();

const { jobStatus } = require("@/config/constants");
const tasks = require("@/tasks");
const queueService = require("@/services/queue.service");
const sleep = require("@/utils/sleep");

(async () => {
  while (true) {
    const firstJob = await queueService.getPendingJob();
    if (firstJob) {
      const { id, type, payload: jsonPayload } = firstJob;
      console.log("Job found:", firstJob);
      try {
        const payload = JSON.parse(jsonPayload);

        //update status :"inprogress"
        queueService.updateStatus(id, jobStatus.inprogress);

        console.log(tasks[type]);
        const handle = tasks[type];
        if (handle) {
          await handle(payload);
        } else {
          console.log("Chưa có logic sử lý cho job", type);
        }
        queueService.updateStatus(id, jobStatus.completed);
      } catch (error) {
        queueService.updateStatus(id, jobStatus.failed);
      }
    }
    await sleep(3000);
  }
})();
