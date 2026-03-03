const constants = require("@/config/constants");
const db = require("@/config/database");

class QueueService {
  async push(type, payload) {
    const jsonPayLoad = JSON.stringify(payload);
    await db.query("insert into queues (type,payload) values (?,?)", [
      type,
      jsonPayLoad,
    ]);
  }
  async getPendingJob() {
    const [rows] = await db.query(
      "select * from queues where status =? order by id limit 1",
      [constants.jobStatus.pending],
    );
    const firstJob = rows[0];
    return firstJob ?? null;
  }
  async updateStatus(id, status) {
    await db.query("update queues set status =? where id =?", [status, id]);
  }
}
module.exports = new QueueService();
