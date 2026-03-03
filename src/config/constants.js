const constants = {
  httpCodes: {
    success: 200,
    created: 201,
    conflict: 409,
    forbidden: 403,
    unprocessableEntity: 422,
    badRequest: 400,
  },
  errCodes: {},
  jobStatus: {
    pending: "pending",
    inprogress: "inprogress",
    completed: "completed",
    failed: "failed",
  },
};
module.exports = constants;
