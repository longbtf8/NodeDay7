class PaginationService {
  apply(service) {
    if (!service.model) {
      throw Error("Model is required for pagination ");
    }
    service.pagination = async (page, limit = 10, condition = {}) => {
      const offset = (page - 1) * limit;
      const rows = await service.model.findAll(limit, offset, condition);
      const total = await service.model.count();
      const pagination = {
        current_page: page,
        total: total,
        per_page: limit,
      };
      if (rows.length) {
        ((pagination.from = offset + 1),
          (pagination.to = offset + rows.length));
      }
      return {
        rows,
        pagination,
      };
    };
  }
  //   async apply(model, page = 1, limit = 20) {
  //     // const limit = 10;
  //     const offset = (page - 1) * limit;
  //     const rows = await model.findAll(limit, offset);
  //     const total = await model.count();
  //     const pagination = {
  //       current_page: page,
  //       total: total,
  //       per_page: limit,
  //     };
  //     if (rows.length) {
  //       ((pagination.from = offset + 1), (pagination.to = offset + rows.length));
  //     }
  //     return {
  //       rows,
  //       pagination,
  //     };
  //   }
}
module.exports = new PaginationService();
