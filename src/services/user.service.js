const UserModel = require("@/models/user.model");
const paginationService = require("./pagination.service");
class userService {
  model = UserModel;
  constructor() {
    paginationService.apply(this);
  }
  async findUserAsEmail(email, currentUserId) {
    const users = await UserModel.findAsEmail(email);
    // Loại bỏ user hiện tại
    const filteredUsers = users.filter((u) => u.id !== currentUserId);
    return filteredUsers;
  }
}
module.exports = new userService();
