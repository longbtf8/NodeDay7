const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return email && emailRegex.test(email);
};
const isValidPassword = (password) => {
  // Ít nhất 6 ký tự
  return password && password.length >= 6;
};
module.exports = { isValidEmail, isValidPassword };
