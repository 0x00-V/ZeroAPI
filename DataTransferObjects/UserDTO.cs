using ZeroAPI.Models;

namespace ZeroAPI.DTOs
{
    public class UserDTO
    {
        public int Id {get; set;}
        public string? Name {get; set;}
        public UserDTO(){}
        public UserDTO(User userObj) => (Id, Name) = (userObj.Id, userObj.Name);
    }

    public class UserCreateDTO
    {
        public string? Name {get; set;}
        public string? Password {get; set;}

        public UserCreateDTO(){}
        public UserCreateDTO(User userObj) => (Name, Password) = (userObj.Name, userObj.Password);
    }
}