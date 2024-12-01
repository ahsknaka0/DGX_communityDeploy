    import { useState, useContext, useEffect } from 'react';
    import ApiContext from '../../context/ApiContext';

    const AdminUsers = () => {
      const { fetchData } = useContext(ApiContext);
      const [users, setUsers] = useState([]);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState(null);

      // Fetch users on component load
      useEffect(() => {
        const fetchUsers = async () => {
          const endpoint = "user/users";    
          const method = "GET";
          const headers = {
            'Content-Type': 'application/json',
          };

          try {
            const result = await fetchData(endpoint, method, {}, headers);
            console.log
            if (result.success) {
              setUsers(result.data);
            } else {
              setError(result.message || 'Failed to fetch user data');
            }
          } catch (error) {
            console.error("Error fetching users:", error);
            setError('Failed to fetch user data');
          } finally {
            setLoading(false);
          }
        };

        fetchUsers();
      }, [fetchData]);

      // Handle user deletion
      // const handleDelete = async (userId) => {
      //   const endpoint = `user/users`;  // Assuming the DELETE API path is /user/users
      //   const method = 'DELETE';
      //   const headers = {
      //     'Content-Type': 'application/json',
      //   };
      //   const body = JSON.stringify({ userId });

      //   try {
      //     const result = await fetchData(endpoint, method, body, headers);
      //     if (result.success) {
      //       setUsers(users.filter((user) => user.UserID !== userId)); // Remove deleted user from state
      //     } else {
      //       console.error('Failed to delete user:', result.message);
      //     }
      //   } catch (error) {
      //     console.error("Failed to delete user:", error);
      //   }
      // };

      // Conditional rendering
      if (loading) return <div>Loading users...</div>;
      if (error) return <div>Error: {error}</div>;

      return (
        <div className="relative overflow-x-auto shadow-md sm:rounded-lg">
          <table className="w-full text-sm text-left rtl:text-right text-gray-500">
            <caption className="p-5 text-lg font-semibold text-left rtl:text-right text-gray-900 bg-white dark:text-white">
              Admin - Manage Users
              <p className="mt-1 text-sm font-normal text-gray-500">Browse and manage DGX community users.</p>
            </caption>
            <thead className="text-xs text-gray-700 uppercase bg-gray-50">
              <tr>
                <th scope="col" className="px-6 py-3">User ID</th>
                <th scope="col" className="px-6 py-3">Name</th>
                <th scope="col" className="px-6 py-3">Email</th>
                <th scope="col" className="px-6 py-3">College Name</th>
                <th scope="col" className="px-6 py-3">Designation</th>
                <th scope="col" className="px-6 py-3"><span className="sr-only">Delete</span></th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.UserID} className="bg-white border-b">
                  <th scope="row" className="px-6 py-4 font-medium text-gray-900 whitespace-nowrap">
                    {user.UserID}
                  </th>
                  <td className="px-6 py-4">{user.Name}</td>
                  <td className="px-6 py-4">{user.EmailId}</td>
                  <td className="px-6 py-4">{user.CollegeName}</td>
                  <td className="px-6 py-4">{user.Designation}</td>
                  <td className="px-6 py-4 text-right">
                    <button
                      onClick={() => handleDelete(user.UserID)}
                      className="font-medium text-red-600 dark:text-red-500 hover:underline"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    };

    export default AdminUsers;
