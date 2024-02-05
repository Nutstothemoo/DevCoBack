 // npx jest to run the tests 


//const authRouter = require('../app/router/authRouter')
const supertest = require('supertest');
const app = require('../index');
const pool =require('../app/services/dbClient');
const Post = require('../app/model/postModel');
const User = require('../app/model/userModel');
const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzgzNTA2ODV9.hLxIbGhuXKjb0DbnXG23sBzZwXha-EO7tzt6g1EMCy8'




describe("posts", ()=>{

   
    
beforeAll(async ()=>{
 await pool.connect()
});

//  afterAll(async ()=>{
//      await pool.end()
//     })

    describe("get post route", ()=>{
        // if post with some user doesn't exist 
        describe("given the post doesn't exists", ()=>{
            it("should return 404", async ()=>{
                const user_id = 7;
               await supertest(app).get(`/api/post/${user_id}`).set('Authorization', `Bearer ${TOKEN}`).expect(400)
            })
        })
        // if post does exists 
        describe("given the post does exists", ()=>{
            it("should return 200 status and the post", async ()=> {
                 const post_id = 51;
                 const post = await Post.findAll({ $where: { id: post_id } })
                const {body, statusCode}  = await supertest(app).get(`/api/post/${post_id}`).set('Authorization', `Bearer ${TOKEN}`);
                expect(body.id).toBe(post_id)
                expect(statusCode).toBe(200)
            })
        })
    })
    

})

describe("POST /login", ()=>{
    
    beforeAll(async ()=>{
     await pool.connect()
    });
    
    //  afterAll(async ()=>{
    //      await pool.end()
    //     })
    
        describe("given a username and password", ()=>{
            
            test("should respond with a 200 status code and login user", async ()=>{
                const user = new User()
                authUser = user.findByField('email', 'myUsername@gmail.com')
                const {statusCode, body} = await supertest(app).post('/api/login').send({
		            email: "myUsername@gmail.com",
                    password: "myUsername"
                })
               expect(statusCode).toBe(200)
               expect(body.email).toEqual(authUser.email)
               expect(body.password).toEqual(authUser.password)
            })
            
        })
        describe("when the username and password are missing", ()=>{
            // should response with a status code of 400
            //
        })
    
    })

   