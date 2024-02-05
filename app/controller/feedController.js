const Feed = require('../model/feedModel.js');
let Parser = require('rss-parser');



const feedController = {
   // get all feeds 
   getFeed: async (req,res)=>{
      try {
            let parser = new Parser();
            const feeds = await Feed.findAll()
            let news = []
               await Promise.all(feeds.map(async (feed) => {
               const feedData = await parser.parseURL(`${feed.url}`);
               news.push(feedData);
               console.log("feed envoyé")
            }))
            res.status(200).json(news)   
            
         } catch (error) {
               res.status(404).json({message: error.message})
         }   
      },
      getOneFeed: async (req,res) => {
         try {
            // get an instance of a feed
         const feed = new Feed();
         //initialize the feed parser
         let parser = new Parser();
         // get a feed by it's id  
         const newFeed = await feed.findByPk(req.params.id);
         const feedData = await parser.parseURL(`${newFeed.url}`);
         res.status(200).json(feedData)   
         } catch(err) {   
         res.status(400).json({message: err.message})
         }
      },
      /**
       * generates all feeds for a particular user
       * @param {*} req 
       * @param {*} res 
       */
      getAllFeedByUser: async(req,res)=>{
         try {
            // creates an instance of a parser
            let parser = new Parser();
            // creates an instance of a feed 
            const feed =  new Feed();
            // generates every feed created by one user
            const userFeeds = await feed.findFeedByUser(req.params.user_id)
            console.log(userFeeds);
            // initialize the table that will hold parsed feeds urls
            let news = []
            // the feeds url are then parsed before there are send to the client
               await Promise.all(userFeeds.map(async (feed) => {
               const feedData = await parser.parseURL(`${feed.url}`);
               news.push(feedData);
               console.log("feed envoyé")
            }))
            // if everything is ok thefeeds url are send to the client 
            res.status(200).json(news)   
            //else the 404 status is send
         } catch (error) {
            res.status(404).json({message: error.message})
         }
      },

      /**
       * create a feed 
       * @param {*} req 
       * @param {*} res 
       */
     addFeed: async (req,res)=>{
      try {
         // creates an instance of a feed
         const feed = await new Feed();
         // generates every feed created by one user
         const  feedName = await feed.findByField("name",req.body.name )
         console.log(feedName);
         if(feedName){
            res.status(400).json('un flux existe déjà avec ce nom veuillez renseigner un autre nom')
         }else{
            const addedFeed = await feed.insertFeedByUser(req.params.user_id,{
               name: req.body.name,
               url: req.body.url,             
            })
            console.log(addedFeed);
            res.status(201).json(addedFeed);
         }
      } catch (error) {
          res.status(400).json({message: error.message})
      }
      },
      
      /**
       * update a feed 
       * @param {*} req 
       * @param {*} res 
       */
     modifyFeed: async (req, res)=> {
        try { 
           const feed = new Feed();
           const updatedFeed = await feed.update(req.params.id, req.body);
           res.status(200).json(updatedFeed)
  
        } catch(err) {
           console.log(err)
           res.status(400).json({message: err.message})
        }
     },

     /**
      * to delete a feed 
      * @param {*} req 
      * @param {*} res 
      */
     deleteFeed: async (req,res) => {
        try {        
           const feed = new Feed();
           const deletedFeed = await feed.deleteFeed(req.params.id);
           res.status(200).json(deletedFeed)
  
        } catch(err) {
           res.status(400).json({message: err.message})
        }
     }
    
    
     
}
module.exports = feedController; 