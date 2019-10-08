const graph = require('fbgraph');
const getScore = require('../utils/scoreCalc');
/**
 * GET /api/facebook
 * Facebook API example.
 */
exports.getFacebook = async (req, res, next) => {

  const token = req.user.data.tokens.find((token) => token.kind === 'facebook');

  graph.setAccessToken(token.accessToken);
  graph.get(`/417061505862004/feed?limit=5`, async (err, result) => {
    if (err) { return res.json(err); }
    posts = result.data;
    nextLink = result.paging.next;
    var finalResults = await Promise.all(posts.map(async (post)=>{
      ids = post.id.split("_")
      post.link = `https://www.facebook.com/groups/${ids[0]}/permalink/${ids[1]}/`
      scores = await getScore(post.message);
      scores = Object.keys(scores).map((key) => {
        const obj = {};
        obj[key] = scores[key];
        return obj;
      });
      scores.sort((a,b)=>{
        return b[Object.keys(b)[0]] - a[Object.keys(a)[0]];
      })
      post.scores = scores;
      console.log(post.scores)
      return post;
    }));

    return res.json({posts:finalResults,next:nextLink});
  });
};
