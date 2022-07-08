const path = require('path')
const fs = require('fs') //node讀取文件
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')
const server = jsonServer.create()
const router = jsonServer.router(path.join(__dirname, 'db.json'))
const middlewares = jsonServer.defaults()
server.use(jsonServer.bodyParser)
server.use(middlewares)

const getUserDb = () => {
  return JSON.parse( fs.readFileSync(path.join(__dirname, 'users.json'), 'utf-8') )
}

const isAuthenticated = ({email, password}) => {
  return getUserDb().users.findIndex(user => user.email === email && user.password === password ) !== -1;
}

const isExist = email => {
  return getUserDb().users.findIndex(user => user.email === email ) !== -1;
}

const SECRET_KEY = "fwrgn2efn1onbkjbv2pi3v";
const expiresIn = "1h";
const createToken = payload => {
  return jwt.sign(payload, SECRET_KEY, { expiresIn } );
}

//定義自己的接口，登入
server.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if( isAuthenticated({email, password}) ) {
    const user = getUserDb().users.find( u => u.email === email && u.password === password);
    const { nickname, type } = user;
    //JWT
    const jwToken = createToken({ nickname, type, email })
    return res.status(200).json(jwToken);
  } else {
    const status = 401;
    const message = "Incorrect Email or Password"
    return res.status(status).json(  {status, message})
  }

})

//註冊
server.post('/auth/register', (req, res) => {
  const { email, password, nickname, type } = req.body;

  //step 1, 註冊過回報提示錯誤
  // if( isAuthenticated({email, password}) ) {
  if( isExist(email) ) {
    const status = 401;
    const message = "Email has already been registered";
    return res.status(status).json({status, message});
  }

  //step 2, 讀取user.json
  fs.readFile(path.join(__dirname, 'users.json'), (err, _data) => {
    if (err) {
      const status = 401;
      const message = err;
      return res.status(status).json({status, message});
    }
    //取得現在users資料
    const data = JSON.parse(_data.toString());
    //取得最後一筆user id
    const last_item_id = data.users[data.users.length - 1].id;
    //新增user
    data.users.push({ id: last_item_id + 1, email, password, nickname, type });
    fs.writeFile(
      path.join(__dirname, 'users.json'),
      JSON.stringify(data),
      (err, result) => {
        //WRITE
        if (err) {
          const status = 401;
          const message = err;
          res.status(status).json({status, message});
          return;
        }else console.log("新增成功")
      }
    )
  })

  //create token for new user
  const jwToken = createToken({ nickname, type, email });
  res.status(200).json(jwToken);

})

const verifyToken = token => {
  return jwt.verify(token, SECRET_KEY, ( err, decode ) => 
    decode !== undefined ? decode : err
  );
}

server.use('/carts', ( req, res, next) => {
  if ( 
    req.headers.authorization === undefined ||
    req.headers.authorization.split(' ')[0] !== "Bearer" 
  ) {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({status, message});
    return;
  }
  try {
    const verifyTokenResult = verifyToken(
      req.headers.authorization.split(' ')[1]
    )
    if ( verifyTokenResult instanceof Error ) {
      const status = 401;
      const message = "access token not provided";
      res.status(status).json({status, message});
      return;
    }
    next(); //把carts的資料返回
  } catch (error) {
    const status = 401;
    const message = "Error token is revoked";
    res.status(status).json({status, message});
  }

})

server.use(router)
server.listen(3003, () => {
  console.log('JSON Server is running')
})