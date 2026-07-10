const { app } = require('./app')

const PORT = process.env.PORT || process.env.MOCKPASS_PORT || 5156

app.listen(PORT, () => {
  console.log(`MockPass listening on ${PORT}`)
})
