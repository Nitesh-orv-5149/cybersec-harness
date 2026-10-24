// Fixture source used only to test package-use evidence. Not executed.
import express from 'express';
import _ from 'lodash';

const app = express();
app.get('/merge', mergeSettings);

function mergeSettings(req, res) {
  res.json(_.merge({}, req.query));
}

export default app;
