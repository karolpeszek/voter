const pug = require('pug');
const _ = require('lodash');

const config = require(__dirname + "/config.json")

const cardsPerPage = config.pdfGeneration.cardsPerPage;

const mapClassToPages = (classItem) => _.chunk(classItem.tokens, cardsPerPage)
    .map((tokens) => ({
        className: classItem.className,
        tokens,
    }));

module.exports.renderHTML = (classes) => pug.renderFile(__dirname + '/templates/index.pug', {
    pages: classes.flatMap(mapClassToPages),
    voteUrl: config.pdfGeneration.votingUrlForUser,
    self: true,
})
