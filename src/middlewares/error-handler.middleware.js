export default function (err, req, res, next) {
    console.error(err);

    // 발생한 에러가 예상한 에러인지, 아니면 다른 에러인지 구분을 해야한다.
    if (err.name === 'ValidationError') {
        return res.status(400).json({ errorMessage: error.message });
    }

    // 500: 서버에 문제가 있어 에러가 발생했다
    return res.status(500).json({ errorMessage: "서버에서 에러가 발생했다." });
}