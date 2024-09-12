import express from "express";
import bcrypt from 'bcrypt';
import joi from 'joi';
import { prisma } from "../utils/prisma/index.js";

const router = express.Router(); // express.Router()를 이용해 라우터를 생성합니다.

// 유효성 검증
const schemaCheck = joi.object({
    userPw: joi.string().min(6).required(),
    userId: joi.string(),
    userName: joi.string(),
    userPwCheck: joi.string().min(6).required(),
})

// 회원가입 API
router.post('/game/sign-up', async(req, res, next) => {
    try{
        const validation = await schemaCheck.validateAsync(req.body);
        const {userId, userPw, userName, userPwCheck} = validation;

        // 같은 ID가 있는지 확인한다.
        const isSameId = await prisma.userAccount.findFirst({
            where: {userId: userId}
        });
        if(isSameId)
            return res.status(409).json({message: '이미 존재하는 ID입니다.'});

        if (userPw !== userPwCheck) {
            return res.status(400).json({ message: '비밀번호와 비밀번호 확인이 일치하지 않습니다.' });
        }

        const hashedPassword = await bcrypt.hash(userPw, 10);
        await prisma.userAccount.create({
            data: {
                userId: userId,
                userPw: hashedPassword,
                userName: userName,
                userPwCheck: hashedPassword
            }
        });

        return res.status(201).json({message: '회원가입 완료!'});
    } catch(error) {
        next(error);
    }
});


export default router;
