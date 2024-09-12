import express from "express";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
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
            return res.status(401).json({ message: '비밀번호와 비밀번호 확인이 일치하지 않습니다.' });
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

// 로그인 API
router.post('/game/sign-in', async(req, res, next) => {
    const {userId, userPw} = req.body;
    const user = await prisma.userAccount.findFirst({
        where: {userId: userId}
    })

    if(!user)
        return res.status(401).json({message: '존재하지 않은 ID입니다.'});
    else if(!(await bcrypt.compare(userPw, user.userPw)))
        return res.status(401).json({message: '비밀번호가 일치하지 않습니다.'});

    const token = jwt.sign(
        {
            userId: user.userId
        },
        'custom-secret=key'
    );
    
    res.cookie('authorization', `Bearer ${token}`);
    return res.status(200).json({message: '로그인 완료!'});
});


export default router;
