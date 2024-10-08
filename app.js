import express from "express";
import cookieParser from 'cookie-parser';
import SimulatorRouter from "./src/routes/simulator.router.js";

const app = express();
const PORT = 3017;

app.use(express.json());
app.use(cookieParser());
app.use("/api", [SimulatorRouter]);

app.listen(PORT, () => {
    console.log(PORT, "포트로 서버가 열렸어요!");
});
