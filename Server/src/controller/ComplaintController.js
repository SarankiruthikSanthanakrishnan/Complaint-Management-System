import db from "../config/db.js";
import HandleError from "../helper/HandleError.js";

export const AddComplaint = async (req,res,next)=>{
    try {
        const{} = req.body;

    } catch (error) {
        return next(new HandleError("Adding Complaint Failed",500));
    }
}
