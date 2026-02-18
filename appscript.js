/*************************************************
  SECURE AUTH BACKEND
*************************************************/

/* ===============================
   ENTRY POINT
================================*/

function doPost(e){

  try{

    // 🔒 Payload size protection
    if(e.postData.contents.length > 5000)
      throw new Error("Payload too large");

    const data = JSON.parse(e.postData.contents);

    switch(data.action){

      case "register": return output(registerUser(data));
      case "login": return output(loginUser(data));
      case "verify": return output(verifyAccount(data.token));
      case "requestReset": return output(requestPasswordReset(data.email));
      case "resetPassword": return output(resetPassword(data));

      default: return output({success:false,message:"Invalid action"});

    }

  } catch(err){
    return output({success:false,message:err.message});
  }
}

function output(obj){
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

/* ===============================
   REGISTRATION
================================*/

function registerUser(data){

  const sheet = getSheet("Users");
  const rows = sheet.getDataRange().getValues();
  const now = new Date();

  const name = sanitizeName(data.name);
  const email = sanitizeEmail(data.email);
  const password = sanitizePassword(data.password);

  // 🔍 Duplicate check
  for(let i=1;i<rows.length;i++){
    if(rows[i][2] === email)
      return {success:false,message:"Email already registered"};
  }

  const salt = Utilities.getUuid();
  const hash = hashPassword(password,salt);
  const id = Utilities.getUuid();

  const verifyToken = Utilities.getUuid();
  const expiry = new Date(now.getTime()+24*60*60*1000);

  sheet.appendRow([
    id,name,email,hash,salt,
    "user",0,"","",
    "pending",verifyToken,expiry,now
  ]);

  sendVerificationEmail(email,verifyToken);

  logAudit(email,"REGISTER","SUCCESS","Verification sent");

  return {success:true,message:"Verification email sent"};
}

/* ===============================
   EMAIL VERIFICATION
================================*/

function verifyAccount(token){

  const sheet = getSheet("Users");
  const rows = sheet.getDataRange().getValues();
  const now = new Date();

  for(let i=1;i<rows.length;i++){

    if(rows[i][10] === token){

      if(now > new Date(rows[i][11]))
        return {success:false,message:"Token expired"};

      sheet.getRange(i+1,10).setValue("active");
      sheet.getRange(i+1,11).setValue("");
      sheet.getRange(i+1,12).setValue("");

      logAudit(rows[i][2],"VERIFY","SUCCESS","Account activated");

      return {success:true,message:"Account verified"};
    }
  }

  return {success:false,message:"Invalid token"};
}

/* ===============================
   LOGIN
================================*/

function loginUser(data){

  const sheet = getSheet("Users");
  const rows = sheet.getDataRange().getValues();
  const now = new Date();

  const email = sanitizeEmail(data.email);
  const password = data.password;

  for(let i=1;i<rows.length;i++){

    if(rows[i][2] === email){

      if(rows[i][9] !== "active")
        return {success:false,message:"Verify email first"};

      if(rows[i][7] && now < new Date(rows[i][7]))
        return {success:false,message:"Account locked"};

      const hash = hashPassword(password,rows[i][4]);

      if(hash === rows[i][3]){

        sheet.getRange(i+1,7).setValue(0);
        sheet.getRange(i+1,8).setValue("");
        sheet.getRange(i+1,9).setValue(now);

        const token = createSession(email);

        logAudit(email,"LOGIN","SUCCESS","");

        return {success:true,token:token};

      } else {

        const attempts = (rows[i][6]||0)+1;
        sheet.getRange(i+1,7).setValue(attempts);

        if(attempts>=5){
          const lockTime = new Date(now.getTime()+15*60*1000);
          sheet.getRange(i+1,8).setValue(lockTime);
        }

        logAudit(email,"LOGIN","FAILED","Wrong password");

        return {success:false,message:"Invalid credentials"};
      }
    }
  }

  return {success:false,message:"User not found"};
}

/* ===============================
   SESSION
================================*/

function createSession(email){

  const sheet = getSheet("Sessions");

  const raw = Utilities.getUuid()+Utilities.getUuid();
  const hash = hashPassword(raw,"sessionSalt");

  const now = new Date();
  const expiry = new Date(now.getTime()+60*60*1000);

  sheet.appendRow([email,hash,now,expiry,"active"]);

  return raw;
}

function verifySession(token){

  const sheet = getSheet("Sessions");
  const rows = sheet.getDataRange().getValues();
  const now = new Date();

  const hash = hashPassword(token,"sessionSalt");

  for(let i=1;i<rows.length;i++){

    if(rows[i][1] === hash && rows[i][4]==="active"){

      if(now > new Date(rows[i][3])){
        sheet.getRange(i+1,5).setValue("expired");
        return false;
      }

      return true;
    }
  }

  return false;
}

/* ===============================
   PASSWORD RESET
================================*/

function requestPasswordReset(email){

  const sheet = getSheet("PasswordResets");
  const token = Utilities.getUuid();
  const expiry = new Date(new Date().getTime()+30*60*1000);

  sheet.appendRow([email,token,expiry,false]);

  sendResetEmail(email,token);

  return {success:true,message:"Reset email sent"};
}

function resetPassword(data){

  const sheet = getSheet("PasswordResets");
  const rows = sheet.getDataRange().getValues();
  const now = new Date();

  for(let i=1;i<rows.length;i++){

    if(rows[i][1]===data.token && !rows[i][3]){

      if(now > new Date(rows[i][2]))
        return {success:false,message:"Token expired"};

      updateUserPassword(rows[i][0],data.newPassword);

      sheet.getRange(i+1,4).setValue(true);

      return {success:true,message:"Password updated"};
    }
  }

  return {success:false,message:"Invalid token"};
}

/* ===============================
   HELPERS
================================*/

function updateUserPassword(email,newPass){

  const sheet = getSheet("Users");
  const rows = sheet.getDataRange().getValues();

  for(let i=1;i<rows.length;i++){

    if(rows[i][2]===email){

      const salt = Utilities.getUuid();
      const hash = hashPassword(newPass,salt);

      sheet.getRange(i+1,4).setValue(hash);
      sheet.getRange(i+1,5).setValue(salt);

      return;
    }
  }
}

function sanitizeName(name){
  if(!name) throw new Error("Name required");
  name=name.trim();
  if(name.length<3||name.length>100) throw new Error("Invalid name");
  return name;
}

function sanitizeEmail(email){
  if(!email) throw new Error("Email required");
  email=email.toLowerCase().trim();
  const regex=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!regex.test(email)) throw new Error("Invalid email");
  return email;
}

function sanitizePassword(password){
  if(!password||password.length<8)
    throw new Error("Password too weak");
  return password;
}

function hashPassword(password,salt){
  const hash = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    password+salt
  );
  return hash.map(b=>('0'+(b&0xFF).toString(16)).slice(-2)).join('');
}

function sendVerificationEmail(email,token){
  const url="YOUR_WEB_APP_URL?action=verify&token="+token;
  MailApp.sendEmail(email,"Verify Account","Click: "+url);
}

function sendResetEmail(email,token){
  const url="https://logtec.vercel.app/reset.html?token="+token;
  MailApp.sendEmail(email,"Reset Password","Click: "+url);
}

function logAudit(email,action,status,notes){
  const sheet=getSheet("AuditLogs");
  sheet.appendRow([new Date(),email,action,status,notes]);
}

function getSheet(name){
  return SpreadsheetApp.getActive().getSheetByName(name);
}