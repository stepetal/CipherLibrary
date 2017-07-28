// Library for ciphers(AES,DES,OTP,2DES)
//cipher_library.h
//abstract class for input
class InputType{
	vector<char> input_text;
public:
	virtual void GetInputText(string input_name) = 0;
	void SetInputText(vector<char> v){ input_text = v; }
	vector<char>& ReturnInput(){ return input_text; }
};
//input from console
class Input_Console :public InputType{
public:
	void GetInputText(string input_name);
};
//input from file
class Input_File :public InputType{
public:
	void GetInputText(string input_name);
};

//abstract class for output
class OutputType
{
	vector<char> output_text;
public:
	virtual void WriteToSink(string output_name) = 0;
	void SetOutput(vector<char> out_text){ output_text = out_text; }
	vector<char>& ReturnOutput(){ return output_text; }
};
//output to file
class Output_File : public OutputType
{
	void WriteToSink(string output_name);
};
//output to console
class Output_Console : public OutputType
{
	void WriteToSink(string output_name);
};

//abstract class for all kinds of ciphers
class CipherType{
protected:
	shared_ptr<InputType> GetPlainText(){ return plain_text; }
	shared_ptr<InputType> GetKey(){ return ciph_key; }
	shared_ptr<OutputType>  GetEncText() { return enc_text; }
	shared_ptr<OutputType> GetDecText(){ return dec_text; }
private:
	shared_ptr<InputType> plain_text;
	shared_ptr<InputType> ciph_key;
	shared_ptr<OutputType> enc_text;
	shared_ptr<OutputType> dec_text;
public:
	virtual void GenerateCipherKey() = 0;
	virtual void Encrypt() = 0;
	virtual void Decrypt() = 0;
	virtual void WriteKeyToFile(vector<char> k)=0;
	void SetEncText(shared_ptr<OutputType> e){ enc_text = e; }
	void SetDecText(shared_ptr<OutputType> d){ dec_text = d; }
	void SetCiphKey(shared_ptr<InputType> k){ ciph_key = k; }
	void SetPlainText(shared_ptr<InputType> p_t){ plain_text = p_t; }
};

//OTP
class VernamCipher : public CipherType{
protected:
	void GenerateCipherKey();
	void Encrypt();
	void Decrypt();
	void WriteKeyToFile(vector<char> k);
public:
	VernamCipher(){};

};

class DES_Cipher : public CipherType{
private:
	DES_key_schedule key;
	int b_part;
protected:
	void GenerateCipherKey();
	void Encrypt();
	void Decrypt();
	void WriteKeyToFile(vector<char> k);
	void SetPaddingPart(int b_p){ b_part = b_p; }
	int GetPaddingPart(){ return b_part; }
	void SetKeySchedule(DES_key_schedule key_s){ key = key_s; }
public:
	DES_Cipher(){ b_part = 0; }
	

};


class RC4_Cipher : public CipherType{
private:
	vector<int> s_table;
protected:
	void Encrypt();
	void Decrypt();
	void GenerateCipherKey();
	void WriteKeyToFile(vector<char> k);
	void Swap(int &a, int &b);
	void KeySchedule();
public:
	RC4_Cipher(){};
	
};




class Double_DES_Cipher : public CipherType{
private:
	DES_key_schedule key1;
	DES_key_schedule key2;
	int b_part;
protected:
	void WriteKeyToFile(vector<char> k);
	void GenerateCipherKey();
	void Encrypt();
	void Decrypt();
	void SetPaddingPart(int b_p){ b_part = b_p; }
	int GetPaddingPart(){ return b_part; }
	void SetKeySchedule1(DES_key_schedule key_s){ key1 = key_s; }
	void SetKeySchedule2(DES_key_schedule key_s){ key2 = key_s; }
public:
	Double_DES_Cipher(){ b_part = 0; }
	
};


class AES_Cipher : public CipherType{
private:
	int key_len;
	int b_part;
protected:
	void GetAESKey(uint8_t *key);
	void SetPaddingPart(int b_p){ b_part = b_p; }
	int GetPaddingPart(){ return b_part; }
	int GetKeyLen(){ return key_len; }
	void SetKeyLen(int len){ key_len = len; }
	void Encrypt();
	void Decrypt();
	void GenerateCipherKey();
	void WriteKeyToFile(vector<char> k);
public:
	AES_Cipher(){ b_part = 0; SetKeyLen(16); }

};


//interface and main function

enum InputTypes { I_Console, I_File } ITypes;
enum OutputTypes { O_Console, O_File } OTypes;
enum CipherTypes { AES, DES, Double_DES, RC4, OTP } CTypes;


CipherType* GetCipherInstance(CipherTypes CTypes)
{
	CipherType *ob=NULL;
	switch (CTypes){
	case AES:{
		ob = new AES_Cipher();
		break;
	}
	case DES:{
		ob = new DES_Cipher();
		break;
	}
	case Double_DES:{
		ob = new Double_DES_Cipher();
		break;
	}
	case RC4:{
		ob = new RC4_Cipher();
		break;
	}
	case OTP:{
		ob = new VernamCipher();
		break;
	}
	}
	return ob;
}

InputType* GetInputInstance(InputTypes ITypes)
{
	InputType *ob=NULL;
	switch (ITypes){
	case I_Console:{
		ob = new Input_Console();
		break;
	}
	case I_File:{
		ob = new Input_File();
		break;
	}
	}
	return ob;
}

OutputType* GetOutputInstance(OutputTypes OTypes)
{
	OutputType *ob=NULL:
	switch (OTypes){
	case O_Console:{
		ob = new Output_Console();
		break;
	}
	case O_File:{
		ob = new Output_File();
		break;
	}
	}
}


int main()
{	//shared_ptr from std
	shared_ptr<InputType> plain_text_otp(GetInputInstance(I_File));
	shared_ptr<OutputType> encrypted_text_otp(GetOutputInstance(O_File));
	shared_ptr<InputType> key_otp(GetInputInstance(I_File));
	shared_ptr<OutputType> decrypted_text_otp(GetOutputInstance(O_File));

	shared_ptr<InputType> plain_text_des(GetInputInstance(I_File));
	shared_ptr<OutputType> encrypted_text_des(GetOutputInstance(O_File));
	shared_ptr<InputType> key_des(GetInputInstance(I_File));
	shared_ptr<OutputType> decrypted_text_des(GetOutputInstance(O_File));

	shared_ptr<InputType> plain_text_rc4(GetInputInstance(I_File));
	shared_ptr<OutputType> encrypted_text_rc4(GetOutputInstance(O_File));
	shared_ptr<InputType> key_rc4(GetInputInstance(I_File));
	shared_ptr<OutputType> decrypted_text_rc4(GetOutputInstance(O_File));

	shared_ptr<InputType> plain_text_2des(GetInputInstance(I_File));
	shared_ptr<OutputType> encrypted_text_2des(GetOutputInstance(O_File));
	shared_ptr<InputType> key_2des(GetInputInstance(I_File));
	shared_ptr<OutputType> decrypted_text_2des(GetOutputInstance(O_File));

	shared_ptr<InputType> plain_text_aes(GetInputInstance(I_File));
	shared_ptr<OutputType> encrypted_text_aes(GetOutputInstance(O_File));
	shared_ptr<InputType> key_aes(GetInputInstance(I_File));
	shared_ptr<OutputType> decrypted_text_aes(GetOutputInstance(O_File));

	
	CipherType *OTP_Cipher = GetCipherInstance(OTP);
	plain_text_otp->GetInputText("input.txt");
	OTP_Cipher->SetPlainText(plain_text_otp);
	OTP_Cipher->SetEncText(encrypted_text_otp);
	OTP_Cipher->SetDecText(decrypted_text_otp);
	OTP_Cipher->GenerateCipherKey();
	key_otp->GetInputText("OTP_Key.txt");
	OTP_Cipher->SetCiphKey(key_otp);
	OTP_Cipher->Encrypt();
	OTP_Cipher->Decrypt();
	decrypted_text_otp->WriteToSink("OTP_output.txt");

	CipherType *DES_Cipher = GetCipherInstance(DES);
	plain_text_des->GetInputText("input.txt");
	DES_Cipher->SetPlainText(plain_text_des);
	DES_Cipher->SetEncText(encrypted_text_des);
	DES_Cipher->SetDecText(decrypted_text_des);
	DES_Cipher->GenerateCipherKey();
	key_des->GetInputText("DES_Key.txt");
	DES_Cipher->SetCiphKey(key_des);
	DES_Cipher->Encrypt();
	DES_Cipher->Decrypt();
	decrypted_text_des->WriteToSink("DES_output.txt");

	CipherType *RC4_Cipher = GetCipherInstance(RC4);
	plain_text_rc4->GetInputText("input.txt");
	RC4_Cipher->SetPlainText(plain_text_rc4);
	RC4_Cipher->SetEncText(encrypted_text_rc4);
	RC4_Cipher->SetDecText(decrypted_text_rc4);
	RC4_Cipher->GenerateCipherKey();
	key_rc4->GetInputText("RC4_Key.txt");
	RC4_Cipher->SetCiphKey(key_rc4);
	RC4_Cipher->Encrypt();
	RC4_Cipher->Decrypt();
	decrypted_text_rc4->WriteToSink("RC4_output.txt");

	CipherType *Double_DES_Cipher = GetCipherInstance(Double_DES);
	plain_text_2des->GetInputText("input.txt");
	Double_DES_Cipher->SetPlainText(plain_text_2des);
	Double_DES_Cipher->SetEncText(encrypted_text_2des);
	Double_DES_Cipher->SetDecText(decrypted_text_2des);
	Double_DES_Cipher->GenerateCipherKey();
	key_2des->GetInputText("2DES_Key.txt");
	Double_DES_Cipher->SetCiphKey(key_2des);
	Double_DES_Cipher->Encrypt();
	Double_DES_Cipher->Decrypt();
	decrypted_text_2des->WriteToSink("2DES_output.txt");

	CipherType *AES_Cipher = GetCipherInstance(AES);
	plain_text_aes->GetInputText("input.txt");
	AES_Cipher->SetPlainText(plain_text_aes);
	AES_Cipher->SetEncText(encrypted_text_aes);
	AES_Cipher->SetDecText(decrypted_text_aes);
	AES_Cipher->GenerateCipherKey();
	key_aes->GetInputText("AES_Key.txt");
	AES_Cipher->SetCiphKey(key_aes);
	AES_Cipher->Encrypt();
	AES_Cipher->Decrypt();
	decrypted_text_aes->WriteToSink("AES_output.txt");
	
	return 0;	
}
