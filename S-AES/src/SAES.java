package src;

import java.util.*;


public class SAES {
    //S盒
    private static final int[][] SBOX1 = {
            {9, 4, 10, 11},
            {13, 1, 8, 5},
            {6, 2, 0, 3},
            {12, 14, 15, 7}
    };
    //逆S盒
    private static final int[][] SBOX2 = {
            {10, 5, 9, 11},
            {1, 7, 8, 15},
            {6, 0, 2, 3},
            {12, 4, 13, 14}
    };
    //GF(2^4)乘法映射表
    private static final int[][] MultiplicationTable = {
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13},
            {0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 14, 13, 7, 4, 1, 2},
            {0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9},
            {0, 5, 10, 15, 7, 2, 14, 9, 12, 8, 4, 1, 13, 11, 3, 6},
            {0, 6, 12, 10, 14, 8, 2, 4, 7, 3, 15, 13, 14, 12, 6, 2},
            {0, 7, 14, 9, 15, 11, 4, 1, 13, 10, 5, 2, 3, 6, 12, 8},
            {0, 8, 3, 11, 6, 14, 5, 13, 12, 4, 15, 7, 10, 2, 9, 1},
            {0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14},
            {0, 10, 7, 13, 14, 4, 9, 3, 15, 5, 11, 1, 2, 8, 6, 12},
            {0, 11, 5, 14, 10, 1, 15, 4, 9, 12, 3, 13, 14, 2, 8, 6},
            {0, 12, 11, 7, 5, 13, 9, 2, 14, 6, 1, 15, 13, 3, 4, 10},
            {0, 13, 9, 1, 11, 7, 8, 5, 2, 15, 14, 4, 3, 12, 10, 6},
            {0, 14, 15, 13, 9, 3, 1, 12, 10, 6, 2, 8, 5, 4, 11, 7},
            {0, 15, 13, 2, 14, 12, 6, 10, 1, 7, 8, 4, 9, 5, 3, 11}
    };

    // RCON
    static int[] rcon1 = {1, 0, 0, 0, 0, 0, 0, 0};
    static int[] rcon2 = {0, 0, 1, 1, 0, 0, 0, 0};
    public static String encrypt(String plaintext, String key){
        // 将明文和密钥转换为整数数组
        int[] bplaintext = binaryStringTointArray(plaintext);
        System.out.println("开始加密， 明文为: " + plaintext);
        int[] k1 = binaryStringTointArray(key);
        // 确保密钥有效
        if (k1.length != 16) {
            throw new IllegalArgumentException("密钥必须为 16 位长。");
        }

        //生成轮密钥
        int[][] initialKey = new int[2][8];
        System.arraycopy(k1, 0, initialKey[0], 0, 8); // 将前8个元素复制到initialKey[0]
        System.arraycopy(k1, 8, initialKey[1], 0, 8); // 将后8个元素复制到initialKey[1]
        int[][] roundKey2 = new int[2][8];
        int[][] roundKey3 = new int[2][8];

        roundKey2[0] = xor(initialKey[0], gFunction(initialKey[1], rcon1));
        roundKey2[1] = xor(roundKey2[0], initialKey[1]);
        roundKey3[0] = xor(roundKey2[0], gFunction(roundKey2[1], rcon2));
        roundKey3[1] = xor(roundKey3[0], roundKey2[1]);

        int[] k2 = new int[16];
        int[] k3 = new int[16];
        System.arraycopy(roundKey2[0], 0, k2, 0, 8); // 将roundKey2[0]复制到k2的前8个位置
        System.arraycopy(roundKey2[1], 0, k2, 8, 8); // 将roundKey2[1]复制到k2的后8个位置

        System.arraycopy(roundKey3[0], 0, k3, 0, 8); // 将roundKey3[0]复制到k3的前8个位置
        System.arraycopy(roundKey3[1], 0, k3, 8, 8); // 将roundKey3[1]复制到k3的后8个位置
        showKey(k1, k2, k3);

        //轮密钥加
        int[] result1 = xor(bplaintext,k1);
        //分为四个半字节
        int[] s00 = new int[4];
        int[] s01 = new int[4];
        int[] s10 = new int[4];
        int[] s11 = new int[4];
        // 使用System.arraycopy将result1的前4个元素复制到s00
        System.arraycopy(result1, 0, s00, 0, 4);
        // 使用System.arraycopy将result1的第4个到第7个元素复制到s10
        System.arraycopy(result1, 4, s10, 0, 4);
        // 使用System.arraycopy将result1的第8个到第11个元素复制到s01
        System.arraycopy(result1, 8, s01, 0, 4);
        // 使用System.arraycopy将result1的第12个到第15个元素复制到s11
        System.arraycopy(result1, 12, s11, 0, 4);
        System.out.print("轮密钥加后");
        showStatus(s00, s01, s10, s11);

        //半字节替代
        nibbleSubstitution(s00);
        nibbleSubstitution(s01);
        nibbleSubstitution(s10);
        nibbleSubstitution(s11);
        System.out.print("半字节替代后");
        showStatus(s00, s01, s10, s11);

        //行位移
        swapRows(s10,s11);
        System.out.print("行位移后");
        showStatus(s00, s01, s10, s11);

        //列混淆
        mixColumn(s00, s01, s10, s11);
        System.out.print("列混淆后");
        showStatus(s00, s01, s10, s11);

        //轮密钥加
        // 创建一个新的数组，长度是result1的长度
        int[] mergedArray = new int[result1.length];
        // 合并数组
        System.arraycopy(s00, 0, mergedArray, 0, 4);
        System.arraycopy(s10, 0, mergedArray, 4, 4);
        System.arraycopy(s01, 0, mergedArray, 8, 4);
        System.arraycopy(s11, 0, mergedArray, 12, 4);
        int[] result2 = xor(mergedArray,k2);
        // 重新分割result2到s00, s01, s10, s11
        System.arraycopy(result2, 0, s00, 0, 4);
        System.arraycopy(result2, 4, s10, 0, 4);
        System.arraycopy(result2, 8, s01, 0, 4);
        System.arraycopy(result2, 12, s11, 0, 4);
        System.out.print("轮密钥加后");
        showStatus(s00, s01, s10, s11);

        //半字节替代
        nibbleSubstitution(s00);
        nibbleSubstitution(s01);
        nibbleSubstitution(s10);
        nibbleSubstitution(s11);
        System.out.print("半字节替代后");
        showStatus(s00, s01, s10, s11);

        //行位移
        swapRows(s10,s11);
        System.out.print("行位移后");
        showStatus(s00, s01, s10, s11);

        //轮密钥加
        // 创建一个新的数组，长度是result1的长度
        int[] mergedArray2 = new int[result1.length];
        // 合并数组
        System.arraycopy(s00, 0, mergedArray2, 0, 4);
        System.arraycopy(s10, 0, mergedArray2, 4, 4);
        System.arraycopy(s01, 0, mergedArray2, 8, 4);
        System.arraycopy(s11, 0, mergedArray2, 12, 4);
        int[] result3 = xor(mergedArray2,k3);
        // 重新分割result2到s00, s01, s10, s11
        System.arraycopy(result3, 0, s00, 0, 4);
        System.arraycopy(result3, 4, s10, 0, 4);
        System.arraycopy(result3, 8, s01, 0, 4);
        System.arraycopy(result3, 12, s11, 0, 4);
        System.out.print("轮密钥加后加密完成，");
        showStatus(s00, s01, s10, s11);

        String ciphertext = intArrayTobinaryString(result3);
        return ciphertext;
    }

    public static String decrypt(String ciphertext, String key){
        // 将明文和密钥转换为整数数组
        int[] bciphertext = binaryStringTointArray(ciphertext);
        System.out.println("开始解密， 密文为: " + ciphertext);
        int[] k1 = binaryStringTointArray(key);
        // 确保密钥有效
        if (k1.length != 16) {
            throw new IllegalArgumentException("密钥必须为 16 位长。");
        }

        //生成轮密钥
        int[][] initialKey = new int[2][8];
        System.arraycopy(k1, 0, initialKey[0], 0, 8); // 将前8个元素复制到initialKey[0]
        System.arraycopy(k1, 8, initialKey[1], 0, 8); // 将后8个元素复制到initialKey[1]
        int[][] roundKey2 = new int[2][8];
        int[][] roundKey3 = new int[2][8];

        roundKey2[0] = xor(initialKey[0], gFunction(initialKey[1], rcon1));
        roundKey2[1] = xor(roundKey2[0], initialKey[1]);
        roundKey3[0] = xor(roundKey2[0], gFunction(roundKey2[1], rcon2));
        roundKey3[1] = xor(roundKey3[0], roundKey2[1]);

        int[] k2 = new int[16];
        int[] k3 = new int[16];
        System.arraycopy(roundKey2[0], 0, k2, 0, 8); // 将roundKey2[0]复制到k2的前8个位置
        System.arraycopy(roundKey2[1], 0, k2, 8, 8); // 将roundKey2[1]复制到k2的后8个位置
        System.arraycopy(roundKey3[0], 0, k3, 0, 8); // 将roundKey3[0]复制到k3的前8个位置
        System.arraycopy(roundKey3[1], 0, k3, 8, 8); // 将roundKey3[1]复制到k3的后8个位置
        showKey(k1, k2, k3);

        //轮密钥加
        //轮密钥加
        int[] result1 = xor(bciphertext,k3);
        //分为四个半字节
        int[] s00 = new int[4];
        int[] s01 = new int[4];
        int[] s10 = new int[4];
        int[] s11 = new int[4];
        // 使用System.arraycopy将result1的前4个元素复制到s00
        System.arraycopy(result1, 0, s00, 0, 4);
        // 使用System.arraycopy将result1的第4个到第7个元素复制到s10
        System.arraycopy(result1, 4, s10, 0, 4);
        // 使用System.arraycopy将result1的第8个到第11个元素复制到s01
        System.arraycopy(result1, 8, s01, 0, 4);
        // 使用System.arraycopy将result1的第12个到第15个元素复制到s11
        System.arraycopy(result1, 12, s11, 0, 4);
        System.out.print("轮密钥加后");
        showStatus(s00, s01, s10, s11);

        //逆行位移
        swapRows(s10,s11);
        System.out.print("逆行位移后");
        showStatus(s00, s01, s10, s11);

        //逆半字节替代
        inNnibbleSubstitution(s00);
        inNnibbleSubstitution(s01);
        inNnibbleSubstitution(s10);
        inNnibbleSubstitution(s11);
        System.out.print("逆半字节替代后");
        showStatus(s00, s01, s10, s11);

        //轮密钥加
        int[] mergedArray = new int[result1.length];
        // 合并数组
        System.arraycopy(s00, 0, mergedArray, 0, 4);
        System.arraycopy(s10, 0, mergedArray, 4, 4);
        System.arraycopy(s01, 0, mergedArray, 8, 4);
        System.arraycopy(s11, 0, mergedArray, 12, 4);
        int[] result2 = xor(mergedArray,k2);
        // 重新分割result2到s00, s01, s10, s11
        System.arraycopy(result2, 0, s00, 0, 4);
        System.arraycopy(result2, 4, s10, 0, 4);
        System.arraycopy(result2, 8, s01, 0, 4);
        System.arraycopy(result2, 12, s11, 0, 4);
        System.out.print("轮密钥加后");
        showStatus(s00, s01, s10, s11);

        //逆列混淆
        inMixColumn(s00, s01, s10, s11);
        System.out.print("逆列混淆后");
        showStatus(s00, s01, s10, s11);

        //逆行位移
        swapRows(s10,s11);
        System.out.print("逆行位移后");
        showStatus(s00, s01, s10, s11);

        //逆半字节代替
        inNnibbleSubstitution(s00);
        inNnibbleSubstitution(s01);
        inNnibbleSubstitution(s10);
        inNnibbleSubstitution(s11);
        System.out.print("逆半字节替代后");
        showStatus(s00, s01, s10, s11);

        //轮密钥加
        // 创建一个新的数组，长度是result1的长度
        int[] mergedArray2 = new int[result1.length];
        // 合并数组
        System.arraycopy(s00, 0, mergedArray2, 0, 4);
        System.arraycopy(s10, 0, mergedArray2, 4, 4);
        System.arraycopy(s01, 0, mergedArray2, 8, 4);
        System.arraycopy(s11, 0, mergedArray2, 12, 4);
        int[] result3 = xor(mergedArray2,k1);
        // 重新分割result2到s00, s01, s10, s11
        System.arraycopy(result3, 0, s00, 0, 4);
        System.arraycopy(result3, 4, s10, 0, 4);
        System.arraycopy(result3, 8, s01, 0, 4);
        System.arraycopy(result3, 12, s11, 0, 4);
        System.out.print("轮密钥加后解密完成，");
        showStatus(s00, s01, s10, s11);

        String plaintext = intArrayTobinaryString(result3);
        return plaintext;
    }


    //按位异或 轮密钥加
    private static int[] xor(int[] data1, int[] data2) {
        int[] result = new int[data1.length];
        for (int i = 0; i < data1.length; i++) {
            result[i] = data1[i] ^ data2[i];
        }
        return result;
    }

    //将字符串转化为整数数组
    private static int[] binaryStringTointArray(String binaryString) {
        int[] result = new int[binaryString.length()];
        for (int i = 0; i < binaryString.length(); i++) {
            result[i] = binaryString.charAt(i) - '0';
        }
        return result;
    }

    //将整数数组转化成字符串
    public static String intArrayTobinaryString(int[] array) {
        if (array == null) {
            return "null";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < array.length; i++) {
            sb.append(array[i]);
            if (i < array.length - 1) {
                sb.append(""); // 在元素之间不添加任何字符
            }
        }
        return sb.toString();
    }

    //将0-15转化为四位二进制数组
    public static int[] intToBinaryArray(int number) {
        if (number <0 || number >15) {
            throw new IllegalArgumentException("Number must be between0 and15.");
        }
        int[] binaryArray = new int[4];
        for (int i =0; i <4; i++) {
            binaryArray[3 - i] = (number >> i) &1; // 使用右移运算符获取当前位
        }
        return binaryArray;
    }

    //半字节替代
    public static void nibbleSubstitution(int[] s){
        int i = s[0]*2 + s[1];
        //System.out.print("行:"+i);
        int j = s[2]*2 + s[3];
        //System.out.print("列:"+j);
        int replacementValue = SBOX1[i][j]; // 获取SBOX1中的替换值
        //System.out.println("替换为"+replacementValue);
        int[] binaryArray = intToBinaryArray(replacementValue); // 将替换值转换为二进制数组

        // 更新s数组的值
        for (int k = 0; k < binaryArray.length; k++) {
            s[k] = binaryArray[k];
            //System.out.print(s[k]);
        }
        //System.out.println();
    }

    //逆半字节替代
    private  static void inNnibbleSubstitution(int[] s){
        int i = s[0]*2 + s[1];
        int j = s[2]*2 + s[3];
        int replacementValue = SBOX2[i][j]; // 获取SBOX2中的替换值
        int[] binaryArray = intToBinaryArray(replacementValue); // 将替换值转换为二进制数组

        // 更新s数组的值
        for (int k = 0; k < binaryArray.length; k++) {
            s[k] = binaryArray[k];
        }
    }

    //行位移
    public static void swapRows(int[] array1, int[] array2) {
        if (array1.length != array2.length) {
            throw new IllegalArgumentException("Arrays must be of the same length.");
        }
        int[] temp = new int[array1.length];
        System.arraycopy(array1, 0, temp, 0, array1.length);
        System.arraycopy(array2, 0, array1, 0, array2.length);
        System.arraycopy(temp, 0, array2, 0, temp.length);
    }

    //列混淆
    public static void mixColumn(int[] s00, int[] s01, int[] s10, int[] s11){
        int S00 = s00[0]*8 + s00[1]*4 + s00[2]*2 + s00[3];
        int S01 = s01[0]*8 + s01[1]*4 + s01[2]*2 + s01[3];
        int S10 = s10[0]*8 + s10[1]*4 + s10[2]*2 + s10[3];
        int S11 = s11[0]*8 + s11[1]*4 + s11[2]*2 + s11[3];

        int[] temp00 = xor(s00, intToBinaryArray(MultiplicationTable[4][S10]));
        int[] temp10 = xor(s10, intToBinaryArray(MultiplicationTable[4][S00]));
        int[] temp01 = xor(s01, intToBinaryArray(MultiplicationTable[4][S11]));
        int[] temp11 = xor(s11, intToBinaryArray(MultiplicationTable[4][S01]));

        // 将临时数组的值复制回原始数组
        System.arraycopy(temp00, 0, s00, 0, temp00.length);
        System.arraycopy(temp10, 0, s10, 0, temp10.length);
        System.arraycopy(temp01, 0, s01, 0, temp01.length);
        System.arraycopy(temp11, 0, s11, 0, temp11.length);
    }

    //逆列混淆
    public static void inMixColumn(int[] s00, int[] s01, int[] s10, int[] s11){
        int S00 = s00[0]*8 + s00[1]*4 + s00[2]*2 + s00[3];
        int S01 = s01[0]*8 + s01[1]*4 + s01[2]*2 + s01[3];
        int S10 = s10[0]*8 + s10[1]*4 + s10[2]*2 + s10[3];
        int S11 = s11[0]*8 + s11[1]*4 + s11[2]*2 + s11[3];

        int[] temp00 = xor(intToBinaryArray(MultiplicationTable[9][S00]), intToBinaryArray(MultiplicationTable[2][S10]));
        int[] temp10 = xor(intToBinaryArray(MultiplicationTable[2][S00]), intToBinaryArray(MultiplicationTable[9][S10]));
        int[] temp01 = xor(intToBinaryArray(MultiplicationTable[9][S01]), intToBinaryArray(MultiplicationTable[2][S11]));
        int[] temp11 = xor(intToBinaryArray(MultiplicationTable[2][S01]), intToBinaryArray(MultiplicationTable[9][S11]));

        // 将临时数组的值复制回原始数组
        System.arraycopy(temp00, 0, s00, 0, temp00.length);
        System.arraycopy(temp10, 0, s10, 0, temp10.length);
        System.arraycopy(temp01, 0, s01, 0, temp01.length);
        System.arraycopy(temp11, 0, s11, 0, temp11.length);
    }




    // g函数
    public static int[] gFunction(int[] keyPart, int[] rcon) {
        int[] temp = new int[8];
        System.arraycopy(keyPart, 0, temp, 0, 8);
        // Left shift
        for (int i = 0; i < 4; i++) {
            int tt = temp[(i + 4) % 8];
            temp[(i + 4) % 8] = temp[i];
            temp[i] = tt;
        }
        // 分割temp数组
        int[] firstHalf = new int[4];
        int[] secondHalf = new int[4];
        System.arraycopy(temp, 0, firstHalf, 0, 4);
        System.arraycopy(temp, 4, secondHalf, 0, 4);
        nibbleSubstitution(firstHalf);
        nibbleSubstitution(secondHalf);
        // 将firstHalf的元素复制到combined数组的前4个位置
        System.arraycopy(firstHalf, 0, temp, 0, 4);
        // 将secondHalf的元素复制到combined数组的后4个位置
        System.arraycopy(secondHalf, 0, temp, 4, 4);

        return xor(temp, rcon);
    }

    //日志
    public static void showKey(int[] k1, int[] k2, int[] k3) {
        // 打印第一个数组
        System.out.print("Key 1: ");
        for (int i = 0; i < k1.length; i++) {
            System.out.print(k1[i]);
            if ((i + 1) % 8 == 0) {
                System.out.print(" "); // 每8个元素后打印一个空格
            }
        }
        System.out.println();

        // 打印第二个数组
        System.out.print("Key 2: ");
        for (int i = 0; i < k2.length; i++) {
            System.out.print(k2[i]);
            if ((i + 1) % 8 == 0) {
                System.out.print(" "); // 每8个元素后打印一个空格
            }
        }
        System.out.println();

        // 打印第三个数组
        System.out.print("Key 3: ");
        for (int i = 0; i < k3.length; i++) {
            System.out.print(k3[i]);
            if ((i + 1) % 8 == 0) {
                System.out.print(" "); // 每8个元素后打印一个空格
            }
        }
        System.out.println();
    }
    public static void showStatus(int[] s00, int[] s01, int[] s10, int[] s11){
        System.out.print("当前状态: ");
        System.out.println();
        // 打印第一排，s00 和 s01
        for (int value : s00) {
            System.out.print(value);
        }
        System.out.print(" "); // s00 和 s01 之间添加空格
        for (int value : s01) {
            System.out.print(value);
        }
        System.out.println(); // 换行

        // 打印第二排，s10 和 s11
        for (int value : s10) {
            System.out.print(value);
        }
        System.out.print(" "); // s10 和 s11 之间添加空格
        for (int value : s11) {
            System.out.print(value);
        }
        System.out.println(); // 换行
    }

    public static int generateRandomIV() {
        Random random = new Random();
        return random.nextInt(0xFFFF + 1);
    }

    public static String ToBinary(int num,int digit) {  //十进制转二进制（特定位数）
        String binStr = "";
        for (int i = digit-1; i >= 0; i--) {
            binStr += (num >> i) & 1;
        }
        return binStr;
    }

    public static List<String> convertToBlocks(String binaryString) {
        // 检查输入字符串是否为空或长度不是16的倍数
        if (binaryString == null || binaryString.length() % 16 != 0) {
            throw new IllegalArgumentException("输入字符串的长度必须是16的倍数");
        }

        // 初始化字符串组
        List<String> blocks = new ArrayList<>();

        // 循环遍历字符串，每次处理16个字符
        for (int i = 0; i < binaryString.length(); i += 16) {
            // 提取16位的子字符串
            String block = binaryString.substring(i, i + 16);
            // 将子字符串添加到组中
            blocks.add(block);
        }

        return blocks;
    }
    public static int[] intTo16BinaryArray(int number) {
        int[] binaryArray = new int[16]; // 创建一个16位的数组
        for (int i = 0; i < 16; i++) { // 从0到15遍历数组
            binaryArray[15 - i] = (number >> i) & 1; // 右移i位并取最低位，将结果放在数组的相应位置
        }
        return binaryArray;
    }
    public static List<String> cbcEncrypt(String plaintext, String keyStr, int iv) {
        List<String> ciphertextBlocks = new ArrayList<>();
        List<String> plaintextBlocks = convertToBlocks(plaintext);
        int[] IV = intTo16BinaryArray(iv);
        int[] previousBlock = IV;

        System.out.println("初始向量 (IV): " + intArrayTobinaryString(IV));
        for (int x = 0; x < plaintextBlocks.size(); x++) {
            // 将明文块与前一个密文块（或IV）进行异或运算
            int[] intcip = binaryStringTointArray(plaintextBlocks.get(x));
            System.out.println("明文块 " + x + ": " + intArrayTobinaryString(intcip));
            int[] xoredBlock = xor(intcip, previousBlock);
            System.out.println("异或后的块 " + x + ": " + intArrayTobinaryString(xoredBlock));
            String xoredStringBlock = intArrayTobinaryString(xoredBlock);
            System.out.println("异或后的块 (二进制字符串) " + x + ": " + xoredStringBlock);

            // 加密异或后的块
            String encryptedBlock = encrypt(xoredStringBlock, keyStr);
            System.out.println("加密后的块 (二进制字符串) " + x + ": " + encryptedBlock);
            // 将加密块的二进制字符串添加到密文列表
            ciphertextBlocks.add(encryptedBlock);
            // 更新前一个块为当前加密块的二进制整数形式
            previousBlock = binaryStringTointArray(encryptedBlock);
            System.out.println("更新后的前一个块 (二进制整数形式): " + intArrayTobinaryString(previousBlock));
        }

        return ciphertextBlocks;
    }

    // CBC模式解密
    public static List<String> cbcDecrypt(String ciphertext, String keyStr, int iv) {
        List<String> plaintextBlocks = new ArrayList<>();
        List<String> ciphertextBlocks = convertToBlocks(ciphertext);
        int[] IV = intTo16BinaryArray(iv);
        int[] previousBlock = IV;

        System.out.println("初始向量 (IV): " + intArrayTobinaryString(IV));
        for (int x = 0; x < ciphertextBlocks.size(); x++) {
            // 解密当前密文块
            String decryptedBlock = decrypt(ciphertextBlocks.get(x), keyStr);
            System.out.println("解密块 " + x + ": " + decryptedBlock);

            int[] intdecryptedBlock = binaryStringTointArray(decryptedBlock);
            System.out.println("解密块 (整数数组) " + x + ": " + intArrayTobinaryString(intdecryptedBlock));

            // 将解密块与前一个密文块（或IV）进行异或运算
            int[] xored = xor(intdecryptedBlock, previousBlock);
            System.out.println("异或后的块 (整数数组) " + x + ": " + intArrayTobinaryString(xored));
            String plaintext = intArrayTobinaryString(xored);
            System.out.println("明文块 " + x + ": " + plaintext);

            // 将得到的明文块添加到明文字符串
            plaintextBlocks.add(plaintext);
            // 更新前一个块为当前密文块
            previousBlock = binaryStringTointArray(ciphertextBlocks.get(x));
            System.out.println("更新后的前一个块 (二进制整数形式): " + intArrayTobinaryString(previousBlock));
        }

        return plaintextBlocks;
    }
    //测试
    public static void main(String[] args){

    }
    //将字符串转化为 二进制十六位字符串 组
    public static String[] charToBinaryStringArray(String input) {
        // 检查输入长度是否为偶数
        if (input.length() % 2 != 0) {
            throw new IllegalArgumentException("Input length must be even.");
        }

        int length = input.length() / 2;
        String[] binaryStrings = new String[length];

        for (int i = 0; i < input.length(); i += 2) {
            // 将两个字符转换为一个整数
            int decimalValue = (input.charAt(i) << 8) | input.charAt(i + 1);

            // 将整数转换为16位的二进制字符串
            StringBuilder binaryBuilder = new StringBuilder();
            for (int j = 15; j >= 0; j--) {
                binaryBuilder.append((decimalValue >> j) & 1);
            }

            // 将二进制字符串填充到16位，如果不足16位则在前面补0
            String binaryString = String.format("%16s", binaryBuilder.toString()).replace(' ', '0');
            binaryStrings[i / 2] = binaryString;
        }

        return binaryStrings;
    }

    public static String binaryStringArrayToString(String[] binaryStrings) {
        StringBuilder output = new StringBuilder();

        for (String binaryString : binaryStrings) {
            // 检查二进制字符串是否为16位
            if (binaryString.length() != 16) {
                throw new IllegalArgumentException("Each binary string must be 16 characters long.");
            }

            // 将16位二进制字符串转换为整数
            int decimalValue = 0;
            for (int j = 0; j < 16; j++) {
                decimalValue |= (binaryString.charAt(15 - j) == '1' ? 1 : 0) << j;
            }

            // 将整数转换为两个字符并添加到输出中
            output.append((char) ((decimalValue & 0xFF00) >> 8));
            output.append((char) (decimalValue & 0x00FF));
        }

        return output.toString();
    }
    public static List<String> stringToBinaryList(String input) {
        // 用于存储每组长度为16的二进制字符串
        List<String> binaryList = new ArrayList<>();

        // 将字符串转换为二进制
        StringBuilder binaryString = new StringBuilder();
        for (char ch : input.toCharArray()) {
            String binaryChar = String.format("%08d", Integer.parseInt(Integer.toBinaryString(ch)));
            binaryString.append(binaryChar);
        }

        // 按照每16位分组
        for (int i = 0; i < binaryString.length(); i += 16) {
            int end = Math.min(i + 16, binaryString.length());
            binaryList.add(binaryString.substring(i, end));
        }

        return binaryList;
    }

    public static String convertToBinaryString(List<String> binaryList) {
        StringBuilder completeBinaryString = new StringBuilder();

        for (String binary : binaryList) {
            completeBinaryString.append(binary);
        }

        return completeBinaryString.toString();
    }
    public static String binaryListToString(List<String> binaryList) {
        StringBuilder originalString = new StringBuilder();

        // 将每个16位二进制字符串转换为字符
        for (String binary : binaryList) {
            for (int i = 0; i < binary.length(); i += 8) {
                // 提取每8位并转换为字符
                String byteString = binary.substring(i, Math.min(i + 8, binary.length()));
                char ch = (char) Integer.parseInt(byteString, 2);
                originalString.append(ch);
            }
        }

        return originalString.toString();
    }
}

