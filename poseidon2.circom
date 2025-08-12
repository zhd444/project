include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// 有限域参数 (BN254)
constant p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

// 轮常量 - 根据参考文档1的Table1生成
constant RC = [
    // 前4轮完全轮常量
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9],
    [10, 11, 12],
    // 部分轮常量
    [13, 14, 15],
    [16, 17, 18],
    [19, 20, 21],
    [22, 23, 24],
    // 后4轮完全轮常量
    [25, 26, 27],
    [28, 29, 30],
    [31, 32, 33],
    [34, 35, 36]
];

// 混合层矩阵
constant M = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
];

// 模p加法
template AddModP() {
    signal input a;
    signal input b;
    signal output out;
    
    out <== (a + b) % p;
}

// 模p乘法
template MulModP() {
    signal input a;
    signal input b;
    signal output out;
    
    out <== (a * b) % p;
}

// 模p幂运算 (x^5 mod p)
template Pow5ModP() {
    signal input x;
    signal output out;
    signal t1, t2;
    
    t1 <== (x * x) % p;       // x^2
    t2 <== (t1 * x) % p;      // x^3
    out <== (t2 * t1) % p;    // x^5
}

// 添加轮常量
template AddRoundConstant(t) {
    signal input state[t];
    signal input constants[t];
    signal output out[t];
    
    for (var i = 0; i < t; i++) {
        component add = AddModP();
        add.a <== state[i];
        add.b <== constants[i];
        out[i] <== add.out;
    }
}

// S盒替换
template SubWords(t, partialRound) {
    signal input state[t];
    signal output out[t];
    
    for (var i = 0; i < t; i++) {
        if (partialRound == 0 || i == 0) {  // 完全轮所有元素都替换，部分轮只替换第一个元素
            component sbox = Pow5ModP();
            sbox.x <== state[i];
            out[i] <== sbox.out;
        } else {
            out[i] <== state[i];
        }
    }
}

// 线性混合层
template MixLayer(t) {
    signal input state[t];
    signal output out[t];
    
    for (var i = 0; i < t; i++) {
        signal sum;
        sum <== 0;
        for (var j = 0; j < t; j++) {
            component mul = MulModP();
            mul.a <== state[j];
            mul.b <== M[i][j];
            component add = AddModP();
            add.a <== sum;
            add.b <== mul.out;
            sum <== add.out;
        }
        out[i] <== sum;
    }
}

// Poseidon2哈希函数
template Poseidon2Hash(t, r, fullRounds, partialRounds) {
    signal input inputs[r];  // 隐私输入：哈希原象（rate个元素）
    signal output hash;      // 公开输出：哈希值
    
    // 初始化状态
    signal state[t];
    for (var i = 0; i < r; i++) {
        state[i] <== inputs[i];
    }
    state[r] <== 0;  // capacity初始化为0
    
    // 前半部分完全轮
    for (var r = 0; r < fullRounds/2; r++) {
        component arc = AddRoundConstant(t);
        for (var i = 0; i < t; i++) {
            arc.state[i] <== state[i];
            arc.constants[i] <== RC[r][i];
        }
        
        component sw = SubWords(t, 0);  // 0表示完全轮
        for (var i = 0; i < t; i++) {
            sw.state[i] <== arc.out[i];
        }
        
        component ml = MixLayer(t);
        for (var i = 0; i < t; i++) {
            ml.state[i] <== sw.out[i];
        }
        
        for (var i = 0; i < t; i++) {
            state[i] <== ml.out[i];
        }
    }
    
    // 部分轮
    for (var r = 0; r < partialRounds; r++) {
        component arc = AddRoundConstant(t);
        for (var i = 0; i < t; i++) {
            arc.state[i] <== state[i];
            arc.constants[i] <== RC[fullRounds/2 + r][i];
        }
        
        component sw = SubWords(t, 1);  // 1表示部分轮
        for (var i = 0; i < t; i++) {
            sw.state[i] <== arc.out[i];
        }
        
        component ml = MixLayer(t);
        for (var i = 0; i < t; i++) {
            ml.state[i] <== sw.out[i];
        }
        
        for (var i = 0; i < t; i++) {
            state[i] <== ml.out[i];
        }
    }
    
    // 后半部分完全轮
    for (var r = 0; r < fullRounds/2; r++) {
        component arc = AddRoundConstant(t);
        for (var i = 0; i < t; i++) {
            arc.state[i] <== state[i];
            arc.constants[i] <== RC[fullRounds/2 + partialRounds + r][i];
        }
        
        component sw = SubWords(t, 0);  // 0表示完全轮
        for (var i = 0; i < t; i++) {
            sw.state[i] <== arc.out[i];
        }
        
        component ml = MixLayer(t);
        for (var i = 0; i < t; i++) {
            ml.state[i] <== sw.out[i];
        }
        
        for (var i = 0; i < t; i++) {
            state[i] <== ml.out[i];
        }
    }
    
    // 输出哈希值（取capacity部分）
    hash <== state[r];
}

// 主电路：验证哈希原象与哈希值的关系
template Main() {
    // 配置参数
    constant t = 3;       // 状态大小
    constant r = 2;       // 率 (t-1)
    constant fullRounds = 8;  // 完全轮数
    constant partialRounds = 4;  // 部分轮数
    
    // 隐私输入：哈希原象（2个元素）
    signal private input preimage[r];
    
    // 公开输入：预期的哈希值
    signal public input expectedHash;
    
    // 计算哈希值
    component poseidon = Poseidon2Hash(t, r, fullRounds, partialRounds);
    for (var i = 0; i < r; i++) {
        poseidon.inputs[i] <== preimage[i];
    }
    
    // 验证计算的哈希值与预期的哈希值是否一致
    expectedHash === poseidon.hash;
}

// 实例化主电路
component main = Main();
