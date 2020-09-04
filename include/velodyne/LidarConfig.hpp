#pragma once
#include <vector>

// 对应于实验室采用的三代不同类型的激光雷达
enum LidarType
{
    VLP16, HDL32, VLP32
};

class LidarConfig
{
private:
    int scanLineNum[3] = {16, 32, 32};
    //=========================================//
    // 线号对应表, 来源velodyne的用户手册
    //=========================================//
    std::vector<int> vlp16_scanID = {
        0, 8,  1, 9,  2, 10, 3, 11,
        4, 12, 5, 13, 6, 14, 7, 15
    };

    std::vector<int> hdl32_scanID = {
        0,  16, 1,  17, 2,  18, 3,  19,
        4,  20, 5,  21, 6,  22, 7,  23,
        8,  24, 9,  25, 10, 26, 11, 27,
        12, 28, 13, 29, 14, 30, 15, 31
    };

    std::vector<int> vlp32_map = {
        0,  3, 4,  7, 8,  11, 12,  16,
        15,  19, 20, 24, 23,  27, 28,  2,
        31,  1, 6,  10, 5, 9, 14, 18,
        13, 17, 22, 21, 26, 25, 30, 29
    };

    std::vector<int> scanIDList;

public:
    LidarConfig(int lidarType = VLP32):
        _nScanRings(scanLineNum[lidarType])
    {
        switch (lidarType)
        {
        case VLP16:
            scanIDList = vlp16_scanID;
            _upperBound = 15.0;
            _lowerBound = 15.0;
            break;
        case HDL32:
            scanIDList = hdl32_scanID;
            _upperBound = 10.0;
            _lowerBound = -30.0;
            break;
        case VLP32:
            scanIDList.resize(32);

            for(int i=0; i<32; ++i)
				scanIDList[vlp32_map[i]] = i;
            _upperBound = 15.0;
            _lowerBound = -25.0;
            break;
        default:
            break;
        }    
    }
    
    // 根据pcap中的线序号得到扫描线的编号
    int getScanID(int lineNum)  { scanIDList[lineNum]; }
    std::vector<int> getScanIDList() { return scanIDList;}

    // 根据角度计算扫描线的编号
    int getScanID(float x, float y, float z)
    {
        float p_x = y, p_y = z, p_z = x;
        float _factor = (_nScanRings - 1) / (_upperBound - _lowerBound);
        float angle = std::atan(p_y / std::sqrt(p_x * p_x + p_z * p_z));
        int scanID = int(((angle * 180 / M_PI) - _lowerBound) * _factor + 0.5); // 加0.5表示四舍五入
        if(scanID > _nScanRings) scanID = _nScanRings;
        else if(scanID < 0) scanID = 0;
        return scanID;
    }

    int getScanNum(){  return _nScanRings;}

private:
    int _nScanRings;
    float _upperBound;
    float _lowerBound;
};