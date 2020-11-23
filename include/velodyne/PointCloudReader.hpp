#pragma once

#include <velodyne/LidarConfig.hpp>
#include <velodyne/PcapReader.hpp>
#include <pcl/point_cloud.h>
#include <pcl/io/pcd_io.h>
#include <pcl/common/transforms.h>

//=========================================//
// data_n 数组内的数据说明:
// - data_n[0] 时间戳整数部分(秒)
// - data_n[1] 时间戳小数部分(微秒)
// - data_n[2] 线束编号(LOAM算法必需)
// - data_n[3] 有效距离
//=========================================//
using PointType = pcl::PointXYZINormal;
using PointCloud = pcl::PointCloud<PointType>;


class PointCloudReader
{
public:
	PointCloudReader() : inited(false) {}
	~PointCloudReader() {}
	
	void setPcapFile(std::string _fileName) { fileNamePcap = _fileName; }
	void setDataType(int data_type)
	{
		LidarConfig lidar(data_type);
		scanID = lidar.getScanIDList();
		nScans = lidar.getScanNum();

		switch(data_type)
		{
		case 0:
			setCalibFile("../resource/VLP-16.xml");
			break;
    	case 1:
        	setCalibFile("../resource/HDL-32.xml");
			break;
    	case 2:
        	setCalibFile("../resource/VLP-32c.xml");
			break;
    	default:
        	std::cout << "Data type error!" << std::endl;
		}	
	}

	int getScanNum() { return nScans; }
	int getTotalFrame() { return reader.totalFrame(); }
	void setCalibFile(std::string _fileName) { calibrationPath = _fileName; }
	void setScanGap(int value) {  scanGap = value;}
	void setVoxelSize(float _voxelLeafsize) { voxelLeafsize = _voxelLeafsize; }
	void setValidDistance(float value) { distanceControl = value; }
	void init()
	{
		if (!open_pcap())
		{
			printf("Cannot open pcap file:%s!\n", fileNamePcap.c_str());
			exit(-1);
		}

		if (reader.totalFrame() < minPcapSize)
		{
			printf("The pcap data is too small!\n");
			exit(-1);
		}

		std::cout << "========================= Information of pcap file ============================\n"
				  << "\tpcapfile name = " << getFileName(fileNamePcap) << std::endl
				  << "\tframe number = " << reader.totalFrame() << std::endl
				  << "\tcalibration file = " << calibrationPath << std::endl
				  << "==============================================================================" << std::endl;
		inited = true;
	}

	/***********************************************************
	 * 返回false表示读取失败
	 * 现版本的Mapping程序需要:
	 * - data_n[2]存储线编号
	 * - curvature存储每个点离雷达中心的距离
	 ***********************************************************/
	bool readPointCloud(pcl::PointCloud<PointType>::Ptr _cloud, long long _frameID)
	{
		if (!inited || !_cloud)
			return false;

		if (!reader.capture(frame, _frameID))
		{
			std::cout << "Read frame " << _frameID << "from [ " << fileNamePcap << "] failed." << std::endl;
			return false;
		}

		_cloud->clear();
		for (int n = 0; n < frame.numLine; n++)
		{
			for (int i = 0; i < frame.lines[n].num; i++)
			{
				PointType pt;
				pt.x = (float)frame.lines[n].pPosition[i].x;
				pt.y = (float)frame.lines[n].pPosition[i].y;
				pt.z = (float)frame.lines[n].pPosition[i].z;
				float dist = sqrt(pt.x * pt.x + pt.y * pt.y + pt.z * pt.z);
				if (distanceControl && (dist > distanceControl))
					continue;

				pt.intensity = frame.lines[n].pIntensity[i] + 0.1f;
				double timestamp = frame.lines[n].pTimestamp[i] / 1e6; //秒为单位
				pt.data_n[0] = int(timestamp);						   //整数部分为秒
				pt.data_n[1] = timestamp - pt.data_n[0];			   //微秒
				pt.data_n[2] = scanID[n] + scanGap;
				pt.data_n[3] = dist;
				pt.curvature = pt.data_n[3];
				_cloud->points.push_back(pt);
			}
		}
		_cloud->height = 1;
		_cloud->width = _cloud->points.size();
		_cloud->is_dense = true;
		return true;
	}

private:
 	std::string getFileName(std::string path)
    {
        std::string fullName = path.substr(path.rfind('/') + 1);
        return fullName.substr(0, fullName.find('.'));
    }

	bool open_pcap()
	{
		if (fileNamePcap == "" || calibrationPath == "")
			return false;
		return reader.open(fileNamePcap, calibrationPath);
	}

private:
	int nScans;
	std::vector<int> scanID;
	std::string fileNamePcap;
	std::string calibrationPath;
	float distanceControl = 25.0;
	float voxelLeafsize = 0.03;

	int scanGap = 0;

	pcapReader reader;
	veloFrame frame;
	bool inited;
	const int minPcapSize = 100;
};