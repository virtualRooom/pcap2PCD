#include <utils/argparse.hpp>
#include <velodyne/PointCloudReader.hpp>

using namespace std;
using namespace Eigen;

bool makeDir(std::string save_dir);

int main(int argc, const char **argv)
{
    ArgumentParser parser;
    parser.addArgument("-p", "--pcap", true);
    parser.addArgument("-d", "--data_type", true);
    parser.addArgument("-b", "--begin_id");
    parser.addArgument("-e", "--end_id");
    parser.addArgument("-o", "--output_dir");
    parser.parse(argc, argv);

    int begin_id = 0;
    int end_id = -1;

    if(parser.count("begin_id"))
        begin_id = parser.get<int>("begin_id");
    if(parser.count("end_id"))
        end_id = parser.get<int>("end_id");

    PointCloudReader reader;
    reader.setPcapFile(parser.get("pcap"));
    reader.setDataType(parser.get<int>("data_type"));   // 0:VLP-16, 1:HDL-32, 2:VLP-32c
    reader.setVoxelSize(0.03); // 默认单帧分辨率3cm
    reader.setValidDistance(25.0); // 默认有效距离25m
    reader.init();

    string out_dir = "output_pcd";
    if(parser.count("output_dir"))
        out_dir = parser.get<std::string>("output_dir");
    makeDir(out_dir);

    PointCloud::Ptr cloud(new PointCloud);
    long long frameID = begin_id;
    end_id = end_id == -1 ? reader.getTotalFrame() : end_id;
    consoleProgress(0);

    while (frameID <= end_id && reader.readPointCloud(cloud, frameID))
    {
        pcl::io::savePCDFileBinaryCompressed<PointType>(out_dir + "/" + to_string(frameID++) + ".pcd", *cloud);
        consoleProgress(frameID, begin_id, end_id);
    }

    cout << "压缩的PCD文件保存至: " << out_dir << endl;

    return 0;
}

// 指定一个保存的文件夹，将会以帧号命名，存下压缩的二进制PCD
bool makeDir(std::string save_dir)
{
    // 建立文件夹
    char DirName[256];
    strcpy(DirName, save_dir.c_str());
    int i, len = strlen(DirName);
    if (DirName[len - 1] != '/')
        strcat(DirName, "/");
    len = strlen(DirName);
    for (i = 1; i < len; i++)
    {
        if (DirName[i] == '/' || DirName[i] == '\\')
        {
            DirName[i] = 0;
            if (access(DirName, 0) != 0) //存在则返回0
            {
                if (mkdir(DirName, 0755) == -1)
                {
                    perror("mkdir   error");
                    return false;
                }
            }
            DirName[i] = '/';
        }
    }
    
    return true;
}
