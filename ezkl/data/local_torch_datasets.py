import glob
import numpy as np
import torch
import cv2
from torch.utils.data import Dataset, DataLoader

# https://medium.com/analytics-vidhya/creating-a-custom-dataset-and-dataloader-in-pytorch-76f210a1df5d

class TrainDataset(Dataset):
    def __init__(self,path):
        self.imgs_path = path
        file_list = glob.glob(self.imgs_path + "*")
        self.data = []
        for class_path in file_list:
            class_name = class_path.split("/")[-1]
            for img_path in glob.glob(class_path + "/*.png"):
                self.data.append((img_path, int(class_name)))
        print(self.data)
        self.img_dim = (800, 603)

    def __len__(self):
        return len(self.data)
     
    def __getitem__(self, idx):
        img_path, class_id = self.data[idx]
        img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
        # img = cv2.imread(img_path)
        # print("IMG HAS SIZE {}".format(img.shape))
        img = cv2.resize(img, self.img_dim)
        img_tensor = torch.from_numpy(img)
        img_tensor = img_tensor.reshape((800,603,1))
        img_tensor = img_tensor.permute(2, 0, 1)
        # print("IMG HAS SIZE {}".format(img.shape))
        # print("IMG TENSOR HAS SIZE {}".format(img_tensor.shape))
        class_id = torch.tensor(class_id)
        # img_tensor = img_tensor.permute(2, 0, 1)
        return (img_tensor, class_id)
    

train_dataset = TrainDataset("/home/benjamin/circuit_breaker/ezkl/data/train_dataset/")
test_dataset = TrainDataset("/home/benjamin/circuit_breaker/ezkl/data/test_dataset/")
number_of_categories = 3

# print("GET ITEM 0: ", train_dataset.__getitem__(0)[1])


train_loader = DataLoader(train_dataset, batch_size=256)

test_loader = DataLoader(test_dataset, batch_size=1)


print(len(train_loader))