# Importing the PIL library
from PIL import Image
from PIL import ImageDraw, ImageFont
from random import randint
import pandas as pd
import numpy as np
import os
import glob
# Open an Image
# Call draw Method to add 2D graphics in an image

font = ImageFont.truetype("font/Gidole-Regular.ttf", size=20)
 
# Add Text to an image
 
# Display edited image
# img.show()
 
# Save the edited image

categories = {
    0: lambda income : 0 <= income <= 50000,
    1: lambda income : 50000 < income <= 100000,
    2: lambda income : 100000 < income < 151000,
}

for class_id in categories:
    files = glob.glob("test_dataset/{}/*".format(class_id))
    for f in files:
        os.remove(f)
    files = glob.glob("train_dataset/{}/*".format(class_id))
    for f in files:
        os.remove(f)

    os.rmdir("test_dataset/{}".format(class_id))
    os.rmdir("train_dataset/{}".format(class_id))

    os.mkdir("test_dataset/{}".format(class_id))
    os.mkdir("train_dataset/{}".format(class_id))

def get_label_for(categories, income):
    for value in categories.keys():
        if categories[value](income):
            return value

train_dataset_size = 1000
test_dataset_size = 10

train_dataset = [0]*train_dataset_size
test_dataset = [0]*test_dataset_size

for sample_index in range(train_dataset_size):

    income = randint(1,3)*50000


    # img = Image.open('/home/benjamin/circuit_breaker/ezkl/data/template/income_sheet_template.jpg')
    # img = Image.new('RGB', (603,800))
    img = Image.new('RGB', (100,20))
    I1 = ImageDraw.Draw(img)
    # I1.text((510, 758), str(income), fill=(255, 0, 0), font=font)  
    I1.text((0, 0), str(income), fill=(255, 0, 0), font=font)  
    img.save("train_dataset/{}/{}.png".format(get_label_for(categories, income), sample_index))
    img_array = np.array(img)

    train_dataset[sample_index] = (img_array,get_label_for(categories, income))

train_dataset_df = pd.Series(train_dataset)
train_dataset_df.to_csv("train_dataset.csv")

for sample_index in range(test_dataset_size):

    income = randint(1,3)*50000

    # img = Image.open('/home/benjamin/circuit_breaker/ezkl/data/template/income_sheet_template.jpg')
    # img = Image.new('RGB', (603,800))
    img = Image.new('RGB', (100,20))

    I1 = ImageDraw.Draw(img)
    # I1.text((510, 758), str(income), fill=(255, 0, 0), font=font)  
    I1.text((0, 0), str(income), fill=(255, 0, 0), font=font)  

    img.save("test_dataset/{}/{}.png".format(get_label_for(categories, income), sample_index))

    img_array = np.array(img)
    # print(img_array.shape)
    test_dataset[sample_index] = (img_array,get_label_for(categories, income))


test_dataset_df = pd.Series(test_dataset)
test_dataset_df.to_csv("test_dataset.csv")