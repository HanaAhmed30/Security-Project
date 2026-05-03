import sys
import numpy as np
from PIL import Image, ImageEnhance

def solve(path1: str, path2: str):
    #convert to RGB to ensure consistent processing every pixel has 3 channels (R,G,B)
    img1 = Image.open(path1).convert("RGB")
    img2 = Image.open(path2).convert("RGB")
    
    #same size , so resize if needed    
    if img1.size != img2.size:
        img2 = img2.resize(img1.size, Image.LANCZOS) #LANCZOS is for high-quality
        
    #convert to arrays for fast xor
    arr1 = np.array(img1, dtype=np.uint8)
    arr2 = np.array(img2, dtype=np.uint8)

    xor_result = arr1 ^ arr2

    result = Image.fromarray(xor_result, mode="RGB") #take the xor result and convert back to image
    result.save("output_xor.png")
    #rgb values are 0-255, so inverting : 255 - value
    Image.fromarray(255 - xor_result, mode="RGB").save("output_inverted.png")

    ImageEnhance.Contrast(result).enhance(5.0).save("output_enhanced.png")

    print("Open output_xor.png")
    
if __name__ == "__main__":
 solve(sys.argv[1], sys.argv[2])