import cv2
import numpy as numpy

def isIntersect(rect1, rect2):
	"""
	:param rect1, rect2: turple(x,y,w,h,approxPoly_corner_count) represents a rectangle 
	"""
	# check x
	x_intersect = False
	if rect1[0] <= rect2[0] and rect2[0] - rect1[0] < rect1[2]:
		x_intersect = True
	if rect2[0] <= rect1[0] and rect1[0] - rect2[0] < rect2[2]:
		x_intersect = True	
	# check y
	y_intersect = False
	if rect1[1] <= rect2[1] and rect2[1] - rect1[1] < rect1[3]:
		y_intersect = True
	if rect2[1] <= rect1[1] and rect1[1] - rect2[1] < rect2[3]:
		y_intersect = True
	return x_intersect and y_intersect

def find_possible_view(img):
	"""
	:param img: numpy.ndarray, should be a color image
	"""
	x_scale = 0.3
	y_scale = 0.3
	# resize to smaller image
	img = cv2.resize(img, (0,0), fx=x_scale, fy=y_scale) 
	# get width and height
	width = len(img)
	height = len(img[0])
	area = width*height
	#Split out each channel
	blue, green, red = cv2.split(img)

	# Run canny edge detection on each channel
	blue_edges = cv2.Canny(blue, 200, 250)
	green_edges = cv2.Canny(green, 200, 250)
	red_edges = cv2.Canny(red, 200, 250)
	# Join edges back into image
	edges = blue_edges | green_edges | red_edges
	# find contour
	_, contours, hierarchy = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_NONE)
	rectangle_list = []
	for index, cnt in enumerate(contours):
		contour_area = cv2.contourArea(cnt)
		# area constraint
		if contour_area < area/300 or contour_area > area/4:
			continue
		x, y, w, h = cv2.boundingRect(cnt)
		# find approxPolyDP
		epsilon = 0.01*cv2.arcLength(cnt,True)
		approx = cv2.approxPolyDP(cnt,epsilon,True)
		if len(approx) == 2:
			continue
		new_rectangle = (x,y,w,h,len(approx))
		should_append = True
		remove_list = []
		for index, rectangle in enumerate(rectangle_list):
			if isIntersect(new_rectangle, rectangle):
				if new_rectangle[4] > rectangle[4]:
					should_append = False
					break
				else:
					remove_list.append(index)
		remove_list.reverse()
		for index in remove_list:
			del rectangle_list[index]
		if should_append:
			rectangle_list.append(new_rectangle)

	result_rectangle = [(int(float(x)/x_scale),int(float(y)/y_scale),int(float(w)/x_scale),int(float(h)/y_scale)) for x,y,w,h,len_approx in rectangle_list]
	return result_rectangle

def calculate_hash(image):
	difference = __difference(image)
	# convert to hex
	decimal_value = 0
	hash_string = ""
	for index, value in enumerate(difference):
		if value:
			decimal_value += value * (2 ** (index % 8))
		if index % 8 == 7:  # every eight binary bit to one hex number
			hash_string += str(hex(decimal_value)[2:-1].rjust(2, "0"))  # 0xf=>0x0f
			decimal_value = 0
	return hash_string

def __difference(image):
	"""
	calculate difference between pixels
	"""
	resize_width = 18
	resize_height = 16
	# 1. resize to (18,16)
	smaller_image = cv2.resize(image, (resize_width, resize_height))
	
	# 2. Grayscale
	grayscale_image = cv2.cvtColor(smaller_image, cv2.COLOR_BGR2GRAY)
	
	# 3. calculate difference between pixels
	difference = []
	for row in range(resize_height):
		for col in range(resize_width - 1):
			difference.append(grayscale_image[row][col] > grayscale_image[row][col + 1])
	return difference

def hamming_distance(first, second):
	"""
	:param first: numpy.ndarray or dHash value(str)
	:param second: numpy.ndarray or dHash value(str)
	:return: hamming distance. 
	"""
	# A. use dHash value to calculate hamming distance
	if isinstance(first, str):
		return DHash.__hamming_distance_with_hash(first, second)

	# B. use numpy.ndarray to calculaet hamming distance
	hamming_distance = 0
	image1_difference = DHash.__difference(first)
	image2_difference = DHash.__difference(second)
	for index, img1_pix in enumerate(image1_difference):
		img2_pix = image2_difference[index]
		if img1_pix != img2_pix:
			hamming_distance += 1
	return hamming_distance

def __hamming_distance_with_hash(dhash1, dhash2):
	"""
	calculte hamming distance according to dHash value
	:param dhash1: str
	:param dhash2: str
	:return: hamming distance (int)
	"""
	difference = (int(dhash1, 16)) ^ (int(dhash2, 16))
	return bin(difference).count("1")

	
