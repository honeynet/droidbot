# This file is created by Minyi Liu (GitHub ID: MiniMinyi)
# The hash algorithm is copied from:
# https://github.com/hjaurum/DHash/blob/master/dHash.py


def _intersect(rect1, rect2):
    """
    Check whether two rectangles intersect.
    :param rect1, rect2: a rectangle represented with a turple(x,y,w,h,approxPoly_corner_count)
    :return whether the two rectangles intersect
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


def load_image_from_path(img_path):
    """
    Load an image from path
    :param img_path: The path to the image
    :return:
    """
    import cv2
    return cv2.imread(img_path)


def load_image_from_buf(img_bytes):
    """
    Load an image from a byte array
    :param img_bytes: The byte array of an image
    :return:
    """
    import cv2
    import numpy
    img_bytes = numpy.array(img_bytes)
    return cv2.imdecode(img_bytes, cv2.IMREAD_UNCHANGED)


def find_views(img):
    """
    Find rectangular views given a UI screenshot
    :param img: numpy.ndarray, representing an image in opencv
    :return: a list of rectangles, each of which is a tuple (x,y,w,h) representing an identified UI view.
    """
    import cv2
    x_scale = 0.3
    y_scale = 0.3
    # resize to a smaller image
    img = cv2.resize(img, (0, 0), fx=x_scale, fy=y_scale)
    # get width and height
    width = len(img)
    height = len(img[0])
    area = width * height
    # Split out each channel
    blue, green, red = cv2.split(img)

    # Run canny edge detection on each channel
    blue_edges = cv2.Canny(blue, 200, 250)
    green_edges = cv2.Canny(green, 200, 250)
    red_edges = cv2.Canny(red, 200, 250)
    # Join edges back into image
    edges = blue_edges | green_edges | red_edges
    # find contour
    contours, hierarchy = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_NONE)
    rectangle_list = []
    for index, cnt in enumerate(contours):
        contour_area = cv2.contourArea(cnt)
        # area constraint
        if contour_area < area / 300 or contour_area > area / 4:
            continue
        x, y, w, h = cv2.boundingRect(cnt)
        # find approxPolyDP
        epsilon = 0.01 * cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, epsilon, True)
        if len(approx) == 2:
            continue
        new_rectangle = (x, y, w, h, len(approx))
        should_append = True
        remove_list = []
        for index, rectangle in enumerate(rectangle_list):
            if _intersect(new_rectangle, rectangle):
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

    result_rectangles = [
        (int(float(x)/x_scale), int(float(y)/y_scale), int(float(w)/x_scale), int(float(h)/y_scale))
        for x, y, w, h, len_approx in rectangle_list]

    # For debugging, show the image
    # print result_rectangles
    # for x, y, w, h, len_approx in rectangle_list:
    #     cv2.rectangle(img, (x, y), (x+w, y+h), (0, 255, 0), 5)
    # cv2.imshow('image', img)
    # cv2.waitKey(0)
    # cv2.destroyAllWindows()

    return result_rectangles


def calculate_dhash(img):
    """
    Calculate the dhash value of an image.
    :param img: numpy.ndarray, representing an image in opencv
    :return:
    """
    difference = _calculate_pixel_difference(img)
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


def _calculate_pixel_difference(img):
    """
    Calculate difference between pixels
    :param img: numpy.ndarray, representing an image in opencv
    """
    import cv2
    resize_width = 18
    resize_height = 16
    # 1. resize to 18*16
    smaller_image = cv2.resize(img, (resize_width, resize_height))

    # 2. calculate grayscale
    grayscale_image = cv2.cvtColor(smaller_image, cv2.COLOR_BGR2GRAY)

    # 3. calculate difference between pixels
    difference = []
    for row in range(resize_height):
        for col in range(resize_width - 1):
            difference.append(grayscale_image[row][col] > grayscale_image[row][col + 1])
    return difference


def img_hamming_distance(img1, img2):
    """
    Calculate the hamming distance between two images
    :param img1: numpy.ndarray, representing an image in opencv
    :param img2: numpy.ndarray, representing an image in opencv
    :return: int, the hamming distance between two images
    """
    # A. use dHash value to calculate hamming distance
    if isinstance(img1, str) and isinstance(img2, str):
        return dhash_hamming_distance(img1, img2)

    # B. use numpy.ndarray to calculate hamming distance
    _hamming_distance = 0
    image1_difference = _calculate_pixel_difference(img1)
    image2_difference = _calculate_pixel_difference(img2)
    for index, img1_pix in enumerate(image1_difference):
        img2_pix = image2_difference[index]
        if img1_pix != img2_pix:
            _hamming_distance += 1
    return _hamming_distance


def dhash_hamming_distance(dhash1, dhash2):
    """
    Calculate the hamming distance between two dhash values
    :param dhash1: str, the dhash of an image returned by `calculate_dhash`
    :param dhash2: str, the dhash of an image returned by `calculate_dhash`
    :return: int, the hamming distance between two dhash values
    """
    difference = (int(dhash1, 16)) ^ (int(dhash2, 16))
    return bin(difference).count("1")
