<?php
    session_start();
    require 'check_if_added.php';
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <!-- Box icons -->
    <link
      rel="stylesheet"
      href="https://cdn.jsdelivr.net/npm/boxicons@latest/css/boxicons.min.css"
    />
    <!-- Custom StyleSheet -->
    <link rel="stylesheet" href="./css/styles.css" />
    <title>Mocktails</title>
  </head>

  <body>
    <!-- Navigation -->
    <div class="top-nav">
      <div class="container d-flex">
        <marquee width="50%"> Product details-<em> Banana  </em></marquee>
        <ul class="d-flex">
          <li><a href="about.html">About Us</a></li>
          <li><a href="contact.html">FAQ</a></li>
          <li><a href="contact.html">Contact</a></li>
        </ul>
      </div>
    </div>
    <div class="navigation">
      <div class="nav-center container d-flex">
        <a href="index.html" class="logo"><h1> Kwa jerry fast food </h1></a>

        <ul class="nav-list d-flex">
          <li class="nav-item">
            <a href="index.php" class="nav-link">Home</a>
          </li>
          <li class="nav-item">
            <a href="product.html" class="nav-link">Order_Menu</a>
          </li>
          <li class="nav-item">
            <a href="terms.xml" class="nav-link">Terms</a>
          </li>
          <li class="nav-item">
            <a href="about.html" class="nav-link">About</a>
          </li>
          <li class="nav-item">
            <a href="contact.html" class="nav-link">Contact</a>
          </li>
        </ul>

        <div class="icons d-flex">
          <a href="login.html" class="icon">
              <i class="bx bx-user"></i>
          </a>
          </a>
          <a href="logout.php" class ="icon">
             <i class="bx bx-log-out"></i>
          </a>
        </div>

        <div class="hamburger">
          <i class="bx bx-menu-alt-left"></i>
        </div>
      </div>
    </div>

    <!-- Product Details -->
    <section class="section product-detail">
      <div class="details container">
        <div class="left image-container">
          <div class="main">
            <img src="./images/Bannana rush.jpg" id="zoom" alt="" />
          </div>
        </div>
        <div class="right">
          <span>Catergory = Mocktails</span>
          <h1>Bannana Rush</h1>
          <div class="price">R45</div>
          
          <form class="form">
            <input type="text" placeholder="1" />
        
        <?php if(!isset($_SESSION['email'])) { ?>
          <p><a href="login.php" role="button" class="btn btn-primary btn-block">Buy Now</a></p>
        <?php } else { 
          if(check_if_added_to_cart(1)) { ?>
            <a href="#" class="btn btn-block btn-success disabled">Added to cart</a>
          <?php } else { ?>
            <a href="cart_add.php?id=17" class="btn btn-block btn-primary" name="add" value="add">Add to cart</a>
          <?php } 
        } ?>
          </form>
          <h3>Product Detail</h3>
          <p>
          Banana juice with rasberry fruit.
          </p>
        </div>
      </div>
    </section>

    
    <!-- Footer -->
    <footer class="footer">
      <div class="row">
        <div class="col d-flex">
          <h4>INFORMATION</h4>
          <a href="">About us</a>
          <a href="">Contact Us</a>
          <a href="">Term & Conditions</a>
        </div>
        <div class="col d-flex">
          <h4>USEFUL LINK</h4>
          <a href="">Customer Services</a>
        </div>
        <div class="col d-flex">
          <span><i class="bx bxl-facebook-square"></i></span>
          <span><i class="bx bxl-instagram-alt"></i></span>
        </div>
      </div>
    </footer>
    <!-- Custom Script -->
    <script src="./js/index.js"></script>
    <script
      src="https://code.jquery.com/jquery-3.4.0.min.js"
      integrity="sha384-JUMjoW8OzDJw4oFpWIB2Bu/c6768ObEthBMVSiIx4ruBIEdyNSUQAjJNFqT5pnJ6"
      crossorigin="anonymous"
    ></script>
    <script src="./js/zoomsl.min.js"></script>
    <script>
      $(function () {
        console.log("hello");
        $("#zoom").imagezoomsl({
          zoomrange: [4, 4],
        });
      });
    </script>
  </body>
</html>
