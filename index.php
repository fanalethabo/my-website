<?php

session_start();

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header("location: login.html");
}

?><!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  
    <!-- Boxicons -->
    <link
      href="https://unpkg.com/boxicons@2.0.7/css/boxicons.min.css"
      rel="stylesheet"
    />
    <!-- Glide js -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/Glide.js/3.4.1/css/glide.core.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/Glide.js/3.4.1/css/glide.theme.css">
    <!-- Custom StyleSheet -->
    <link rel="stylesheet" href="./css/styles.css" />
    <link rel="stylesheet" href="css/Marquee.css"> <!-- Links the external CSS file located in the 'css' folder -->
    <title>Index </title>
  </head>
  <body>
    <!-- Header -->
    <header class="header" id="header">
      <!-- Top Nav -->
      <div class="top-nav">
        <div class="container d-flex">
          <marquee width="90%"> Home Page -<em> kwaJerry fast food </em></marquee>
        </div>
      </div>
      <div class="navigation">
        <div class="nav-center container d-flex">
        <a href="index.html" class="logo"><h1>Kwa Jerry Fast foods </h1></a>

          <ul class="nav-list d-flex">
            <li class="nav-item">
              <a href="index.php" class="nav-link">Home</a>
            </li>
            <li class="nav-item">
              <a href="product.html" class="nav-link">Order_Menu </a>
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
            <a href="logout.php" class="icon">
              <i class="bx bx-search"></i>
            </a>
            <div class="icon" >
              <i class="bx bx-heart"></i>
              <span class="d-flex">0</span>
            </div>
            <a href="cart.html" class="icon">
              <i class="bx bx-cart"></i>
              <span class="d-flex">0</span>
            </a>
          </div>

          <div class="hamburger">
            <i class="bx bx-menu-alt-left"></i>
          </div>
        </div>
      </div>

    <div class="hero">
      <div class="glide" id="glide_1">
        <div class="glide__track" data-glide-el="track">
          <ul class="glide__slides">
            <li class="glide__slide">
              <div class="center">
                <div class="left">
                  
                  <h1 class=""> Alcohol infused Cocktail Specials *R300.00*</h1>
                  <span class=""><p>We have a wide selection of cocktail to offer.</p><br>
                  <p>Buy Two cocktails and get 1 Free,Bottomless Hubbly is included in package </p>
                <p><em><h2>If we dont cocktail you then we will mocktail you!</h2></em></p></span>
                </div>
                <div class="right">
                
                   <!--Attach video -->
                <video width="500" height="400" controls>
                  <source src="./images/Cocktail.mp4" type="Video/mp4">
               Vedieo tag not supported by Your browser.
                </video> 
                  
                </div>
              </div>
              
            </li>
            <li class="glide__slide">
              <div class="center">
                <div class="left">
                  <h1 class=""> Non-Alcohol infused Cocktail Specials *R200.00*</h1>
                  <span class=""><p>We have a wide selection of Non-Alcohol cocktails to offer.</p><br>
                  <p>Buy any Two cocktails and get 1 Free,Bottomless Hubbly is included in package </p>
                <p><em><h2>If we Mocktail you then we will not Cocktail  you!</h2></em></p></span>
                </div>
                <div class="right">
                  
                   <!--Attach video -->
                <video width="500" height="340" controls>
                  <source src="./images/Mocktail.mp4" type="Video/mp4">
                 Vedieo tag not supported by Your browser.
                </div>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </div>
    </header>

    <div class ="title">
    <h1><p>We offer a wide of range of enjoyable meals to choose from, our menu is unique </p></h1><br>
    <h2><p>category of meals are as follows.</p></h2>
    <p>All Alcohol in fused drinks are not for sale for personel under the age of 18 </p>
    Platters are always avilable and readily prepaired this includes all other meals.
    </div>

    <!-- Categories Section -->
    <!--first catergory-->

    <section class="section category">
      <div class="cat-center">
        <div class="cat">
          <img src="./images/Cocktails.jpg" alt="" />
          <div>
            <p>Cocktails</p>
          </div>
        </div>
        <div class="cat">
          <img src="./images/Beers.jpg" alt="" />
          <div>
            <p>Beers</p>
          </div>
         </div>
         <div class="cat">
          <img src="./images/Mocktails.jpg" alt="" />
          <div>
            <p>Mocktails</p>
          </div>
          </div>
      </div>
    </section>

    <!-- Second catergory-->
    <section class="section category">
      <div class="cat-center">
        <div class="cat">
          <img src="./images/Ice cream.jpg" alt="" />
          <div>
            <p>Ice cream</p>
          </div>
        </div>
        <div class="cat">
          <img src="./images/Milk shake.jpg" alt="" />
          <div>
            <p>Milk Shakes</p>
          </div>
         </div>
         <div class="cat">
          <img src="./images/Platters.jpg" alt="" />
          <div>
            <p>Platters</p>
          </div>
          </div>
          </div>
         </section>

    <!--Up Coming events  code -->
        <Section class="events">
         <!--Title of Section-->>
        <div class="title">
        <h1>Up coming Events</h1>
        <div class="marquee"> <!-- Container for the marquee -->
          <div class="marquee-content"> <!-- Inner container for the images -->
              <img src="./images/event 1.jpg" alt="event 1"> <!-- First image -->
              <img src="./images/event 2.jpg" alt="event 2"> <!-- Second image -->
          </div>
      </div> 
        </div>
        </Section>
    
        
    <section class="section new-arrival">
      <div class="title">
        <h1>Inovation</h1>
        <p>As a source of inovation our container store has been renuvated during and after the covid 19 pendamic<p> 
          <p> we are proud to say that our container store has expanded in order to accomodate large amount of clients and 
            booked special events ,we belive thaat improving the structure will build an inclusive enviroment for our clients.</p>
      </div>
    </section>

    <section class="section new-arrival">
      <div class="title">
        <h1>Our Vision</h1>
        <p>our vision is to stand out amoung the rest of our compertitors localy and also catter for our ever growing consumer base
          ,every meal is served with grate pride and we so adhere to the state of the art packaging of meals ordered.the reason we 
          exist is to provide a solution to satisfy our customers hunger and offer a memoryable taste bud expirience.
           and of your common big sa brands</p>
  
      </div>
    </section>

    <section class="section new-arrival">
      <div class="title">
        <h1>Our Mission </h1>
      <p>Our soul mission is to set a calinery foot print in local townships as well as improve our digital foot print, in our township 
        economy we strive to be recorgnised as a retail brand socialy and economicaly ,our brand strategy is to work along side different 
        type of technology standards to improve our e-commerce retailing foot print.fearther more we rely on third party delivery services 
        to connect and brige the B2C Bussiness to Custormer dividing gap,we hope that investing in a e -commerce projects  will create more
         time for consumers and improve consumer expirience</p>
      </div>
    </section>


    <!-- Contact -->
    <section class="section contact">
      <div class="row">
        <div class="col">
          <h2>Kwa Jerry SUPPORT</h2>
          <p> "Customers can reach out any time
          of day "we would like to hear from you"</p>
          <a href="contact.html" class="btn btn-1">Contact</a>
        </div>
        <div class="col">
          <form action="">
            <div>
              <input type="email" placeholder="Email Address">
            <a href="fanalethabo@gmail.com">Send</a>
            </div>
          </form>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
      <div class="row">
        <div class="col d-flex">
          <h4>INFORMATION</h4>
          <a href="about.html">About us</a>
          <a href="contact.html">Contact Us</a>
          <a href="">Term & Conditions</a>
          <a href="">Shipping Guide</a>
        </div>
        <div class="col d-flex">
          <h4>USEFUL LINK</h4>
          <a href="">Online Store</a>
          <a href="">Customer Services</a>
          <a href="">Promotion</a>
          <a href="img src="">Partners</a>
        </div>
        <div class="col d-flex">
          <span><i class='bx bxl-facebook-square'></i></span>
          <span><i class='bx bxl-instagram-alt' ></i></span>
        </div>
      </div>
    </footer>


  <!-- PopUp -->
  <div class="popup hide-popup">
    <div class="popup-content">
      <div class="popup-close">
        <i class='bx bx-x'></i>
      </div>
      <div class="popup-left">
        <div class="popup-img-container">
          <img class="popup-img" src="./images/flasheed.jpg" alt="popup">
        </div>
      </div>
      <div class="popup-right">
        <div class="right-content">
          <h1> <span> Order now! </span> </h1>
         <h2> <p>We now deliver!</p></h2>

          <p><em></em><strong><span>Have you heard </strong></strong></em> "Wka Jerry Fast foods" now delivers around 
            surrounding Kagiso area ,we are proud to anounce that our orders will be managed by a third party "errands"
             delivery service, with a registered trading name Isikuta Couriers <em>"AKA"</em> <strong>365 on the dot</strong>.
          </p>
          <p><strong>customers out of rich should rest assured we got you covered </strong></p>
          <p>how ever so we will utilise the e-hailing passenger giant Bolt 
            to full fill your orders excluded by <strong>"Isikuta Courier".</strong>. </p>
            <p><strong>You heared this!</strong><br><br></p>
              <p><span><h2> Now we deliver!</span></h2><span></p>

              <a href="https://play.google.com/store/apps/details/Bolt_Fast_Affordable_Rides?id=ee.mtakso.client&gl=ZA&pli=1">Download Bolt App</a>
            
        </div>
      </div>
    </div>
  </div>

  </body>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Glide.js/3.4.1/glide.min.js"></script>
  <script src="./js/slider.js"></script>
  <script src="./js/index.js"></script>
</html>
