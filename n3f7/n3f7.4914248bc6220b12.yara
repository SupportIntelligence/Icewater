
rule n3f7_4914248bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.4914248bc6220b12"
     cluster="n3f7.4914248bc6220b12"
     cluster_size="39"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker html"
     md5_hashes="['01f894ab4b5a734c5341549f51ddef17','1239bf432e72a76ee768f5d4216684df','85c9f87072cd9cfdc853cf7492adfefb']"

   strings:
      $hex_string = { 656d656e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f7363726970743e0a3c2f626f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
