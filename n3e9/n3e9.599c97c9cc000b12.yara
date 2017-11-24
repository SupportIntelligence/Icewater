
rule n3e9_599c97c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.599c97c9cc000b12"
     cluster="n3e9.599c97c9cc000b12"
     cluster_size="83"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softonic bundler softonicdownloader"
     md5_hashes="['03bb0e2f63c733246b9c13ffd29665d9','05c33f4310a698218c07623abe80b23a','3b0848f8a643c7d7f56b578bf1a221c6']"

   strings:
      $hex_string = { ca3566d82e150d67f6836e899b49399765cedfec5e1fc5a8ab2b9aa01824fd0a4b5f63e97f11bce548ac8e07b6cd25217b1eaa3498ba50dda933582a1917cf12 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
