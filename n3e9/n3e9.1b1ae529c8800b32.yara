
rule n3e9_1b1ae529c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1ae529c8800b32"
     cluster="n3e9.1b1ae529c8800b32"
     cluster_size="208"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['02c9d77e0c3b949acf8ec69459cfe9f5','034e928e974a776c06e166acf5fe4594','22c8436ace971326300a255989c58de2']"

   strings:
      $hex_string = { 367cbf084d78f1b49149600b48fa8341fe510c742d436361d06632219a4f5a208b5baf90c875e3c959a7e6c07177e7675eda68b7bb64dff094318feee5b5ff09 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
