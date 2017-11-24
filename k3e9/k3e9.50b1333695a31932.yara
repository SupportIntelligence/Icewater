
rule k3e9_50b1333695a31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b1333695a31932"
     cluster="k3e9.50b1333695a31932"
     cluster_size="35"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['1bc77e43441645547c83ea693fd0e962','2f1c66c9bce40545f1170d6fc597dec5','cf6c2387338f9334769ce7eca7257603']"

   strings:
      $hex_string = { 0003000150000000002800530056000a00e803ffff8000260044006f006e00270074002000720065006d0069006e00640020006d006500200061006700610069 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
