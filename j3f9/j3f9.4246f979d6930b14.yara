
rule j3f9_4246f979d6930b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.4246f979d6930b14"
     cluster="j3f9.4246f979d6930b14"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious genericrxco"
     md5_hashes="['110376fcb156f2899958a33427b7aa2e','45312728a81f842942aaad5d8808656d','fc0bc837781790fa2d6caf0d18a77b46']"

   strings:
      $hex_string = { a804f31fbd58051bdf8550495302d036745c04bf3715b98bd204af9a14ffd22e2106fb1ae4620cffd2aeb0b8b8688020b5388200bd01e00b7a89da701908105f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
