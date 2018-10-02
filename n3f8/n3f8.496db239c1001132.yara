
rule n3f8_496db239c1001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.496db239c1001132"
     cluster="n3f8.496db239c1001132"
     cluster_size="149"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smsspy androidos smforw"
     md5_hashes="['d12a11b9197f64708ef47fe27ad43c4f60d80e13','a4fbcba03eda4150e0104f4c0e7eac1a36502f33','6e4d5bf2236f29d5ace9cae90239b1a31599941e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.496db239c1001132"

   strings:
      $hex_string = { 76614d61696c2e00034a756c00034a756e00094b4545505f5345454e00074b4559574f524400074b53433536303100084b6579776f72647300014c00064c4152 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
