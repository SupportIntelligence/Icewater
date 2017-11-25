
rule k3e7_11b5b49cc2230b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.11b5b49cc2230b16"
     cluster="k3e7.11b5b49cc2230b16"
     cluster_size="53"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy trojandropper"
     md5_hashes="['4cacb82ba1e1230ddc4de13cd416ba1c','bca17e00dd1cdcab53f291548cff0eef','bca17e00dd1cdcab53f291548cff0eef']"

   strings:
      $hex_string = { e4196b434720e7808dd21a1b44fd0e9b17c7da425813f7619e047638a295ea626c6f1e6a01e3fe2ddff0c422e8857dd3a5087ee802003ff4db1dfb9c102a3e39 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
