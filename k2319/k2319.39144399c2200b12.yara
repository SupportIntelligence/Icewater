
rule k2319_39144399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39144399c2200b12"
     cluster="k2319.39144399c2200b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['8a3a13dec888c377d08d8bbf6cfd1bb79d54f246','17be7981f76734b85947a1436b8c0481fc409412','71bd7fd454652671ff037db1377c973a8f0c2e33']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39144399c2200b12"

   strings:
      $hex_string = { 6f773b666f7228766172204c365420696e204b31503654297b6966284c36542e6c656e6774683d3d3d2830783144463e3d2830783234372c313335293f283938 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
