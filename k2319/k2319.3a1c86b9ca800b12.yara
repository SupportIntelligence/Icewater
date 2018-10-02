
rule k2319_3a1c86b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a1c86b9ca800b12"
     cluster="k2319.3a1c86b9ca800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4d16ffeb6153180039a9911e49fa138e3bf82840','85325f9c7f229c6f68fafd8cba2c6597c850bc3f','d8c57a1db651ce375acb50464cdf84dab2b1446a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a1c86b9ca800b12"

   strings:
      $hex_string = { 475d213d3d756e646566696e6564297b72657475726e204d5b475d3b7d76617220563d283130392e3545313c2834312e3245312c30783845293f30783233313a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
