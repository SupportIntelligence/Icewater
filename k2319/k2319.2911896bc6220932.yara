
rule k2319_2911896bc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2911896bc6220932"
     cluster="k2319.2911896bc6220932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['68a0e32e4d8add0616d8a0d0c034ae70eacb6a9f','d589fe278f4b4907b1209566298e562398bb5a4b','82bed91479faf8487f2b2b0e65ed47e747711740']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2911896bc6220932"

   strings:
      $hex_string = { 4c5d213d3d756e646566696e6564297b72657475726e206f5b4c5d3b7d76617220543d282838352e3445312c32322e293c3d2830783232302c3078314344293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
