
rule m26bb_2b40dda92a211932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.2b40dda92a211932"
     cluster="m26bb.2b40dda92a211932"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dangerousobject multi zdengo"
     md5_hashes="['e26851082cfb5b9a3d305de1c1bcf22e4a18f839','12b270266ed940701c0074870d051458a78b2d8e','68a14399351cbc8a964d7e17411b3deda71c3e3b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.2b40dda92a211932"

   strings:
      $hex_string = { 70448e0a4e9f9b7b76fe8c3f1cffb788105c84f0168040adfdfb4ad6f2f8dc2f8d8a0d6ed5434d7713ef3697b2bdf1205b1af651dd554f8fab3360a43cc89af9 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
