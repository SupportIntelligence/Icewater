
rule m2321_331a464cdb9b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.331a464cdb9b0912"
     cluster="m2321.331a464cdb9b0912"
     cluster_size="60"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup zbot lethic"
     md5_hashes="['04b1d7ff9a83017ffb16b4aa31fa50ad','04de0dc28e28162b345ebd038c7a9011','3bc6ef1ece4d7038a98d61dbd4118f80']"

   strings:
      $hex_string = { dfc34f2a5c8d13760b7175381f85bce5c11b3f21acfed38bb688ead1161d3d89b57833458150a152f42cb12b3bef47700a42effb06205114a8d4c7635fe2546e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
