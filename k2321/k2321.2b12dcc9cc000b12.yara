
rule k2321_2b12dcc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b12dcc9cc000b12"
     cluster="k2321.2b12dcc9cc000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['06e88b8f2fdb03ed2c3d92a507d2dfae','14fe481234f51443522b9b7072de670c','76f05f590a58b4f9b2832a33e222e18d']"

   strings:
      $hex_string = { 20f61f84a956c28aa6706425fb80300b634a041d2ad9743bd8eb94f8aa608b02d3d012d8411bac616510661cb70855b029a1ad78253bca67e46ae223ccb17393 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
