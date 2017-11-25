
rule o3e9_59993ec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.59993ec9c4000932"
     cluster="o3e9.59993ec9c4000932"
     cluster_size="174"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock krypt nabucur"
     md5_hashes="['025ac9236bfad48c7ef6261dea4f38f7','02793d34bca3d8552e0b9f5b4a2ddf9d','77b8a5560780aa3be8467bd1493b796c']"

   strings:
      $hex_string = { 00fcfdfd00fdfcfd00f2fbfa0022d8f70005dcfb000ad5f800089cef001c4fdf002a2ad5001d21cd000e51da0026a4eb00759fc00010a1de004cc8f200f9fbfa }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
