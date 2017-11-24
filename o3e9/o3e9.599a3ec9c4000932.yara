
rule o3e9_599a3ec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.599a3ec9c4000932"
     cluster="o3e9.599a3ec9c4000932"
     cluster_size="121"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['0016c16cf4a1c8178d88202a214e0611','03e56022913bdba48101afdd2d453995','4c7a5f45120ccda4f4bfca78767885d7']"

   strings:
      $hex_string = { 009b360900824914002659200039330d00432b070051544b003e6f6c000c1a0e000a090600231b0a003b350b004a2302004f240200604015007d7149009c3d0d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
