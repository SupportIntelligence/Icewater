
rule k3ec_375578e39b030b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.375578e39b030b32"
     cluster="k3ec.375578e39b030b32"
     cluster_size="37"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="heuristic malicious engine"
     md5_hashes="['01e479b973b21f9f4223a76256d44ef2','06df41b79853b0dc42d96769c67e5424','515f71ff719b6678c53bc08f3f8096f0']"

   strings:
      $hex_string = { 01000000537461636b2061726f756e6420746865207661726961626c65202700272077617320636f727275707465642e00000000546865207661726961626c65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
