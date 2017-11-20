
rule m3e9_19b1655ad8bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.19b1655ad8bb0912"
     cluster="m3e9.19b1655ad8bb0912"
     cluster_size="18"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob zusy"
     md5_hashes="['08c3b6d3a64fb2e67d32960e0b34b02b','13705c3ebf80476640c574499e8fb4ce','ea5e0f10d2678927a05f65438abd6a6e']"

   strings:
      $hex_string = { 866ccc56c133c4433d0f1b32e0b50855fdd0fbee54d9e768fa60c8890c96f88575a2775a79e14c212f563751dd021cbfb4eb50b2dc0527040e39cd4b461fd706 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
