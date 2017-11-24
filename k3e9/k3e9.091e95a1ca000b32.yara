
rule k3e9_091e95a1ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091e95a1ca000b32"
     cluster="k3e9.091e95a1ca000b32"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre jqvu bublik"
     md5_hashes="['22003b7a5a9081b6253da4d243ee4eb7','48f07846afa67574688037670f0ff620','e4aa13cf40bcd3c46b80f087a259ad96']"

   strings:
      $hex_string = { 967a4a14f53ee215bb64e056a94e8a8665ef871a4db23a69cd60a657f495499ae49094f821339155fab3635531747dc367cb43dd848298c44404f1e724c2ccd1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
